"""
Proxy chaining engine.

Chain architecture:
    Client → [Local SOCKS server] → Tor → Public SOCKS proxy → Internet

The local SOCKS5 server created by this module acts as the single entry point.
Every incoming connection is relayed through Tor, then through the chosen exit proxy.
"""

import socket
import threading
import select
import time
import struct
import logging
from typing import Callable, List, Optional, Set, Tuple

import socks  # PySocks

from rich.console import Console
from proxy_scraper import Proxy

console = Console()
logger = logging.getLogger(__name__)

DEFAULT_LOCAL_PORT = 10800
LOCAL_BIND = "0.0.0.0"   # listen on all interfaces so LAN devices can use the proxy


# ── Reliable recv ─────────────────────────────────────────────────────────────

def _recvall(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket (handles TCP fragmentation)."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"Socket closed after {len(data)}/{n} bytes")
        data += chunk
    return data


# ── SOCKS5 server-side handshake ──────────────────────────────────────────────

def _socks5_handshake(client_sock: socket.socket) -> Optional[Tuple[str, int]]:
    """
    Handle the server-side SOCKS5 handshake.
    Returns (host, port) requested by the client, or None on error.
    """
    try:
        header = _recvall(client_sock, 2)
        if header[0] != 0x05:
            return None
        nmethods = header[1]
        _recvall(client_sock, nmethods)       # consume method list
        client_sock.sendall(b"\x05\x00")      # accept: no authentication

        req = _recvall(client_sock, 4)
        if req[0] != 0x05 or req[1] != 0x01:
            client_sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return None

        atype = req[3]
        if atype == 0x01:    # IPv4
            host = socket.inet_ntoa(_recvall(client_sock, 4))
        elif atype == 0x03:  # domain name
            length = _recvall(client_sock, 1)[0]
            host = _recvall(client_sock, length).decode()
        elif atype == 0x04:  # IPv6
            host = socket.inet_ntop(socket.AF_INET6, _recvall(client_sock, 16))
        else:
            client_sock.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return None

        port = struct.unpack("!H", _recvall(client_sock, 2))[0]
        return (host, port)
    except Exception:
        return None


def _socks5_reply_success(client_sock: socket.socket, bound_host: str = "0.0.0.0", bound_port: int = 0):
    try:
        addr_bytes = socket.inet_aton(bound_host)
        port_bytes = struct.pack("!H", bound_port)
        client_sock.sendall(b"\x05\x00\x00\x01" + addr_bytes + port_bytes)
    except Exception:
        pass


def _socks5_reply_error(client_sock: socket.socket, code: int = 0x04):
    try:
        client_sock.sendall(bytes([0x05, code, 0x00, 0x01]) + b"\x00" * 6)
    except Exception:
        pass


# ── Bidirectional relay ───────────────────────────────────────────────────────

def _relay(sock_a: socket.socket, sock_b: socket.socket, timeout: int = 60):
    """Relay data between two sockets in both directions."""
    sock_a.settimeout(timeout)
    sock_b.settimeout(timeout)
    try:
        while True:
            try:
                readable, _, exceptional = select.select(
                    [sock_a, sock_b], [], [sock_a, sock_b], timeout
                )
            except Exception:
                break
            if exceptional or not readable:
                break
            for s in readable:
                other = sock_b if s is sock_a else sock_a
                try:
                    data = s.recv(4096)
                    if not data:
                        return
                    other.sendall(data)
                except Exception:
                    return
    except Exception:
        pass


# ── Per-connection handler (thread) ──────────────────────────────────────────

class _ClientHandler(threading.Thread):
    """Thread that handles a single client connection through the proxy chain."""

    def __init__(
        self,
        client_sock: socket.socket,
        tor_port: int,
        exit_proxy: Proxy,
        on_chain_failure: Optional[Callable] = None,
        trigger_hosts: Optional[Set[str]] = None,
        on_rate_limit: Optional[Callable] = None,
    ):
        super().__init__(daemon=True)
        self.client_sock = client_sock
        self.tor_port = tor_port
        self.exit_proxy = exit_proxy
        self.on_chain_failure = on_chain_failure
        self.trigger_hosts = trigger_hosts
        self.on_rate_limit = on_rate_limit

    def run(self):
        remote_sock = None
        try:
            result = _socks5_handshake(self.client_sock)
            if not result:
                return
            target_host, target_port = result

            # Redirect-based rate-limit detection: the SOCKS5 CONNECT hostname
            # is always in plaintext, even for HTTPS. If the browser was redirected
            # to a known rate-limit page (e.g. accounts.censys.io), we see it here.
            if self.trigger_hosts and target_host in self.trigger_hosts and self.on_rate_limit:
                threading.Thread(target=self.on_rate_limit, daemon=True).start()

            remote_sock = self._connect_chain(target_host, target_port)
            if remote_sock is None:
                _socks5_reply_error(self.client_sock, 0x04)
                if self.on_chain_failure:
                    self.on_chain_failure()
                return

            _socks5_reply_success(self.client_sock)
            _relay(self.client_sock, remote_sock)

        except Exception as e:
            logger.debug(f"ClientHandler error: {e}")
        finally:
            for s in (self.client_sock, remote_sock):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _connect_chain(self, target_host: str, target_port: int) -> Optional[socket.socket]:
        """
        Build the chain: local → Tor (SOCKS5) → exit proxy (SOCKS4/5) → target.

        Step A: open a PySocks socket that tunnels through Tor to reach the exit proxy.
        Step B: speak SOCKS4/5 with the exit proxy to reach the final destination.
        """
        try:
            tor_sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            tor_sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port, rdns=True)
            tor_sock.settimeout(20)
            tor_sock.connect((self.exit_proxy.host, self.exit_proxy.port))

            proto = self.exit_proxy.proto.lower()
            if proto == "socks4":
                self._socks4_connect(tor_sock, target_host, target_port)
            else:
                self._socks5_connect(tor_sock, target_host, target_port)

            return tor_sock

        except Exception as e:
            logger.debug(f"Chain connect failed: {e}")
            return None

    def _socks5_connect(self, sock: socket.socket, host: str, port: int):
        """Client-side SOCKS5 handshake toward the exit proxy."""
        sock.sendall(b"\x05\x01\x00")
        resp = _recvall(sock, 2)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise ConnectionError(f"SOCKS5 auth rejected: {resp!r}")

        # Always send as domain name (ATYP 0x03) — no local DNS resolution
        host_bytes = host.encode()
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", port)
        )

        header = _recvall(sock, 4)   # VER, REP, RSV, ATYP
        if header[1] != 0x00:
            raise ConnectionError(f"SOCKS5 CONNECT failed: code=0x{header[1]:02x}")

        # Consume BND.ADDR + BND.PORT (variable length depending on ATYP)
        atyp = header[3]
        if atyp == 0x01:
            _recvall(sock, 4 + 2)
        elif atyp == 0x03:
            domain_len = _recvall(sock, 1)[0]
            _recvall(sock, domain_len + 2)
        elif atyp == 0x04:
            _recvall(sock, 16 + 2)
        else:
            raise ConnectionError(f"SOCKS5 CONNECT: unknown ATYP 0x{atyp:02x}")

    def _socks4_connect(self, sock: socket.socket, host: str, port: int):
        """Client-side SOCKS4a handshake toward the exit proxy."""
        host_bytes = host.encode() + b"\x00"
        sock.sendall(
            b"\x04\x01"
            + struct.pack("!H", port)
            + b"\x00\x00\x00\x01"   # IP 0.0.0.1 signals SOCKS4a
            + b"\x00"               # empty user ID
            + host_bytes
        )
        resp = _recvall(sock, 8)
        if resp[1] != 0x5A:
            raise ConnectionError(f"SOCKS4 CONNECT failed: code=0x{resp[1]:02x}")


# ── Local SOCKS5 server ───────────────────────────────────────────────────────

class ProxyChainServer:
    """
    Local SOCKS5 server that chains connections:
        Client → Server (local) → Tor → Exit SOCKS proxy → Internet

    Supports automatic proxy rotation via a watchdog thread and HTTP 429 detection.
    """

    def __init__(
        self,
        exit_proxy: Proxy,
        tor_port: int = 9050,
        local_port: int = DEFAULT_LOCAL_PORT,
        local_host: str = LOCAL_BIND,
        proxy_pool: Optional[List[Proxy]] = None,
        watchdog_interval: int = 30,
        fail_threshold: int = 3,
        trigger_hosts: Optional[Set[str]] = None,
    ):
        self.exit_proxy = exit_proxy
        self.tor_port = tor_port
        self.local_port = local_port
        self.local_host = local_host
        self._trigger_hosts = trigger_hosts

        # Proxy pool for auto-rotation
        self._proxy_pool: List[Proxy] = proxy_pool if proxy_pool else [exit_proxy]
        self._proxy_index: int = 0
        self._failure_count: int = 0
        self._watchdog_interval = watchdog_interval
        self._fail_threshold = fail_threshold

        self._lock = threading.Lock()
        self._rotation_in_progress = False

        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._watchdog_thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Start the local SOCKS5 server and watchdog in background threads."""
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.local_host, self.local_port))
            self._server_sock.listen(50)
            self._running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
            self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
            self._watchdog_thread.start()
            console.print(
                f"[green]Local SOCKS5 server ready: "
                f"[bold]socks5://{self.local_host}:{self.local_port}[/bold][/green]"
            )
            return True
        except Exception as e:
            console.print(f"[red]Failed to start local server: {e}[/red]")
            return False

    def _accept_loop(self):
        self._server_sock.settimeout(1.0)
        while self._running:
            try:
                client_sock, _ = self._server_sock.accept()
                _ClientHandler(
                    client_sock=client_sock,
                    tor_port=self.tor_port,
                    exit_proxy=self.exit_proxy,
                    on_chain_failure=self._on_chain_failure,
                    trigger_hosts=self._trigger_hosts,
                    on_rate_limit=self._on_rate_limit,
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.debug(f"Accept error: {e}")
                break

    # ── Watchdog ──────────────────────────────────────────────────────────────

    def _probe_proxy(self, proxy: Proxy) -> bool:
        """TCP probe through Tor to verify the exit proxy is reachable."""
        try:
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port, rdns=True)
            s.settimeout(10)
            s.connect((proxy.host, proxy.port))
            s.close()
            return True
        except Exception:
            return False

    def _watchdog_loop(self):
        elapsed = 0
        while self._running:
            time.sleep(1)
            elapsed += 1
            if elapsed < self._watchdog_interval:
                continue
            elapsed = 0

            proxy = self.exit_proxy
            ok = self._probe_proxy(proxy)
            if ok:
                with self._lock:
                    self._failure_count = 0
            else:
                with self._lock:
                    self._failure_count += 1
                    count = self._failure_count
                logger.debug(f"Watchdog: probe failed ({count}/{self._fail_threshold})")
                if count >= self._fail_threshold:
                    self._auto_rotate("watchdog")

    # ── Auto-rotation ─────────────────────────────────────────────────────────

    def _auto_rotate(self, reason: str):
        """Rotate to the next proxy in the pool (thread-safe, debounced)."""
        with self._lock:
            if self._rotation_in_progress:
                return
            if len(self._proxy_pool) <= 1:
                logger.debug("Auto-rotate: pool has only one proxy, skipping")
                return
            self._rotation_in_progress = True
            self._proxy_index = (self._proxy_index + 1) % len(self._proxy_pool)
            new_proxy = self._proxy_pool[self._proxy_index]
            self.exit_proxy = new_proxy
            self._failure_count = 0

        console.print(
            f"\n[yellow bold]Auto-rotation ({reason}) → "
            f"[cyan]{new_proxy.address}[/cyan] "
            f"({new_proxy.country or '??'})[/yellow bold]"
        )

        with self._lock:
            self._rotation_in_progress = False

    def _on_chain_failure(self):
        """Called by _ClientHandler when a connection through the chain fails."""
        with self._lock:
            self._failure_count += 1
            count = self._failure_count
        if count >= self._fail_threshold:
            self._auto_rotate("chain-failure")

    def _on_rate_limit(self):
        """Called when HTTP 429 / quota exhaustion is detected on a watched host."""
        console.print(
            "\n[red bold]Rate-limit detected (HTTP 429 / quota). Rotating exit proxy...[/red bold]"
        )
        self._auto_rotate("rate-limit")
        threading.Thread(target=self._announce_new_ip, daemon=True).start()

    def _announce_new_ip(self):
        """Fetch and display the new public IP after a rate-limit rotation."""
        ip_info = get_chained_ip(self.local_port)
        if ip_info:
            console.print(
                f"[green]New exit IP: [bold]{ip_info['ip']}[/bold] | "
                f"{ip_info['country']} | {ip_info['city']} | {ip_info['org']}[/green]"
            )
        else:
            console.print("[yellow]Could not verify new IP after rotation.[/yellow]")

    # ── Public API ────────────────────────────────────────────────────────────

    def swap_exit_proxy(self, new_proxy: Proxy):
        """Hot-swap the exit proxy without restarting the server."""
        with self._lock:
            self.exit_proxy = new_proxy
            self._failure_count = 0
        console.print(
            f"[cyan]Exit proxy swapped → [bold]{new_proxy.address}[/bold] "
            f"({new_proxy.country or '??'})[/cyan]"
        )

    def rotate(self) -> Proxy:
        """Manually rotate to the next proxy in the pool. Returns the new proxy."""
        self._auto_rotate("manual")
        return self.exit_proxy

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        if self._watchdog_thread:
            self._watchdog_thread.join(timeout=3)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


# ── Final IP check ────────────────────────────────────────────────────────────

def get_chained_ip(local_port: int = DEFAULT_LOCAL_PORT) -> Optional[dict]:
    """
    Fetch the public IP through the local SOCKS server (full chain).
    Returns a dict with ip, country, city, org.
    """
    import requests as req

    proxies = {
        "http":  f"socks5h://127.0.0.1:{local_port}",
        "https": f"socks5h://127.0.0.1:{local_port}",
    }
    endpoints = [
        ("https://ipinfo.io/json",  "json"),
        ("http://ip-api.com/json",  "json"),
        ("https://api.ipify.org",   "text"),
    ]
    for url, fmt in endpoints:
        try:
            r = req.get(url, proxies=proxies, timeout=25)
            if fmt == "json":
                data = r.json()
                return {
                    "ip":      data.get("ip") or data.get("query", "?"),
                    "country": data.get("country") or data.get("countryCode", "?"),
                    "city":    data.get("city", "?"),
                    "org":     data.get("org") or data.get("isp", "?"),
                }
            else:
                return {"ip": r.text.strip(), "country": "?", "city": "?", "org": "?"}
        except Exception:
            continue
    return None
