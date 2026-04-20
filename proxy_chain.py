"""
Moteur de chainage de proxies.

Architecture du chainage :
    Client → [Serveur SOCKS local] → Tor (9050) → Proxy SOCKS public → Internet

Le serveur SOCKS local créé par ce module agit comme un point d'entrée unique.
Toute connexion entrante est relayée via Tor, puis via le proxy SOCKS choisi.
"""

import socket
import threading
import select
import time
import struct
import logging
from typing import Optional, Tuple

import socks  # PySocks

from rich.console import Console
from proxy_scraper import Proxy

console = Console()
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Lecture fiable (recv exact N octets)
# ──────────────────────────────────────────────

def _recvall(sock: socket.socket, n: int) -> bytes:
    """Lit exactement n octets depuis le socket (robuste à la fragmentation TCP)."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"Socket closed after {len(data)}/{n} bytes")
        data += chunk
    return data

# Port du serveur SOCKS local qu'on crée
DEFAULT_LOCAL_PORT = 10800
# Adresse de liaison du serveur local (0.0.0.0 = accessible réseau)
LOCAL_BIND = "0.0.0.0"


# ──────────────────────────────────────────────
# Utilitaires SOCKS5 handshake
# ──────────────────────────────────────────────

def _socks5_handshake(client_sock: socket.socket) -> Optional[Tuple[str, int]]:
    """
    Gère le handshake SOCKS5 côté serveur et retourne (host, port) demandé.
    Retourne None en cas d'erreur.
    """
    try:
        # Phase 1 : négociation méthode
        header = _recvall(client_sock, 2)
        if header[0] != 0x05:
            return None
        nmethods = header[1]
        _recvall(client_sock, nmethods)   # lire et ignorer les méthodes
        # On accepte sans authentification (méthode 0x00)
        client_sock.sendall(b"\x05\x00")

        # Phase 2 : requête de connexion (4 octets fixes)
        req = _recvall(client_sock, 4)
        if req[0] != 0x05 or req[1] != 0x01:
            client_sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return None

        atype = req[3]
        if atype == 0x01:  # IPv4
            host = socket.inet_ntoa(_recvall(client_sock, 4))
        elif atype == 0x03:  # Domain name
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
    """Envoie une réponse SOCKS5 de succès au client."""
    try:
        addr_bytes = socket.inet_aton(bound_host)
        port_bytes = struct.pack("!H", bound_port)
        client_sock.sendall(b"\x05\x00\x00\x01" + addr_bytes + port_bytes)
    except Exception:
        pass


def _socks5_reply_error(client_sock: socket.socket, code: int = 0x04):
    """Envoie une réponse SOCKS5 d'erreur au client."""
    try:
        client_sock.sendall(bytes([0x05, code, 0x00, 0x01]) + b"\x00" * 6)
    except Exception:
        pass


# ──────────────────────────────────────────────
# Relay de données bidirectionnel
# ──────────────────────────────────────────────

def _relay(sock_a: socket.socket, sock_b: socket.socket, timeout: int = 60):
    """Relaie les données entre deux sockets dans les deux sens."""
    sock_a.settimeout(timeout)
    sock_b.settimeout(timeout)
    try:
        while True:
            try:
                readable, _, exceptional = select.select([sock_a, sock_b], [], [sock_a, sock_b], timeout)
            except Exception:
                break

            if exceptional:
                break

            if not readable:
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


# ──────────────────────────────────────────────
# Gestionnaire de client (thread)
# ──────────────────────────────────────────────

class _ClientHandler(threading.Thread):
    """Thread gérant une connexion client vers le proxy chaîné."""

    def __init__(
        self,
        client_sock: socket.socket,
        tor_port: int,
        exit_proxy: Proxy,
    ):
        super().__init__(daemon=True)
        self.client_sock = client_sock
        self.tor_port = tor_port
        self.exit_proxy = exit_proxy

    def run(self):
        remote_sock = None
        try:
            # 1. Handshake SOCKS5 avec le client local
            result = _socks5_handshake(self.client_sock)
            if not result:
                return
            target_host, target_port = result

            # 2. Connexion via Tor → proxy exit (double hop)
            remote_sock = self._connect_chain(target_host, target_port)
            if remote_sock is None:
                _socks5_reply_error(self.client_sock, 0x04)
                return

            # 3. Répondre succès au client local
            _socks5_reply_success(self.client_sock)

            # 4. Relayer les données
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
        Établit la chaîne : Tor SOCKS5 (port 9050) → proxy exit → target.

        On crée un socket PySocks qui se connecte D'ABORD à Tor,
        puis Tor se connecte au proxy exit, puis le proxy exit
        se connecte à la destination.

        En pratique on fait :
          PySocks → Tor → proxy exit (on parle SOCKS4/5 avec lui)
          puis le proxy exit → destination
        """
        try:
            # Étape A : connexion à Tor, puis via Tor vers le proxy exit
            tor_sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            tor_sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port, rdns=True)
            tor_sock.settimeout(20)
            # On se connecte AU proxy exit via Tor
            tor_sock.connect((self.exit_proxy.host, self.exit_proxy.port))

            # Étape B : faire le handshake SOCKS avec le proxy exit
            proto = self.exit_proxy.proto.lower()
            if proto == "socks5":
                self._socks5_connect(tor_sock, target_host, target_port)
            elif proto == "socks4":
                self._socks4_connect(tor_sock, target_host, target_port)
            else:
                self._socks5_connect(tor_sock, target_host, target_port)

            return tor_sock

        except Exception as e:
            logger.debug(f"Chain connect failed: {e}")
            return None

    def _socks5_connect(self, sock: socket.socket, host: str, port: int):
        """Handshake SOCKS5 CLIENT vers le proxy exit."""
        # Négociation méthode (sans auth)
        sock.sendall(b"\x05\x01\x00")
        resp = _recvall(sock, 2)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise ConnectionError(f"SOCKS5 auth failed: {resp!r}")

        # Requête CONNECT avec le nom de domaine (ATYP 0x03)
        host_bytes = host.encode()
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", port)
        )
        sock.sendall(request)

        # Lire la réponse : 4 octets fixes (VER, REP, RSV, ATYP)
        header = _recvall(sock, 4)
        if header[1] != 0x00:
            raise ConnectionError(f"SOCKS5 CONNECT failed: code=0x{header[1]:02x}")

        # Consommer l'adresse de liaison (BND.ADDR + BND.PORT) selon ATYP
        atyp = header[3]
        if atyp == 0x01:        # IPv4 : 4 octets
            _recvall(sock, 4 + 2)
        elif atyp == 0x03:      # Domain name : 1 octet longueur + N octets + 2 port
            domain_len = _recvall(sock, 1)[0]
            _recvall(sock, domain_len + 2)
        elif atyp == 0x04:      # IPv6 : 16 octets
            _recvall(sock, 16 + 2)
        else:
            raise ConnectionError(f"SOCKS5 CONNECT: ATYP inconnu 0x{atyp:02x}")

    def _socks4_connect(self, sock: socket.socket, host: str, port: int):
        """Handshake SOCKS4a CLIENT vers le proxy exit."""
        host_bytes = host.encode() + b"\x00"
        request = (
            b"\x04\x01"
            + struct.pack("!H", port)
            + b"\x00\x00\x00\x01"  # IP 0.0.0.1 = SOCKS4a
            + b"\x00"              # user ID vide
            + host_bytes
        )
        sock.sendall(request)
        resp = _recvall(sock, 8)
        if resp[1] != 0x5A:
            raise ConnectionError(f"SOCKS4 CONNECT failed: code=0x{resp[1]:02x}")


# ──────────────────────────────────────────────
# Serveur SOCKS5 local
# ──────────────────────────────────────────────

class ProxyChainServer:
    """
    Serveur SOCKS5 local qui chaîne les connexions :
    Client → Serveur (local) → Tor → Proxy exit SOCKS → Internet
    """

    def __init__(
        self,
        exit_proxy: Proxy,
        tor_port: int = 9050,
        local_port: int = DEFAULT_LOCAL_PORT,
        local_host: str = LOCAL_BIND,
    ):
        self.exit_proxy = exit_proxy
        self.tor_port = tor_port
        self.local_port = local_port
        self.local_host = local_host
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Démarre le serveur SOCKS5 local dans un thread séparé."""
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.local_host, self.local_port))
            self._server_sock.listen(50)
            self._running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
            console.print(
                f"[green]✓ Serveur SOCKS5 local démarré sur "
                f"[bold]socks5://{self.local_host}:{self.local_port}[/bold][/green]"
            )
            return True
        except Exception as e:
            console.print(f"[red]❌ Impossible de démarrer le serveur local: {e}[/red]")
            return False

    def _accept_loop(self):
        """Boucle principale d'acceptation des connexions."""
        self._server_sock.settimeout(1.0)
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
                handler = _ClientHandler(
                    client_sock=client_sock,
                    tor_port=self.tor_port,
                    exit_proxy=self.exit_proxy,
                )
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.debug(f"Accept error: {e}")
                break

    def swap_exit_proxy(self, new_proxy: Proxy):
        """Remplace le proxy de sortie à chaud (sans redémarrer)."""
        self.exit_proxy = new_proxy
        console.print(
            f"[cyan]🔄 Proxy de sortie changé → [bold]{new_proxy.address}[/bold] "
            f"({new_proxy.country or '??'})[/cyan]"
        )

    def stop(self):
        """Arrête le serveur proprement."""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


# ──────────────────────────────────────────────
# Vérification de l'IP finale via la chaîne
# ──────────────────────────────────────────────

def get_chained_ip(local_port: int = DEFAULT_LOCAL_PORT) -> Optional[dict]:
    """
    Récupère l'IP publique en passant par le serveur SOCKS local (= chaîne complète).
    Retourne un dict avec ip, country, city, org.
    """
    import requests as req

    proxies = {
        "http": f"socks5h://127.0.0.1:{local_port}",
        "https": f"socks5h://127.0.0.1:{local_port}",
    }
    endpoints = [
        ("https://ipinfo.io/json", "json"),
        ("http://ip-api.com/json", "json"),
        ("https://api.ipify.org", "text"),
    ]
    for url, fmt in endpoints:
        try:
            r = req.get(url, proxies=proxies, timeout=25)
            if fmt == "json":
                data = r.json()
                return {
                    "ip": data.get("ip") or data.get("query", "?"),
                    "country": data.get("country") or data.get("countryCode", "?"),
                    "city": data.get("city", "?"),
                    "org": data.get("org") or data.get("isp", "?"),
                }
            else:
                return {"ip": r.text.strip(), "country": "?", "city": "?", "org": "?"}
        except Exception:
            continue
    return None
