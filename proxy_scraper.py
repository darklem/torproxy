"""
Public SOCKS proxy scraper from multiple sources.
Fetches, deduplicates and filters proxies by country.

Sources are defined in proxy_sources.py — edit that file to add new ones.
"""

import time
import socket
import ssl
import hashlib
import json as _json
import struct
import threading
import re
import logging
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional, Dict

import requests
import socks

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from proxy_sources import SOURCES

console = Console()
logger = logging.getLogger(__name__)

PROXY_CHECK_TIMEOUT = 8
_CHAIN_VERIFY_TIMEOUT = 20   # seconds — longer because Tor + proxy + HTTPS
MAX_CHECK_WORKERS = 30

_IPCONFIG_HOST = "ipconfig.io"
_IPCONFIG_PORT = 443

# Module-level baseline TLS cert fingerprint for ipconfig.io (SHA-256 of DER cert).
# "" = direct fetch failed (skip comparison); None = not yet attempted.
_ipconfig_baseline: Optional[str] = None
_ipconfig_baseline_lock = threading.Lock()


@dataclass
class Proxy:
    """Represents a SOCKS proxy."""
    host: str
    port: int
    proto: str = "socks5"       # "socks4" or "socks5"
    country: str = ""           # ISO 2-letter country code (e.g. "FR", "US")
    country_name: str = ""      # Full country name
    latency_ms: float = -1.0    # -1 = not tested
    alive: bool = False
    username: str = ""
    password: str = ""
    mitm_clean: bool = True     # False if TLS cert mismatch detected during chain verify

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        creds = f"{self.username}:{self.password}@" if self.username else ""
        return f"{self.proto}://{creds}{self.host}:{self.port}"

    def __hash__(self):
        return hash((self.host, self.port))

    def __eq__(self, other):
        return isinstance(other, Proxy) and self.host == other.host and self.port == other.port


# ── Generic text fetcher ──────────────────────────────────────────────────────

def _fetch_text_url(url: str, proto: str) -> List[Proxy]:
    """Fetch a plain-text proxy list (one IP:PORT per line)."""
    proxies = []
    try:
        r = requests.get(url, timeout=15)
        for line in r.text.strip().splitlines():
            line = line.strip().split()[0]   # strip inline comments
            if ":" in line:
                host, port_s = line.rsplit(":", 1)
                try:
                    proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto=proto))
                except ValueError:
                    pass
    except Exception as e:
        logger.debug(f"fetch_text_url({url}): {e}")
    return proxies


# ── Special JSON sources ──────────────────────────────────────────────────────

def _fetch_proxylist_download() -> List[Proxy]:
    """proxy-list.download — SOCKS5 with country (JSON API)."""
    proxies = []
    try:
        r = requests.get(
            "https://www.proxy-list.download/api/v2/get?l=en&t=socks5",
            timeout=15,
        )
        data = r.json()
        for item in data.get("LISTA", []):
            host = item.get("IP", "")
            port_s = item.get("PORT", "")
            country = item.get("COUNTRY", "")
            if host and port_s:
                try:
                    proxies.append(Proxy(
                        host=host,
                        port=int(port_s),
                        proto="socks5",
                        country=country.upper()[:2] if country else "",
                    ))
                except ValueError:
                    pass
    except Exception as e:
        logger.debug(f"fetch_proxylist_download: {e}")
    return proxies


# ── Country resolution via ip-api.com ─────────────────────────────────────────

def resolve_countries_batch(proxies: List[Proxy], via_tor_port: Optional[int] = None) -> List[Proxy]:
    """
    Enrich proxies that have no country by querying ip-api.com in batches of 100.
    Requests are routed through Tor if via_tor_port is set.
    """
    to_resolve = [p for p in proxies if not p.country]
    if not to_resolve:
        return proxies

    req_kwargs = {}
    if via_tor_port:
        req_kwargs["proxies"] = {
            "http":  f"socks5h://127.0.0.1:{via_tor_port}",
            "https": f"socks5h://127.0.0.1:{via_tor_port}",
        }

    ip_map: Dict[str, tuple] = {}
    batch_size = 100
    batches = [to_resolve[i:i + batch_size] for i in range(0, len(to_resolve), batch_size)]
    total_batches = len(batches)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[resolved]} resolved[/dim]"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                "[cyan]Geolocating via ip-api.com...[/cyan]",
                total=total_batches,
                resolved=0,
            )

            for batch_idx, batch in enumerate(batches):
                payload = [{"query": p.host} for p in batch]
                try:
                    r = requests.post(
                        "http://ip-api.com/batch?fields=query,countryCode,country",
                        json=payload,
                        timeout=20,
                        **req_kwargs,
                    )
                    for entry in r.json():
                        query = entry.get("query", "")
                        cc = entry.get("countryCode", "")
                        cn = entry.get("country", "")
                        if query and cc:
                            ip_map[query] = (cc.upper(), cn)
                except Exception:
                    pass

                progress.update(
                    task,
                    advance=1,
                    resolved=len(ip_map),
                    description=(
                        f"[cyan]Geolocation "
                        f"[bold]{batch_idx + 1}/{total_batches}[/bold] batches...[/cyan]"
                    ),
                )

                if batch_idx < total_batches - 1:
                    time.sleep(0.5)  # ip-api rate limit: 45 req/min

    except Exception:
        pass

    for p in proxies:
        if p.host in ip_map:
            p.country, p.country_name = ip_map[p.host]

    return proxies


# ── ipconfig.io baseline + full-chain verification ────────────────────────────
#
# Design goal: ONE TCP connection per proxy does BOTH geolocation AND MITM
# detection.  No second request, no second host, no second TLS handshake.
#
# Chain under test:
#   us → Tor (SOCKS5 at 127.0.0.1:tor_port)
#       → exit proxy (SOCKS4/5 at proxy.host:proxy.port)
#           → ipconfig.io:443 (HTTPS)
#
# What we learn from a single successful connection:
#   • Proxy is alive and routes HTTPS traffic.
#   • Exit IP geolocation (country_code, country) from the JSON body.
#   • Whether a TLS MITM is in place: compare the certificate fingerprint
#     seen through the chain against one fetched directly (no proxy).
# ─────────────────────────────────────────────────────────────────────────────

def _get_ipconfig_baseline() -> Optional[str]:
    """
    Fetch the SHA-256 fingerprint of ipconfig.io's TLS certificate via a
    direct connection (no Tor, no proxy) and cache it for the process lifetime.

    This is the reference value.  Every proxy we test must present the same
    certificate to ipconfig.io; a different fingerprint means something on the
    path is intercepting TLS and substituting its own certificate (MITM).

    Returns the hex fingerprint string, or None if the direct fetch failed
    (network unavailable, firewall, …).  Callers treat None as "skip comparison
    and give proxy the benefit of the doubt."
    """
    global _ipconfig_baseline
    with _ipconfig_baseline_lock:
        # "" is our sentinel meaning "fetch was attempted and failed".
        if _ipconfig_baseline is not None:
            return _ipconfig_baseline or None
        try:
            ctx = ssl.create_default_context()   # uses system CA bundle
            raw = socket.create_connection((_IPCONFIG_HOST, _IPCONFIG_PORT), timeout=10)
            tls = ctx.wrap_socket(raw, server_hostname=_IPCONFIG_HOST)
            cert_der = tls.getpeercert(binary_form=True)   # raw DER bytes
            tls.close()
            _ipconfig_baseline = hashlib.sha256(cert_der).hexdigest()
            logger.debug(f"ipconfig.io TLS baseline: {_ipconfig_baseline[:16]}…")
            return _ipconfig_baseline
        except Exception as exc:
            logger.debug(f"ipconfig.io baseline fetch failed: {exc}")
            _ipconfig_baseline = ""   # prevent future retries
            return None


def _recv_exact(sock, n: int) -> bytes:
    """
    Read exactly n bytes from a socket, handling TCP fragmentation.
    Raises ConnectionError if the socket closes before n bytes are received.
    """
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed after {len(data)}/{n} bytes")
        data += chunk
    return data


def _socks5_connect_to(sock, host: str, port: int) -> bool:
    """
    Speak the SOCKS5 client protocol over an already-open socket to ask the
    SOCKS5 server (= our exit proxy) to tunnel us to host:port.

    SOCKS5 wire format (RFC 1928):
      Greeting  → VER(1) NMETHODS(1) METHODS(N)
      Response  ← VER(1) METHOD(1)          [0x00 = no auth]
      Request   → VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT(2)
      Response  ← VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR BND.PORT(2)

    We always request ATYP=0x03 (domain name) so the exit proxy resolves
    the hostname, not us.  Returns True on success (REP=0x00).
    """
    try:
        # Offer "no authentication" as the only method
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2)[1] != 0x00:   # server must accept no-auth
            return False

        host_b = host.encode("idna")
        sock.sendall(
            b"\x05\x01\x00\x03"                       # VER CMD RSV ATYP=domain
            + bytes([len(host_b)]) + host_b            # DST.ADDR
            + struct.pack("!H", port)                  # DST.PORT
        )

        # Read the fixed 4-byte response header
        hdr = _recv_exact(sock, 4)
        if hdr[1] != 0x00:   # REP=0x00 means success
            return False

        # Consume the variable-length BND.ADDR + BND.PORT so the socket
        # is positioned at the start of the proxied data stream.
        atyp = hdr[3]
        if atyp == 0x01:               # IPv4: 4 bytes + 2 port
            _recv_exact(sock, 6)
        elif atyp == 0x03:             # domain: 1-byte length + N bytes + 2 port
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        elif atyp == 0x04:             # IPv6: 16 bytes + 2 port
            _recv_exact(sock, 18)
        return True
    except Exception:
        return False


def _socks4a_connect_to(sock, host: str, port: int) -> bool:
    """
    Speak the SOCKS4a protocol over an already-open socket.

    SOCKS4a extends SOCKS4 by allowing hostname resolution at the server side:
    setting the IP to 0.0.0.x (non-routable) signals that a hostname follows
    after the user-id field.

    Wire format (single request/response):
      Request  → VER(1) CMD(1) PORT(2) IP(4) USERID NUL HOSTNAME NUL
      Response ← VER(1) REP(1) PORT(2) IP(4)       [REP=0x5A = granted]
    """
    try:
        host_b = host.encode("ascii") + b"\x00"
        sock.sendall(
            struct.pack("!BBHBBBB", 4, 1, port, 0, 0, 0, 1)  # IP=0.0.0.1 → SOCKS4a
            + b"\x00"                                          # empty user-id
            + host_b                                           # hostname + NUL
        )
        resp = _recv_exact(sock, 8)
        return resp[1] == 0x5A   # 0x5A = request granted
    except Exception:
        return False


def _verify_via_chain(proxy: Proxy, tor_port: int) -> Proxy:
    """
    Verify a proxy through the full chain in a single TCP connection.

    Path:  us → Tor → exit proxy → ipconfig.io:443

    One connection does everything:
      1. Confirm the proxy is alive and reachable via Tor.
      2. Confirm the proxy routes HTTPS traffic end-to-end.
      3. Detect MITM: compare the TLS certificate fingerprint against the
         direct (no-proxy) baseline fetched by _get_ipconfig_baseline().
      4. Geolocate the exit IP: parse country_code / country from the JSON
         body returned by ipconfig.io/json.

    Results written to the proxy object:
      proxy.alive        — True if all steps succeeded
      proxy.latency_ms   — round-trip time to first byte of response
      proxy.country      — ISO-2 code of the exit IP (from ipconfig.io)
      proxy.country_name — full country name
      proxy.mitm_clean   — False if the TLS cert fingerprint differs from
                           the direct baseline (MITM suspected)

    On any failure proxy.alive is set to False and the proxy is discarded.
    """
    start = time.monotonic()
    try:
        # ── 1. Open a socket through Tor to the exit proxy ───────────────────
        # PySocks transparently tunnels the TCP connection through Tor's
        # SOCKS5 interface.  After .connect() the socket carries traffic
        # between us and the exit proxy, via Tor.
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", tor_port)
        s.settimeout(_CHAIN_VERIFY_TIMEOUT)
        s.connect((proxy.host, proxy.port))
        # Path so far:  us ←TCP→ Tor ←TCP→ exit proxy

        # ── 2. Ask the exit proxy to connect to ipconfig.io:443 ──────────────
        # We speak SOCKS5 (or SOCKS4a) directly over the existing socket.
        # The exit proxy opens its own connection to ipconfig.io on our behalf.
        if proxy.proto == "socks5":
            ok = _socks5_connect_to(s, _IPCONFIG_HOST, _IPCONFIG_PORT)
        else:
            ok = _socks4a_connect_to(s, _IPCONFIG_HOST, _IPCONFIG_PORT)

        if not ok:
            proxy.alive = False
            return proxy
        # Path now:  us ←TCP→ Tor ←TCP→ exit proxy ←TCP→ ipconfig.io:443

        # ── 3. TLS handshake + MITM detection ────────────────────────────────
        # Wrap the socket in TLS.  The system CA bundle validates the cert
        # chain, so a self-signed or unknown-CA certificate will raise here.
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(s, server_hostname=_IPCONFIG_HOST)

        # Extract the raw DER certificate and fingerprint it.
        cert_der = tls.getpeercert(binary_form=True)
        fp = hashlib.sha256(cert_der).hexdigest()

        # Compare against the baseline fetched without any proxy.
        # If they differ, the exit proxy (or something between it and us)
        # is presenting its own certificate — classic TLS MITM.
        baseline = _get_ipconfig_baseline()
        if baseline and fp != baseline:
            proxy.mitm_clean = False
            logger.warning(
                f"MITM cert mismatch on {proxy.address}: "
                f"got {fp[:16]}… expected {baseline[:16]}…"
            )
        # baseline=None means the direct fetch failed; we skip the comparison
        # and leave mitm_clean=True (benefit of the doubt).

        # ── 4. HTTP GET /json — one request, two results ──────────────────────
        # We reuse the TLS connection we already have (no extra round-trip).
        # ipconfig.io sees the request arriving from the exit proxy's IP and
        # returns geolocation data (country_code, country, city, …) for it.
        tls.sendall((
            f"GET /json HTTP/1.1\r\n"
            f"Host: {_IPCONFIG_HOST}\r\n"
            f"Accept: application/json\r\n"
            f"Connection: close\r\n\r\n"
        ).encode())

        # Read up to 16 KB.  The /json response is tiny (~200 bytes); the cap
        # prevents hanging if a broken proxy sends garbage indefinitely.
        data = b""
        while len(data) < 16384:
            try:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            except (ssl.SSLError, OSError):
                break
        tls.close()

        # ── 5. Parse geolocation from the JSON body ───────────────────────────
        # We use a regex instead of splitting on \r\n\r\n so chunked
        # Transfer-Encoding is handled without a full HTTP parser.
        m = re.search(rb'\{[^{}]+\}', data)
        if m:
            info = _json.loads(m.group().decode("utf-8", errors="ignore"))
            cc = info.get("country_code", "")
            if isinstance(cc, str) and len(cc) >= 2:
                proxy.country = cc[:2].upper()
            cn = info.get("country", "")
            if isinstance(cn, str):
                proxy.country_name = cn

        # ── Done ─────────────────────────────────────────────────────────────
        proxy.latency_ms = (time.monotonic() - start) * 1000
        proxy.alive = True

    except Exception as exc:
        # Any failure (proxy down, Tor error, TLS error, timeout, …) marks
        # the proxy as dead.  Details go to DEBUG to avoid cluttering output.
        logger.debug(f"_verify_via_chain({proxy.address}): {exc}")
        proxy.alive = False

    return proxy


# ── Proxy liveness check ──────────────────────────────────────────────────────

def _check_proxy(proxy: Proxy, via_tor_port: Optional[int] = None) -> Proxy:
    """
    Test whether a proxy is reachable.
    If via_tor_port is set, the TCP connection goes through Tor first.
    """
    start = time.monotonic()
    try:
        if via_tor_port:
            import socks as socks_mod
            s = socks_mod.socksocket()
            s.set_proxy(socks_mod.SOCKS5, "127.0.0.1", via_tor_port)
            s.settimeout(PROXY_CHECK_TIMEOUT)
            s.connect((proxy.host, proxy.port))
            s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(PROXY_CHECK_TIMEOUT)
            s.connect((proxy.host, proxy.port))
            s.close()

        proxy.latency_ms = (time.monotonic() - start) * 1000
        proxy.alive = True
    except Exception:
        proxy.alive = False

    return proxy


def check_proxies(
    proxies: List[Proxy],
    via_tor_port: Optional[int] = None,
    max_workers: int = MAX_CHECK_WORKERS,
    show_progress: bool = True,
) -> List[Proxy]:
    """
    Check all proxies in parallel and return the alive ones sorted by latency.

    When via_tor_port is set, performs full chain verification:
    Tor → exit proxy → ipconfig.io:443 (HTTPS).  This sets country/country_name
    from the real exit IP and mitm_clean from TLS cert comparison.
    """
    if via_tor_port:
        # Pre-fetch the direct baseline once before spawning workers
        _get_ipconfig_baseline()
        check_fn = lambda p: _verify_via_chain(p, via_tor_port)
        desc = f"[cyan]Verifying {len(proxies)} proxies via full chain (ipconfig.io)...[/cyan]"
    else:
        check_fn = lambda p: _check_proxy(p)
        desc = f"[cyan]Checking {len(proxies)} proxies...[/cyan]"

    results = []
    total = len(proxies)
    _done = 0
    _alive = 0
    _lock = threading.Lock()

    def _run(p):
        nonlocal _done, _alive
        result = check_fn(p)
        with _lock:
            _done += 1
            if result.alive:
                _alive += 1
            done_snap, alive_snap = _done, _alive
        if done_snap % 10 == 0 or done_snap == total:
            logger.info(f"Tested {done_snap}/{total} — {alive_snap} alive")
        return result

    if show_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(desc, total=total)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_run, p): p for p in proxies}
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
                    progress.advance(task)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(_run, proxies))

    alive = [p for p in results if p.alive]
    return sorted(alive, key=lambda p: p.latency_ms)


# ── Entry point ───────────────────────────────────────────────────────────────

# Special sources that require a custom fetcher (JSON API, etc.)
_SPECIAL_SOURCES = [
    ("proxy-list.download", _fetch_proxylist_download),
]


def fetch_all_proxies(verbose: bool = False) -> List[Proxy]:
    """Fetch proxies from all sources (proxy_sources.py + special) and deduplicate."""
    all_proxies: List[Proxy] = []
    seen: set = set()
    total = len(SOURCES) + len(_SPECIAL_SOURCES)

    def _add(found: List[Proxy], name: str):
        new = 0
        for p in found:
            key = (p.host, p.port)
            if key not in seen:
                seen.add(key)
                all_proxies.append(p)
                new += 1
        if verbose:
            console.print(f"  [dim]{name}: {new} proxies[/dim]")
        logger.info(f"Source '{name}': {new} new proxies")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Fetching public proxies...[/cyan]", total=total)

        for source in SOURCES:
            progress.update(task, description=f"[cyan]Scraping: {source.name}[/cyan]")
            found = []
            for url in source.urls:
                found.extend(_fetch_text_url(url, source.proto))
            _add(found, source.name)
            progress.advance(task)

        for name, fetcher in _SPECIAL_SOURCES:
            progress.update(task, description=f"[cyan]Scraping: {name}[/cyan]")
            _add(fetcher(), name)
            progress.advance(task)

    console.print(
        f"[green]{len(all_proxies)} unique proxies collected from {total} sources.[/green]"
    )
    logger.info(f"Proxy fetch complete: {len(all_proxies)} unique proxies from {total} sources")
    return all_proxies


def get_countries_available(proxies: List[Proxy]) -> Dict[str, int]:
    """Return a {country_code: proxy_count} dict for proxies that have country info."""
    countries: Dict[str, int] = {}
    for p in proxies:
        if p.country:
            countries[p.country] = countries.get(p.country, 0) + 1
    return dict(sorted(countries.items(), key=lambda x: -x[1]))


def filter_by_country(proxies: List[Proxy], country_code: str) -> List[Proxy]:
    """Filter proxies by ISO country code."""
    cc = country_code.upper().strip()
    return [p for p in proxies if p.country.upper() == cc]
