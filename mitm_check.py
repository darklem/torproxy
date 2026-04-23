"""
Bulk MITM scan for cached proxies  (--scan-mitm mode).

MITM detection during normal operation is handled in proxy_scraper.py:
_verify_via_chain() does a single HTTPS connection to ipconfig.io per proxy
and compares the TLS certificate fingerprint against a direct baseline.
Only proxies that pass are added to the active pool and the cache.

This module is only used by the --scan-mitm CLI flag, which runs a batch
check of already-cached proxies to audit them independently.

Each proxy is checked for:
  1. TLS certificate fingerprint  (Tor → proxy → ipinfo.io / api.ipify.org)
     Fingerprints are compared against a baseline fetched directly (no proxy).
     A mismatch means the proxy is presenting a different certificate → MITM.

  2. HTTP header injection  (Tor → proxy → httpbin.org/headers, plain HTTP)
     httpbin echoes all request headers it received.  If proxy-related headers
     (Via, X-Forwarded-For, …) appear, the proxy is injecting them.

Results: PASS / WARN / FAIL per proxy, with a ratio summary at the end.
"""

import ssl
import socket
import hashlib
import struct
import json
import time
import concurrent.futures
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import Enum

import socks as socks_mod
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
from rich import box

console = Console()

# ── Status codes ──────────────────────────────────────────────────────────────

class Status(Enum):
    PASS    = "pass"
    WARN    = "warn"     # suspicious but not conclusive
    FAIL    = "fail"     # clear evidence of MITM
    ERROR   = "error"    # could not complete the check
    TIMEOUT = "timeout"  # proxy too slow to respond


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Result of a full MITM scan on one proxy."""
    proxy_host: str
    proxy_port: int
    proxy_proto: str
    country: str
    tls: Status          # TLS certificate check
    headers: Status      # HTTP header injection check
    verdict: Status      # PASS / WARN / FAIL / ERROR / TIMEOUT
    injected_headers: List[str]   # names of injected headers (if any)


# ── Endpoints ─────────────────────────────────────────────────────────────────

# Hosts used for TLS certificate comparison
_BASELINE_ENDPOINTS = ["ipinfo.io", "api.ipify.org"]

# Header names that indicate a transparent / injecting proxy
_PROXY_HEADERS = {
    "via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "forwarded", "proxy-connection", "x-cache", "x-cache-hits",
    "x-proxy-id", "x-bluecoat-via", "x-squid-error",
}

# httpbin echoes request headers as JSON — ideal for header injection detection
_HEADER_HOST = "httpbin.org"
_HEADER_PATH = "/headers"


# ── Low-level socket helpers ──────────────────────────────────────────────────

def _recvall_sock(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes, handling TCP fragmentation."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"Socket closed ({len(data)}/{n} bytes)")
        data += chunk
    return data


def _socks5_tunnel(sock: socket.socket, host: str, port: int):
    """
    Client-side SOCKS5 handshake over an already-open socket.
    Asks the SOCKS5 server to tunnel us to host:port.
    Raises ConnectionError on failure.
    """
    sock.sendall(b"\x05\x01\x00")   # offer no-auth only
    resp = _recvall_sock(sock, 2)
    if resp[1] != 0x00:
        raise ConnectionError(f"SOCKS5 auth rejected: {resp!r}")
    host_b = host.encode()
    sock.sendall(
        b"\x05\x01\x00\x03"
        + bytes([len(host_b)]) + host_b
        + struct.pack("!H", port)
    )
    hdr = _recvall_sock(sock, 4)
    if hdr[1] != 0x00:
        raise ConnectionError(f"SOCKS5 CONNECT failed: 0x{hdr[1]:02x}")
    # Consume BND.ADDR + BND.PORT
    atyp = hdr[3]
    if atyp == 0x01:    _recvall_sock(sock, 6)
    elif atyp == 0x03:  _recvall_sock(sock, _recvall_sock(sock, 1)[0] + 2)
    elif atyp == 0x04:  _recvall_sock(sock, 18)


def _socks4_tunnel(sock: socket.socket, host: str, port: int):
    """
    Client-side SOCKS4a handshake over an already-open socket.
    Raises ConnectionError on failure.
    """
    host_b = host.encode() + b"\x00"
    sock.sendall(
        b"\x04\x01"
        + struct.pack("!H", port)
        + b"\x00\x00\x00\x01\x00"   # IP=0.0.0.1 (SOCKS4a) + empty user-id
        + host_b
    )
    resp = _recvall_sock(sock, 8)
    if resp[1] != 0x5A:
        raise ConnectionError(f"SOCKS4 CONNECT failed: 0x{resp[1]:02x}")


def _connect_via_chain(
    proxy_host: str, proxy_port: int, proxy_proto: str,
    tor_port: int,
    target_host: str, target_port: int,
    timeout: int = 12,
) -> socket.socket:
    """
    Return a socket already tunneled through Tor → exit proxy → target host:port.
    The caller owns the socket and must close it.

    Path: us → Tor (SOCKS5 at 127.0.0.1:tor_port)
              → exit proxy (SOCKS4/5 at proxy_host:proxy_port)
                  → target_host:target_port
    """
    sock = socks_mod.socksocket()
    sock.set_proxy(socks_mod.SOCKS5, "127.0.0.1", tor_port, rdns=True)
    sock.settimeout(timeout)
    sock.connect((proxy_host, proxy_port))   # Tor reaches the exit proxy

    # Now speak SOCKS to the exit proxy to reach the final target
    if proxy_proto.lower() == "socks4":
        _socks4_tunnel(sock, target_host, target_port)
    else:
        _socks5_tunnel(sock, target_host, target_port)
    return sock


# ── Per-check primitives ──────────────────────────────────────────────────────

def _cert_via_chain(
    proxy_host: str, proxy_port: int, proxy_proto: str,
    tor_port: int, host: str,
) -> Optional[str]:
    """
    Return the SHA-256 fingerprint of the TLS certificate presented by host
    when connecting through Tor → exit proxy.
    Returns None if the connection or handshake fails.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # we compare fingerprints manually
    try:
        sock = _connect_via_chain(proxy_host, proxy_port, proxy_proto, tor_port, host, 443)
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    except Exception:
        return None


def _headers_via_chain(
    proxy_host: str, proxy_port: int, proxy_proto: str,
    tor_port: int,
) -> Optional[set]:
    """
    Send a plain HTTP request to httpbin.org/headers through the chain.
    httpbin returns the request headers it received as JSON.

    Returns the set of injected proxy-related header names, or None on error.
    An empty set means no injection was detected.
    """
    try:
        sock = _connect_via_chain(
            proxy_host, proxy_port, proxy_proto,
            tor_port, _HEADER_HOST, 80,   # plain HTTP so the proxy can see headers
        )
        req = (
            f"GET {_HEADER_PATH} HTTP/1.0\r\n"
            f"Host: {_HEADER_HOST}\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
        body = raw.split(b"\r\n\r\n", 1)[-1].decode(errors="ignore")
        data = json.loads(body)
        # Intersect received headers with the known proxy-injection list
        seen = {k.lower() for k in data.get("headers", {}).keys()}
        return seen & _PROXY_HEADERS
    except Exception:
        return None


# ── Baseline (direct, no proxy) ───────────────────────────────────────────────

def _get_cert_direct(host: str, timeout: int = 10) -> Optional[str]:
    """SHA-256 fingerprint of host's TLS cert via a direct connection (no proxy)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    except Exception:
        return None


def fetch_baseline_fingerprints() -> Dict[str, str]:
    """Fetch TLS cert fingerprints for all baseline endpoints directly (no proxy)."""
    return {host: _get_cert_direct(host) for host in _BASELINE_ENDPOINTS}


# ── Single-proxy scan ─────────────────────────────────────────────────────────

def _scan_one(proxy, tor_port: int, baseline: Dict[str, str]) -> ScanResult:
    """
    Run TLS + header checks on a single proxy through the Tor chain.
    baseline: {host: expected_fingerprint} from fetch_baseline_fingerprints().
    """
    from proxy_scraper import Proxy  # avoid circular import at module level

    # ── TLS check ────────────────────────────────────────────────────────────
    tls_status = Status.ERROR
    for host, expected in baseline.items():
        if expected is None:
            continue
        got = _cert_via_chain(proxy.host, proxy.port, proxy.proto, tor_port, host)
        if got is None:
            tls_status = Status.TIMEOUT
            break
        if got != expected:
            tls_status = Status.FAIL   # cert mismatch = MITM
            break
        tls_status = Status.PASS

    # ── Header injection check (only if proxy seems reachable) ────────────────
    injected: List[str] = []
    if tls_status not in (Status.TIMEOUT, Status.ERROR):
        found = _headers_via_chain(proxy.host, proxy.port, proxy.proto, tor_port)
        if found is None:
            headers_status = Status.ERROR
        elif found:
            headers_status = Status.WARN
            injected = sorted(found)
        else:
            headers_status = Status.PASS
    else:
        headers_status = Status.TIMEOUT

    # ── Overall verdict ───────────────────────────────────────────────────────
    if tls_status == Status.FAIL:
        verdict = Status.FAIL
    elif tls_status in (Status.TIMEOUT, Status.ERROR) and headers_status in (Status.TIMEOUT, Status.ERROR):
        verdict = Status.TIMEOUT
    elif headers_status == Status.WARN:
        verdict = Status.WARN
    elif tls_status == Status.PASS and headers_status == Status.PASS:
        verdict = Status.PASS
    else:
        verdict = Status.ERROR

    return ScanResult(
        proxy_host=proxy.host,
        proxy_port=proxy.port,
        proxy_proto=proxy.proto,
        country=proxy.country,
        tls=tls_status,
        headers=headers_status,
        verdict=verdict,
        injected_headers=injected,
    )


# ── Bulk scan entry point ─────────────────────────────────────────────────────

def scan_all_proxies(
    proxies: list,
    tor_port: int,
    max_workers: int = 15,
) -> List[ScanResult]:
    """
    Scan a list of proxies for MITM behaviour in parallel.
    Fetches the TLS baseline once, then tests each proxy concurrently.
    Returns results in completion order.
    """
    console.print("[cyan]Fetching TLS baseline (direct connection)...[/cyan]")
    baseline = fetch_baseline_fingerprints()
    available = [h for h, fp in baseline.items() if fp]
    if not available:
        console.print("[red]Could not fetch any baseline fingerprint. Aborting scan.[/red]")
        return []
    console.print(f"[dim]  Baseline ready for: {', '.join(available)}[/dim]")

    results: List[ScanResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[mitm]} MITM  {task.fields[warn]} warn  {task.fields[clean]} clean[/dim]"),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {len(proxies)} proxies...[/cyan]",
            total=len(proxies),
            mitm=0, warn=0, clean=0,
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_one, p, tor_port, baseline): p for p in proxies}
            for future in concurrent.futures.as_completed(futures):
                r = future.result()
                results.append(r)
                mitm  = sum(1 for x in results if x.verdict == Status.FAIL)
                warn  = sum(1 for x in results if x.verdict == Status.WARN)
                clean = sum(1 for x in results if x.verdict == Status.PASS)
                progress.update(task, advance=1, mitm=mitm, warn=warn, clean=clean)

    return results


# ── Display ───────────────────────────────────────────────────────────────────

def _flag(cc: str) -> str:
    flags = {
        "FR": "🇫🇷", "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "CN": "🇨🇳",
        "RU": "🇷🇺", "JP": "🇯🇵", "NL": "🇳🇱", "BR": "🇧🇷", "IN": "🇮🇳",
        "CA": "🇨🇦", "AU": "🇦🇺", "KR": "🇰🇷", "IT": "🇮🇹", "ES": "🇪🇸",
        "PL": "🇵🇱", "UA": "🇺🇦", "TR": "🇹🇷", "ID": "🇮🇩", "TH": "🇹🇭",
        "VN": "🇻🇳", "HK": "🇭🇰", "SG": "🇸🇬", "AR": "🇦🇷", "MX": "🇲🇽",
        "ZA": "🇿🇦", "NG": "🇳🇬", "EG": "🇪🇬", "PK": "🇵🇰", "BD": "🇧🇩",
    }
    return flags.get(cc.upper(), "🏳️")


def display_scan_results(results: List[ScanResult]):
    """Print the bulk scan table and a ratio summary panel."""

    VERDICT_BADGE = {
        Status.PASS:    "[green]CLEAN[/green]",
        Status.WARN:    "[yellow]WARN[/yellow]",
        Status.FAIL:    "[red]MITM[/red]",
        Status.ERROR:   "[dim]ERR[/dim]",
        Status.TIMEOUT: "[dim]TIMEOUT[/dim]",
    }
    TLS_BADGE = {
        Status.PASS:    "[green]✓[/green]",
        Status.WARN:    "[yellow]~[/yellow]",
        Status.FAIL:    "[red]✗[/red]",
        Status.ERROR:   "[dim]?[/dim]",
        Status.TIMEOUT: "[dim]·[/dim]",
    }

    table = Table(
        title="MITM Bulk Scan",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Country",  no_wrap=True)
    table.add_column("Proxy",    no_wrap=True, style="dim")
    table.add_column("Proto",    no_wrap=True, justify="center")
    table.add_column("TLS",      no_wrap=True, justify="center")
    table.add_column("Headers",  no_wrap=True, justify="center", style="dim")
    table.add_column("Verdict",  no_wrap=True)

    # Sort: FAIL first, then WARN, then the rest
    order = {Status.FAIL: 0, Status.WARN: 1, Status.PASS: 2, Status.ERROR: 3, Status.TIMEOUT: 4}
    for r in sorted(results, key=lambda x: order.get(x.verdict, 9)):
        cc = r.country or "??"
        hdr_cell = (
            f"[yellow]{', '.join(r.injected_headers)}[/yellow]"
            if r.injected_headers else TLS_BADGE[r.headers]
        )
        table.add_row(
            f"{_flag(cc)} {cc}",
            f"{r.proxy_host}:{r.proxy_port}",
            r.proxy_proto.upper(),
            TLS_BADGE[r.tls],
            hdr_cell,
            VERDICT_BADGE[r.verdict],
        )

    console.print()
    console.print(table)

    # ── Summary ──
    total   = len(results)
    n_mitm  = sum(1 for r in results if r.verdict == Status.FAIL)
    n_warn  = sum(1 for r in results if r.verdict == Status.WARN)
    n_clean = sum(1 for r in results if r.verdict == Status.PASS)
    n_err   = sum(1 for r in results if r.verdict in (Status.ERROR, Status.TIMEOUT))

    summary = (
        f"  [bold]Tested:[/bold] {total} proxies\n"
        f"  [red]MITM   :[/red]  {n_mitm:>4}  ({n_mitm/total*100:5.1f}%)\n"
        f"  [yellow]Warn   :[/yellow]  {n_warn:>4}  ({n_warn/total*100:5.1f}%)\n"
        f"  [green]Clean  :[/green]  {n_clean:>4}  ({n_clean/total*100:5.1f}%)\n"
        f"  [dim]Timeout/Err: {n_err}[/dim]"
    ) if total else "  No results."

    border = "red" if n_mitm else ("yellow" if n_warn else "green")
    console.print(Panel(summary, title="[bold]Scan summary[/bold]", border_style=border, padding=(0, 2)))
