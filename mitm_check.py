"""
MITM (man-in-the-middle) detection — active chain and bulk proxy scan.

Active-chain checks (run_mitm_checks):
  1. TLS certificate fingerprint vs direct-connection baseline
  2. HTTP header injection (Via, X-Forwarded-For, X-Cache, …)
  3. SSL stripping — verify TLS handshake is not downgraded to plain HTTP

Bulk scan (scan_all_proxies):
  Runs checks 1 & 2 directly through Tor → each proxy, in parallel.
  Displays a result table with per-proxy verdict and a MITM ratio summary.
"""

import ssl
import socket
import hashlib
import struct
import json
import time
import concurrent.futures
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from enum import Enum

import requests
import socks as socks_mod
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
from rich import box

console = Console()

# ── Status & result types ─────────────────────────────────────────────────────

class Status(Enum):
    PASS    = "pass"
    WARN    = "warn"
    FAIL    = "fail"
    ERROR   = "error"
    TIMEOUT = "timeout"


@dataclass
class CheckResult:
    name: str
    status: Status
    detail: str


@dataclass
class ScanResult:
    proxy_host: str
    proxy_port: int
    proxy_proto: str
    country: str
    tls: Status
    headers: Status
    verdict: Status          # PASS / WARN / FAIL / ERROR / TIMEOUT
    injected_headers: List[str]


# ── Endpoints ─────────────────────────────────────────────────────────────────

_BASELINE_ENDPOINTS = ["ipinfo.io", "api.ipify.org"]

_PROXY_HEADERS = {
    "via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "forwarded", "proxy-connection", "x-cache", "x-cache-hits",
    "x-proxy-id", "x-bluecoat-via", "x-squid-error",
}

_HEADER_HOST = "httpbin.org"
_HEADER_PATH = "/headers"


# ── Low-level socket helpers ──────────────────────────────────────────────────

def _recvall_sock(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"Socket closed ({len(data)}/{n} bytes)")
        data += chunk
    return data


def _socks5_tunnel(sock: socket.socket, host: str, port: int):
    """Speak SOCKS5 (no-auth) to tunnel sock to host:port."""
    sock.sendall(b"\x05\x01\x00")
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
    atyp = hdr[3]
    if atyp == 0x01:   _recvall_sock(sock, 6)
    elif atyp == 0x03: _recvall_sock(sock, _recvall_sock(sock, 1)[0] + 2)
    elif atyp == 0x04: _recvall_sock(sock, 18)


def _socks4_tunnel(sock: socket.socket, host: str, port: int):
    """Speak SOCKS4a to tunnel sock to host:port."""
    host_b = host.encode() + b"\x00"
    sock.sendall(
        b"\x04\x01"
        + struct.pack("!H", port)
        + b"\x00\x00\x00\x01\x00"
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
    Return a socket tunneled through Tor → exit proxy → target host:port.
    The caller is responsible for closing the socket.
    """
    sock = socks_mod.socksocket()
    sock.set_proxy(socks_mod.SOCKS5, "127.0.0.1", tor_port, rdns=True)
    sock.settimeout(timeout)
    sock.connect((proxy_host, proxy_port))
    if proxy_proto.lower() == "socks4":
        _socks4_tunnel(sock, target_host, target_port)
    else:
        _socks5_tunnel(sock, target_host, target_port)
    return sock


# ── Per-proxy check primitives ────────────────────────────────────────────────

def _cert_via_chain(
    proxy_host: str, proxy_port: int, proxy_proto: str,
    tor_port: int, host: str,
) -> Optional[str]:
    """SHA-256 fingerprint of the TLS cert seen through Tor → proxy → host."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
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
    Send a plain HTTP request through Tor → proxy → httpbin.org/headers.
    Returns the set of injected proxy-related header names, or None on error.
    """
    try:
        sock = _connect_via_chain(
            proxy_host, proxy_port, proxy_proto,
            tor_port, _HEADER_HOST, 80,
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
        seen = {k.lower() for k in data.get("headers", {}).keys()}
        return seen & _PROXY_HEADERS
    except Exception:
        return None


# ── Baseline (direct, no proxy) ───────────────────────────────────────────────

def _get_cert_direct(host: str, timeout: int = 10) -> Optional[str]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    except Exception:
        return None


def fetch_baseline_fingerprints() -> Dict[str, str]:
    """Fetch TLS cert fingerprints directly (no proxy) for all baseline endpoints."""
    return {host: _get_cert_direct(host) for host in _BASELINE_ENDPOINTS}


# ── Active-chain checks (existing API, unchanged) ─────────────────────────────

def _get_cert_fingerprint_via_proxy(host: str, local_port: int, timeout: int = 15) -> Optional[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socks_mod.socksocket()
        raw.set_proxy(socks_mod.SOCKS5, "127.0.0.1", local_port)
        raw.settimeout(timeout)
        raw.connect((host, 443))
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    except Exception:
        return None


def check_tls_cert(local_port: int) -> CheckResult:
    mismatches, errors = [], []
    for host in _BASELINE_ENDPOINTS:
        direct  = _get_cert_direct(host)
        proxied = _get_cert_fingerprint_via_proxy(host, local_port)
        if direct is None or proxied is None:
            errors.append(host)
        elif direct != proxied:
            mismatches.append(host)
    if mismatches:
        return CheckResult("TLS certificate", Status.FAIL,
            f"Cert mismatch on: {', '.join(mismatches)} — proxy may be intercepting TLS")
    if errors:
        return CheckResult("TLS certificate", Status.ERROR,
            f"Could not compare certs for: {', '.join(errors)}")
    return CheckResult("TLS certificate", Status.PASS,
        f"Fingerprints match on all {len(_BASELINE_ENDPOINTS)} endpoints")


def check_header_injection(local_port: int) -> CheckResult:
    proxies = {
        "http":  f"socks5h://127.0.0.1:{local_port}",
        "https": f"socks5h://127.0.0.1:{local_port}",
    }
    try:
        r = requests.get(f"http://{_HEADER_HOST}{_HEADER_PATH}", proxies=proxies, timeout=20)
        injected = {k.lower() for k in r.json().get("headers", {}).keys()} & _PROXY_HEADERS
        if injected:
            return CheckResult("Header injection", Status.WARN,
                f"Proxy headers in upstream request: {', '.join(sorted(injected))}")
        return CheckResult("Header injection", Status.PASS,
            "No proxy headers injected into upstream HTTP request")
    except Exception as e:
        return CheckResult("Header injection", Status.ERROR, f"Unreachable: {e}")


def check_ssl_stripping(local_port: int) -> CheckResult:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socks_mod.socksocket()
        raw.set_proxy(socks_mod.SOCKS5, "127.0.0.1", local_port)
        raw.settimeout(15)
        raw.connect(("ipinfo.io", 443))
        with ctx.wrap_socket(raw, server_hostname="ipinfo.io") as tls:
            cipher = tls.cipher()
            if cipher:
                return CheckResult("SSL stripping", Status.PASS, f"TLS OK ({cipher[0]})")
            return CheckResult("SSL stripping", Status.WARN, "TLS established, cipher unavailable")
    except ssl.SSLError as e:
        return CheckResult("SSL stripping", Status.FAIL, f"TLS handshake failed: {e}")
    except Exception as e:
        return CheckResult("SSL stripping", Status.ERROR, f"Connection error: {e}")


def run_mitm_checks(local_port: int) -> List[CheckResult]:
    checks = [
        ("Checking TLS certificates...", lambda: check_tls_cert(local_port)),
        ("Checking header injection...", lambda: check_header_injection(local_port)),
        ("Checking SSL stripping...",    lambda: check_ssl_stripping(local_port)),
    ]
    results = []
    for label, fn in checks:
        console.print(f"[dim]  {label}[/dim]", end="\r")
        results.append(fn())
    return results


def display_mitm_results(results: List[CheckResult]):
    STATUS_STYLE = {
        Status.PASS:    "[green]PASS[/green]",
        Status.WARN:    "[yellow]WARN[/yellow]",
        Status.FAIL:    "[red]FAIL[/red]",
        Status.ERROR:   "[dim]ERR[/dim]",
        Status.TIMEOUT: "[dim]TIME[/dim]",
    }
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Status", no_wrap=True, width=6)
    table.add_column("Check",  style="bold", no_wrap=True)
    table.add_column("Detail", style="dim")

    has_fail = any(r.status == Status.FAIL for r in results)
    has_warn = any(r.status == Status.WARN for r in results)
    for r in results:
        table.add_row(STATUS_STYLE[r.status], r.name, r.detail)

    if has_fail:
        border, title = "red",    "[bold red]⚠  MITM check — SUSPICIOUS[/bold red]"
    elif has_warn:
        border, title = "yellow", "[bold yellow]⚠  MITM check — warnings[/bold yellow]"
    else:
        border, title = "green",  "[bold green]✓  MITM check — clean[/bold green]"
    console.print(Panel(table, title=title, border_style=border, padding=(0, 1)))


# ── Bulk scan ─────────────────────────────────────────────────────────────────

def _scan_one(proxy, tor_port: int, baseline: Dict[str, str]) -> ScanResult:
    """Run TLS + header checks on a single proxy through the Tor chain."""
    from proxy_scraper import Proxy  # avoid circular at module level

    # TLS check
    tls_status = Status.ERROR
    for host, expected in baseline.items():
        if expected is None:
            continue
        got = _cert_via_chain(proxy.host, proxy.port, proxy.proto, tor_port, host)
        if got is None:
            tls_status = Status.TIMEOUT
            break
        if got != expected:
            tls_status = Status.FAIL
            break
        tls_status = Status.PASS

    # Header injection check
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

    # Overall verdict
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


def scan_all_proxies(
    proxies: list,
    tor_port: int,
    max_workers: int = 15,
) -> List[ScanResult]:
    """
    Scan a list of proxies for MITM behavior in parallel.
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
    """Display the bulk scan results table with per-proxy verdict and ratio summary."""

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
        cc_display = f"{_flag(cc)} {cc}"
        hdr_cell = (
            f"[yellow]{', '.join(r.injected_headers)}[/yellow]"
            if r.injected_headers else TLS_BADGE[r.headers]
        )
        table.add_row(
            cc_display,
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

    ratio_mitm  = n_mitm  / total * 100 if total else 0
    ratio_warn  = n_warn  / total * 100 if total else 0
    ratio_clean = n_clean / total * 100 if total else 0

    summary = (
        f"  [bold]Tested:[/bold] {total} proxies\n"
        f"  [red]MITM   :[/red]  {n_mitm:>4}  ({ratio_mitm:5.1f}%)\n"
        f"  [yellow]Warn   :[/yellow]  {n_warn:>4}  ({ratio_warn:5.1f}%)\n"
        f"  [green]Clean  :[/green]  {n_clean:>4}  ({ratio_clean:5.1f}%)\n"
        f"  [dim]Timeout/Err: {n_err}[/dim]"
    )

    border = "red" if n_mitm else ("yellow" if n_warn else "green")
    console.print(Panel(summary, title="[bold]Scan summary[/bold]", border_style=border, padding=(0, 2)))
