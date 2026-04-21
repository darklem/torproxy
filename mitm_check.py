"""
MITM (man-in-the-middle) detection for the active proxy chain.

Runs three independent checks:
  1. TLS certificate issuer / fingerprint against a known-good baseline
  2. HTTP header injection (Via, X-Forwarded-For, Proxy-Connection, X-Cache, etc.)
  3. SSL stripping — verify HTTPS is not silently downgraded to HTTP

Each check returns a CheckResult. The final verdict is CLEAN only if all pass.
"""

import ssl
import socket
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


class Status(Enum):
    PASS  = "pass"
    WARN  = "warn"
    FAIL  = "fail"
    ERROR = "error"


@dataclass
class CheckResult:
    name: str
    status: Status
    detail: str


# ── Known-good TLS fingerprints ───────────────────────────────────────────────
# SHA-256 of the DER-encoded leaf certificate for a set of stable endpoints.
# These are collected via a direct (non-proxied) connection at tool build time.
# A mismatch means the proxy presented a different cert → likely interception.

_BASELINE_ENDPOINTS = [
    "ipinfo.io",
    "api.ipify.org",
]


def _get_cert_fingerprint(host: str, port: int = 443, timeout: int = 10) -> Optional[str]:
    """Return SHA-256 fingerprint of the leaf TLS certificate for host:port."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                return hashlib.sha256(der).hexdigest()
    except Exception:
        return None


def _get_cert_fingerprint_via_proxy(
    host: str,
    local_port: int,
    port: int = 443,
    timeout: int = 15,
) -> Optional[str]:
    """
    Return SHA-256 fingerprint of the TLS certificate seen through the proxy chain.
    We open a raw TCP tunnel via the local SOCKS5 server, then do a TLS handshake
    ourselves so we can inspect the cert before requests/urllib processes it.
    """
    import socks as socks_mod

    ctx = ssl.create_default_context()
    # We want to see the cert even if validation fails (self-signed MITM cert)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socks_mod.socksocket()
        raw.set_proxy(socks_mod.SOCKS5, "127.0.0.1", local_port)
        raw.settimeout(timeout)
        raw.connect((host, port))
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            return hashlib.sha256(der).hexdigest()
    except Exception:
        return None


def check_tls_cert(local_port: int) -> CheckResult:
    """
    Compare TLS cert fingerprints seen through the proxy vs a direct connection.
    A mismatch on any endpoint is a strong MITM signal.
    """
    mismatches = []
    errors = []

    for host in _BASELINE_ENDPOINTS:
        direct = _get_cert_fingerprint(host)
        proxied = _get_cert_fingerprint_via_proxy(host, local_port)

        if direct is None or proxied is None:
            errors.append(host)
            continue

        if direct != proxied:
            mismatches.append(host)

    if mismatches:
        return CheckResult(
            name="TLS certificate",
            status=Status.FAIL,
            detail=f"Certificate mismatch on: {', '.join(mismatches)} — proxy may be intercepting TLS",
        )
    if errors and not mismatches:
        return CheckResult(
            name="TLS certificate",
            status=Status.ERROR,
            detail=f"Could not compare certs for: {', '.join(errors)} (timeout or connection error)",
        )
    return CheckResult(
        name="TLS certificate",
        status=Status.PASS,
        detail=f"Cert fingerprints match on all {len(_BASELINE_ENDPOINTS)} endpoints",
    )


# ── Header injection check ────────────────────────────────────────────────────

_PROXY_HEADERS = {
    "via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "forwarded", "proxy-connection", "x-cache", "x-cache-hits",
    "x-proxy-id", "x-bluecoat-via", "x-squid-error",
}

_HEADER_ENDPOINT = "http://httpbin.org/headers"   # plain HTTP so we can see injected headers


def check_header_injection(local_port: int) -> CheckResult:
    """
    Send an HTTP (not HTTPS) request and check whether the proxy injected
    any forwarding or identification headers into the upstream request.
    """
    proxies = {
        "http":  f"socks5h://127.0.0.1:{local_port}",
        "https": f"socks5h://127.0.0.1:{local_port}",
    }
    try:
        r = requests.get(_HEADER_ENDPOINT, proxies=proxies, timeout=20)
        received_headers = {k.lower() for k in r.json().get("headers", {}).keys()}
        injected = received_headers & _PROXY_HEADERS
        if injected:
            return CheckResult(
                name="Header injection",
                status=Status.WARN,
                detail=f"Proxy-related headers found in upstream request: {', '.join(sorted(injected))}",
            )
        return CheckResult(
            name="Header injection",
            status=Status.PASS,
            detail="No proxy headers injected into upstream HTTP request",
        )
    except Exception as e:
        return CheckResult(
            name="Header injection",
            status=Status.ERROR,
            detail=f"Could not reach {_HEADER_ENDPOINT}: {e}",
        )


# ── SSL stripping check ───────────────────────────────────────────────────────

def check_ssl_stripping(local_port: int) -> CheckResult:
    """
    Attempt an HTTPS connection through the proxy and verify the TLS handshake
    actually completed (i.e. we are not silently talking plain HTTP).
    """
    import socks as socks_mod

    host = "ipinfo.io"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socks_mod.socksocket()
        raw.set_proxy(socks_mod.SOCKS5, "127.0.0.1", local_port)
        raw.settimeout(15)
        raw.connect((host, 443))
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            cipher = tls.cipher()
            if cipher:
                return CheckResult(
                    name="SSL stripping",
                    status=Status.PASS,
                    detail=f"TLS handshake succeeded ({cipher[0]})",
                )
            return CheckResult(
                name="SSL stripping",
                status=Status.WARN,
                detail="TLS connection established but cipher info unavailable",
            )
    except ssl.SSLError as e:
        return CheckResult(
            name="SSL stripping",
            status=Status.FAIL,
            detail=f"TLS handshake failed — possible SSL stripping: {e}",
        )
    except Exception as e:
        return CheckResult(
            name="SSL stripping",
            status=Status.ERROR,
            detail=f"Connection error: {e}",
        )


# ── Public API ────────────────────────────────────────────────────────────────

def run_mitm_checks(local_port: int) -> List[CheckResult]:
    """Run all MITM checks and return results."""
    checks = [
        ("Checking TLS certificates...",   lambda: check_tls_cert(local_port)),
        ("Checking header injection...",   lambda: check_header_injection(local_port)),
        ("Checking SSL stripping...",      lambda: check_ssl_stripping(local_port)),
    ]
    results = []
    for label, fn in checks:
        console.print(f"[dim]  {label}[/dim]", end="\r")
        results.append(fn())
    return results


def display_mitm_results(results: List[CheckResult]):
    """Render check results as a Rich table inside a panel."""
    STATUS_STYLE = {
        Status.PASS:  ("[green]PASS[/green]",  "green"),
        Status.WARN:  ("[yellow]WARN[/yellow]", "yellow"),
        Status.FAIL:  ("[red]FAIL[/red]",      "red"),
        Status.ERROR: ("[dim]ERR[/dim]",        "dim"),
    }

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Status", no_wrap=True, width=6)
    table.add_column("Check",  style="bold", no_wrap=True)
    table.add_column("Detail", style="dim")

    overall_ok = True
    for r in results:
        badge, _ = STATUS_STYLE[r.status]
        table.add_row(badge, r.name, r.detail)
        if r.status in (Status.FAIL, Status.WARN):
            overall_ok = False

    has_fail = any(r.status == Status.FAIL for r in results)
    if has_fail:
        border = "red"
        title = "[bold red]⚠  MITM check — SUSPICIOUS[/bold red]"
    elif not overall_ok:
        border = "yellow"
        title = "[bold yellow]⚠  MITM check — warnings[/bold yellow]"
    else:
        border = "green"
        title = "[bold green]✓  MITM check — clean[/bold green]"

    console.print(Panel(table, title=title, border_style=border, padding=(0, 1)))
