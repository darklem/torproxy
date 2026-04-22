"""
Public SOCKS proxy scraper from multiple sources.
Fetches, deduplicates and filters proxies by country.

Sources are defined in proxy_sources.py — edit that file to add new ones.
"""

import time
import socket
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
MAX_CHECK_WORKERS = 30


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
    """Check all proxies in parallel and return the alive ones sorted by latency."""
    results = []

    if show_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Checking {len(proxies)} proxies...[/cyan]",
                total=len(proxies),
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_check_proxy, p, via_tor_port): p
                    for p in proxies
                }
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
                    progress.advance(task)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(lambda p: _check_proxy(p, via_tor_port), proxies))

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
