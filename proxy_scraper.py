"""
Scraper de proxies SOCKS publics depuis plusieurs sources.
Récupère, déduplique et filtre les proxies par pays.
"""

import re
import time
import socket
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlparse

import requests
import socks

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

# Timeout pour vérifier un proxy
PROXY_CHECK_TIMEOUT = 8
# Nombre de workers pour le check concurrent
MAX_CHECK_WORKERS = 30


@dataclass
class Proxy:
    """Représente un proxy SOCKS."""
    host: str
    port: int
    proto: str = "socks5"       # "socks4" ou "socks5"
    country: str = ""           # Code pays ISO 2 lettres (ex: "FR", "US")
    country_name: str = ""      # Nom complet du pays
    latency_ms: float = -1.0    # -1 = non testé
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


# ──────────────────────────────────────────────
# Sources de proxies publics
# ──────────────────────────────────────────────

def _fetch_proxyscrape_socks5() -> List[Proxy]:
    """proxyscrape.com – SOCKS5."""
    proxies = []
    urls = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_type=socks5&timeout=10000&country=all&simplified=true",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.strip().splitlines():
                line = line.strip()
                if ":" in line:
                    host, port_s = line.rsplit(":", 1)
                    try:
                        proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks5"))
                    except ValueError:
                        pass
        except Exception:
            pass
    return proxies


def _fetch_proxyscrape_socks4() -> List[Proxy]:
    """proxyscrape.com – SOCKS4."""
    proxies = []
    urls = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_type=socks4&timeout=10000&country=all&simplified=true",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.strip().splitlines():
                line = line.strip()
                if ":" in line:
                    host, port_s = line.rsplit(":", 1)
                    try:
                        proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks4"))
                    except ValueError:
                        pass
        except Exception:
            pass
    return proxies


def _fetch_github_hookzof() -> List[Proxy]:
    """hookzof/socks5_list sur GitHub."""
    proxies = []
    url = "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
    try:
        r = requests.get(url, timeout=15)
        for line in r.text.strip().splitlines():
            line = line.strip()
            if ":" in line:
                host, port_s = line.rsplit(":", 1)
                try:
                    proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks5"))
                except ValueError:
                    pass
    except Exception:
        pass
    return proxies


def _fetch_github_proxifly() -> List[Proxy]:
    """proxifly/proxy-list – SOCKS5 avec pays."""
    proxies = []
    url = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"
    try:
        r = requests.get(url, timeout=15)
        for line in r.text.strip().splitlines():
            line = line.strip()
            if ":" in line:
                host, port_s = line.rsplit(":", 1)
                try:
                    proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks5"))
                except ValueError:
                    pass
    except Exception:
        pass
    return proxies


def _fetch_github_thespeedx() -> List[Proxy]:
    """TheSpeedX/PROXY-List – SOCKS5."""
    proxies = []
    url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
    try:
        r = requests.get(url, timeout=15)
        for line in r.text.strip().splitlines():
            line = line.strip()
            if ":" in line:
                host, port_s = line.rsplit(":", 1)
                try:
                    proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks5"))
                except ValueError:
                    pass
    except Exception:
        pass
    return proxies


def _fetch_github_thespeedx_s4() -> List[Proxy]:
    """TheSpeedX/PROXY-List – SOCKS4."""
    proxies = []
    url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"
    try:
        r = requests.get(url, timeout=15)
        for line in r.text.strip().splitlines():
            line = line.strip()
            if ":" in line:
                host, port_s = line.rsplit(":", 1)
                try:
                    proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks4"))
                except ValueError:
                    pass
    except Exception:
        pass
    return proxies


def _fetch_github_monosans() -> List[Proxy]:
    """monosans/proxy-list – SOCKS5."""
    proxies = []
    urls = [
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks5.txt",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=15)
            for line in r.text.strip().splitlines():
                line = line.strip().split()[0]  # enlever commentaires éventuels
                if ":" in line:
                    host, port_s = line.rsplit(":", 1)
                    try:
                        proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks5"))
                    except ValueError:
                        pass
        except Exception:
            pass
    return proxies


def _fetch_proxylist_download() -> List[Proxy]:
    """proxy-list.download – SOCKS5 avec pays."""
    proxies = []
    try:
        r = requests.get(
            "https://www.proxy-list.download/api/v2/get?l=en&t=socks5",
            timeout=15
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
                        country=country.upper()[:2] if country else ""
                    ))
                except ValueError:
                    pass
    except Exception:
        pass
    return proxies


def _fetch_openproxylist() -> List[Proxy]:
    """openproxylist.xyz – SOCKS5."""
    proxies = []
    try:
        r = requests.get(
            "https://openproxylist.xyz/socks5.txt",
            timeout=15
        )
        for line in r.text.strip().splitlines():
            line = line.strip()
            if ":" in line:
                host, port_s = line.rsplit(":", 1)
                try:
                    proxies.append(Proxy(host=host.strip(), port=int(port_s.strip()), proto="socks5"))
                except ValueError:
                    pass
    except Exception:
        pass
    return proxies


# ──────────────────────────────────────────────
# Résolution de pays via IP-API
# ──────────────────────────────────────────────

def resolve_countries_batch(proxies: List[Proxy], via_tor_port: Optional[int] = None) -> List[Proxy]:
    """
    Enrichit les proxies sans info pays en interrogeant ip-api.com
    (batch de 100 max par requête).
    """
    to_resolve = [p for p in proxies if not p.country]
    if not to_resolve:
        return proxies

    req_kwargs = {}
    if via_tor_port:
        req_kwargs["proxies"] = {
            "http": f"socks5h://127.0.0.1:{via_tor_port}",
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
            TextColumn("[dim]{task.fields[resolved]} résolus[/dim]"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[cyan]🌍 Géolocalisation via ip-api.com...[/cyan]",
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
                        **req_kwargs
                    )
                    for entry in r.json():
                        query = entry.get("query", "")
                        cc = entry.get("countryCode", "")
                        cn = entry.get("country", "")
                        if query and cc:
                            ip_map[query] = (cc.upper(), cn)
                except Exception:
                    pass

                resolved_so_far = len(ip_map)
                progress.update(
                    task,
                    advance=1,
                    resolved=resolved_so_far,
                    description=(
                        f"[cyan]🌍 Géolocalisation "
                        f"[bold]{batch_idx + 1}/{total_batches}[/bold] batches...[/cyan]"
                    ),
                )

                if batch_idx < total_batches - 1:
                    time.sleep(0.5)  # rate-limit ip-api (45 req/min)

    except Exception:
        pass

    for p in proxies:
        if p.host in ip_map:
            p.country, p.country_name = ip_map[p.host]

    return proxies


# ──────────────────────────────────────────────
# Vérification des proxies
# ──────────────────────────────────────────────

def _check_proxy(proxy: Proxy, via_tor_port: Optional[int] = None) -> Proxy:
    """
    Teste si un proxy est vivant en s'y connectant via Tor (si dispo)
    puis en vérifiant une connexion TCP basique.
    """
    start = time.monotonic()
    try:
        if via_tor_port:
            # Teste le proxy en passant par Tor : Tor → proxy → ipify
            import requests as req_mod
            session = req_mod.Session()
            session.proxies = {
                "http": f"socks5h://127.0.0.1:{via_tor_port}",
                "https": f"socks5h://127.0.0.1:{via_tor_port}",
            }
            # On tente de se connecter AU proxy via Tor (TCP check)
            # puis de faire une requête HTTP depuis le proxy
            # Pour simplifier, on teste juste la connectivité TCP vers le proxy via Tor
            import socks as socks_mod
            s = socks_mod.socksocket()
            s.set_proxy(socks_mod.SOCKS5, "127.0.0.1", via_tor_port)
            s.settimeout(PROXY_CHECK_TIMEOUT)
            s.connect((proxy.host, proxy.port))
            s.close()
        else:
            # TCP connect direct
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
    """Vérifie tous les proxies en parallèle et retourne ceux qui sont vivants."""
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
                f"[cyan]Vérification de {len(proxies)} proxies...[/cyan]",
                total=len(proxies)
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_check_proxy, p, via_tor_port): p
                    for p in proxies
                }
                for future in concurrent.futures.as_completed(futures):
                    proxy = future.result()
                    results.append(proxy)
                    progress.advance(task)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(lambda p: _check_proxy(p, via_tor_port), proxies))

    alive = [p for p in results if p.alive]
    return sorted(alive, key=lambda p: p.latency_ms)


# ──────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────

SCRAPERS = [
    ("proxyscrape SOCKS5",    _fetch_proxyscrape_socks5),
    ("proxyscrape SOCKS4",    _fetch_proxyscrape_socks4),
    ("GitHub hookzof",        _fetch_github_hookzof),
    ("GitHub proxifly",       _fetch_github_proxifly),
    ("GitHub TheSpeedX S5",   _fetch_github_thespeedx),
    ("GitHub TheSpeedX S4",   _fetch_github_thespeedx_s4),
    ("GitHub monosans",       _fetch_github_monosans),
    ("proxy-list.download",   _fetch_proxylist_download),
    ("openproxylist.xyz",     _fetch_openproxylist),
]


def fetch_all_proxies(verbose: bool = False) -> List[Proxy]:
    """Récupère les proxies depuis toutes les sources, déduplique."""
    all_proxies: List[Proxy] = []
    seen = set()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Récupération des proxies publics...[/cyan]", total=len(SCRAPERS))

        for name, scraper in SCRAPERS:
            progress.update(task, description=f"[cyan]Scraping: {name}[/cyan]")
            try:
                found = scraper()
                new = 0
                for p in found:
                    key = (p.host, p.port)
                    if key not in seen:
                        seen.add(key)
                        all_proxies.append(p)
                        new += 1
                if verbose:
                    console.print(f"  [dim]{name}: {new} proxies[/dim]")
            except Exception as e:
                if verbose:
                    console.print(f"  [red]{name}: erreur – {e}[/red]")
            progress.advance(task)

    console.print(f"[green]✓ {len(all_proxies)} proxies uniques collectés depuis {len(SCRAPERS)} sources[/green]")
    return all_proxies


def get_countries_available(proxies: List[Proxy]) -> Dict[str, int]:
    """
    Retourne un dict { code_pays: nombre_proxies }
    pour les proxies ayant une info pays.
    """
    countries: Dict[str, int] = {}
    for p in proxies:
        if p.country:
            countries[p.country] = countries.get(p.country, 0) + 1
    return dict(sorted(countries.items(), key=lambda x: -x[1]))


def filter_by_country(proxies: List[Proxy], country_code: str) -> List[Proxy]:
    """Filtre les proxies par code pays ISO."""
    cc = country_code.upper().strip()
    return [p for p in proxies if p.country.upper() == cc]
