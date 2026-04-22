#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              🧅  TorProxy-Chain  ⛓️                              ║
║   Tor + public SOCKS proxy chaining with country selection       ║
╚══════════════════════════════════════════════════════════════════╝

Architecture:
  You ──► Tor (9050) ──► Public SOCKS proxy [chosen country] ──► Internet

Usage:
  python main.py                      # interactive mode
  python main.py --country FR         # direct country selection
  python main.py --list-countries     # list available countries
  python main.py --tor-port 9150      # use an existing Tor SOCKS port
  python main.py --country US --local-port 1080
"""

import sys
import time
import signal
import os
import logging
from typing import List, Optional, Set
import click
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.columns import Columns
from rich import box

from tor_manager import TorManager, TOR_SOCKS_PORT
from proxy_scraper import (
    fetch_all_proxies,
    check_proxies,
    resolve_countries_batch,
    get_countries_available,
    filter_by_country,
    Proxy,
)
from proxy_chain import ProxyChainServer, get_chained_ip, DEFAULT_LOCAL_PORT
from proxy_cache import (
    load_cached_proxies,
    save_proxies_to_cache,
    count_cached_proxies,
    cache_age_hours,
    write_pid,
    read_pid,
    clear_pid,
    CACHE_TTL,
)
from mitm_check import (
    run_mitm_checks, display_mitm_results,
    scan_all_proxies, display_scan_results,
)

console = Console()


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(stream=sys.stdout, level=level, format=fmt, datefmt="%Y-%m-%d %H:%M:%S")
    # Silence noisy third-party loggers
    for noisy in ("urllib3", "requests", "stem", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


DEFAULT_TRIGGER_HOSTS = {"accounts.censys.io"}

BANNER = """[bold cyan]
  ████████╗ ██████╗ ██████╗    ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
     ██╔══╝██╔═══██╗██╔══██╗  ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
     ██║   ██║   ██║██████╔╝  ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
     ██║   ██║   ██║██╔══██╗  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
     ██║   ╚██████╔╝██║  ██║  ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
     ╚═╝    ╚═════╝ ╚═╝  ╚═╝  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
[/bold cyan]
[dim]         ⛓️  CHAIN  |  🧅 TOR  |  🌍 SOCKS PROXY BY COUNTRY  ⛓️[/dim]"""


COUNTRY_FLAGS = {
    "AD": "🇦🇩", "AE": "🇦🇪", "AF": "🇦🇫", "AG": "🇦🇬", "AL": "🇦🇱",
    "AM": "🇦🇲", "AO": "🇦🇴", "AR": "🇦🇷", "AT": "🇦🇹", "AU": "🇦🇺",
    "AZ": "🇦🇿", "BA": "🇧🇦", "BB": "🇧🇧", "BD": "🇧🇩", "BE": "🇧🇪",
    "BF": "🇧🇫", "BG": "🇧🇬", "BH": "🇧🇭", "BI": "🇧🇮", "BJ": "🇧🇯",
    "BN": "🇧🇳", "BO": "🇧🇴", "BR": "🇧🇷", "BS": "🇧🇸", "BT": "🇧🇹",
    "BW": "🇧🇼", "BY": "🇧🇾", "BZ": "🇧🇿", "CA": "🇨🇦", "CD": "🇨🇩",
    "CF": "🇨🇫", "CG": "🇨🇬", "CH": "🇨🇭", "CI": "🇨🇮", "CL": "🇨🇱",
    "CM": "🇨🇲", "CN": "🇨🇳", "CO": "🇨🇴", "CR": "🇨🇷", "CU": "🇨🇺",
    "CV": "🇨🇻", "CY": "🇨🇾", "CZ": "🇨🇿", "DE": "🇩🇪", "DJ": "🇩🇯",
    "DK": "🇩🇰", "DM": "🇩🇲", "DO": "🇩🇴", "DZ": "🇩🇿", "EC": "🇪🇨",
    "EE": "🇪🇪", "EG": "🇪🇬", "ER": "🇪🇷", "ES": "🇪🇸", "ET": "🇪🇹",
    "FI": "🇫🇮", "FJ": "🇫🇯", "FM": "🇫🇲", "FR": "🇫🇷", "GA": "🇬🇦",
    "GB": "🇬🇧", "GD": "🇬🇩", "GE": "🇬🇪", "GH": "🇬🇭", "GM": "🇬🇲",
    "GN": "🇬🇳", "GQ": "🇬🇶", "GR": "🇬🇷", "GT": "🇬🇹", "GW": "🇬🇼",
    "GY": "🇬🇾", "HN": "🇭🇳", "HR": "🇭🇷", "HT": "🇭🇹", "HU": "🇭🇺",
    "ID": "🇮🇩", "IE": "🇮🇪", "IL": "🇮🇱", "IN": "🇮🇳", "IQ": "🇮🇶",
    "IR": "🇮🇷", "IS": "🇮🇸", "IT": "🇮🇹", "JM": "🇯🇲", "JO": "🇯🇴",
    "JP": "🇯🇵", "KE": "🇰🇪", "KG": "🇰🇬", "KH": "🇰🇭", "KI": "🇰🇮",
    "KM": "🇰🇲", "KN": "🇰🇳", "KP": "🇰🇵", "KR": "🇰🇷", "KW": "🇰🇼",
    "KZ": "🇰🇿", "LA": "🇱🇦", "LB": "🇱🇧", "LC": "🇱🇨", "LI": "🇱🇮",
    "LK": "🇱🇰", "LR": "🇱🇷", "LS": "🇱🇸", "LT": "🇱🇹", "LU": "🇱🇺",
    "LV": "🇱🇻", "LY": "🇱🇾", "MA": "🇲🇦", "MC": "🇲🇨", "MD": "🇲🇩",
    "ME": "🇲🇪", "MG": "🇲🇬", "MH": "🇲🇭", "MK": "🇲🇰", "ML": "🇲🇱",
    "MM": "🇲🇲", "MN": "🇲🇳", "MR": "🇲🇷", "MT": "🇲🇹", "MU": "🇲🇺",
    "MV": "🇲🇻", "MW": "🇲🇼", "MX": "🇲🇽", "MY": "🇲🇾", "MZ": "🇲🇿",
    "NA": "🇳🇦", "NE": "🇳🇪", "NG": "🇳🇬", "NI": "🇳🇮", "NL": "🇳🇱",
    "NO": "🇳🇴", "NP": "🇳🇵", "NR": "🇳🇷", "NZ": "🇳🇿", "OM": "🇴🇲",
    "PA": "🇵🇦", "PE": "🇵🇪", "PG": "🇵🇬", "PH": "🇵🇭", "PK": "🇵🇰",
    "PL": "🇵🇱", "PT": "🇵🇹", "PW": "🇵🇼", "PY": "🇵🇾", "QA": "🇶🇦",
    "RO": "🇷🇴", "RS": "🇷🇸", "RU": "🇷🇺", "RW": "🇷🇼", "SA": "🇸🇦",
    "SB": "🇸🇧", "SC": "🇸🇨", "SD": "🇸🇩", "SE": "🇸🇪", "SG": "🇸🇬",
    "SI": "🇸🇮", "SK": "🇸🇰", "SL": "🇸🇱", "SM": "🇸🇲", "SN": "🇸🇳",
    "SO": "🇸🇴", "SR": "🇸🇷", "SS": "🇸🇸", "ST": "🇸🇹", "SV": "🇸🇻",
    "SY": "🇸🇾", "SZ": "🇸🇿", "TD": "🇹🇩", "TG": "🇹🇬", "TH": "🇹🇭",
    "TJ": "🇹🇯", "TL": "🇹🇱", "TM": "🇹🇲", "TN": "🇹🇳", "TO": "🇹🇴",
    "TR": "🇹🇷", "TT": "🇹🇹", "TV": "🇹🇻", "TZ": "🇹🇿", "UA": "🇺🇦",
    "UG": "🇺🇬", "US": "🇺🇸", "UY": "🇺🇾", "UZ": "🇺🇿", "VA": "🇻🇦",
    "VC": "🇻🇨", "VE": "🇻🇪", "VN": "🇻🇳", "VU": "🇻🇺", "WS": "🇼🇸",
    "YE": "🇾🇪", "ZA": "🇿🇦", "ZM": "🇿🇲", "ZW": "🇿🇼", "HK": "🇭🇰",
    "TW": "🇹🇼",
}


def flag(cc: str) -> str:
    return COUNTRY_FLAGS.get(cc.upper(), "🏳️")


def display_countries(countries: dict, proxies: list):
    """Display a table of available countries with proxy counts."""
    name_map = {}
    for p in proxies:
        if p.country and p.country_name:
            name_map[p.country] = p.country_name

    table = Table(
        title="🌍 Available countries",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        title_style="bold white",
    )
    table.add_column("Flag",    justify="center", no_wrap=True)
    table.add_column("Code",    justify="center", style="bold yellow", no_wrap=True)
    table.add_column("Country", style="white")
    table.add_column("Proxies", justify="right", style="green")

    for cc, count in countries.items():
        table.add_row(flag(cc), cc, name_map.get(cc, cc), str(count))

    console.print()
    console.print(table)
    console.print()


def select_country_interactive(countries: dict, proxies: list) -> str:
    """Interactive country selection prompt."""
    display_countries(countries, proxies)
    available_codes = set(countries.keys())

    while True:
        try:
            console.print(
                "[bold cyan]Enter country code[/bold cyan] "
                "(e.g. [yellow]FR[/yellow], [yellow]US[/yellow], [yellow]DE[/yellow]): ",
                end="",
            )
            choice = input().strip().upper()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

        if not choice:
            console.print("[yellow]Empty input — please enter a valid country code (e.g. FR, US, DE).[/yellow]")
            continue

        if choice in available_codes:
            return choice

        console.print(f"[red]Country '{choice}' not available. Choose from the list above.[/red]")


def display_chain_status(proxy: Proxy, local_port: int, ip_info: dict):
    """Display a summary panel for the active proxy chain."""
    chain_visual = (
        f"[bold white]You[/bold white] "
        f"[dim]──►[/dim] "
        f"[bold cyan]🧅 Tor[/bold cyan] "
        f"[dim]──►[/dim] "
        f"[bold yellow]{flag(proxy.country)} {proxy.address}[/bold yellow] "
        f"[dim]({proxy.country or '??'})[/dim] "
        f"[dim]──►[/dim] "
        f"[bold green]🌐 Internet[/bold green]"
    )

    latency_line = (
        f"  [bold]Proxy latency     :[/bold]  [magenta]{proxy.latency_ms:.0f} ms[/magenta]"
        if proxy.latency_ms > 0 else ""
    )

    content = "\n".join(filter(None, [
        f"  {chain_visual}",
        "",
        f"  [bold]Public IP         :[/bold]  [bold green]{ip_info.get('ip', '?')}[/bold green]",
        f"  [bold]Detected country  :[/bold]  {ip_info.get('country', '?')}",
        f"  [bold]City              :[/bold]  {ip_info.get('city', '?')}",
        f"  [bold]ISP               :[/bold]  {ip_info.get('org', '?')}",
        "",
        f"  [bold]Local SOCKS5      :[/bold]  [cyan]socks5://127.0.0.1:{local_port}[/cyan]",
        f"  [bold]Exit proxy        :[/bold]  [yellow]{proxy.proto}://{proxy.address}[/yellow]",
        latency_line,
    ]))

    console.print(Panel(
        content,
        title="[bold green]⛓️  Active chain[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))


def _run_scan_mitm(tor_port_arg: Optional[int], limit: int):
    """Standalone MITM scan: connect Tor, load cache, scan, display results."""
    console.print(BANNER)
    console.print()

    console.print(Panel(
        f"[bold cyan]MITM bulk scan — up to {limit} proxies from cache[/bold cyan]",
        border_style="cyan", padding=(0, 1),
    ))

    # Connect Tor
    tor = TorManager(external_port=tor_port_arg)
    if not tor.start():
        console.print("[red]Could not connect to Tor.[/red]")
        return
    console.print(f"[green]Tor ready at socks5://127.0.0.1:{tor.socks_port}[/green]\n")

    # Load proxies from cache
    proxies = load_cached_proxies()
    if not proxies:
        console.print("[yellow]Cache is empty. Run without --scan-mitm first to populate it.[/yellow]")
        tor.stop()
        return

    proxies = proxies[:limit]
    console.print(f"[cyan]{len(proxies)} proxies loaded from cache (limit: {limit})[/cyan]\n")

    results = scan_all_proxies(proxies, tor_port=tor.socks_port)
    display_scan_results(results)

    tor.stop()


_log = logging.getLogger(__name__)


def _run_mitm_and_react(server, local_port: int, alive_proxies: list, max_retries: int = 3):
    """
    Run MITM checks after chain mount. On FAIL, auto-rotate and retry up to
    max_retries times. Logs every individual check result + global verdict.
    Stores result in server for the web admin UI.
    """
    from mitm_check import run_mitm_checks, display_mitm_results, Status

    for attempt in range(1, max_retries + 1):
        console.print()
        label = "automatic at chain mount" if attempt == 1 else f"attempt {attempt}/{max_retries}"
        console.print(f"[cyan]Running MITM detection ({label})...[/cyan]")

        results = run_mitm_checks(local_port)
        display_mitm_results(results)

        # Log every individual check
        for r in results:
            lvl = _log.warning if r.status in (Status.FAIL, Status.WARN) else _log.info
            lvl(f"MITM [{r.name}] {r.status.value.upper()} — {r.detail}")

        has_fail = any(r.status == Status.FAIL for r in results)
        has_warn = any(r.status == Status.WARN for r in results)
        verdict = "fail" if has_fail else "warn" if has_warn else "pass"

        # Push state to the server for the web UI
        checks_payload = [
            {"name": r.name, "status": r.status.value, "detail": r.detail}
            for r in results
        ]
        server.set_mitm_result(verdict, checks_payload)

        proxy_label = f"{server.exit_proxy.address} ({server.exit_proxy.country or '??'})"

        if has_fail:
            _log.warning(f"MITM DETECTED on {proxy_label} — rotating to next proxy")
            console.print("[red bold]⚠ MITM DETECTED — rotating exit proxy automatically[/red bold]")
            if len(alive_proxies) > 1:
                server.rotate()
                time.sleep(3)
            else:
                _log.warning("MITM detected but pool has only one proxy — cannot rotate")
                console.print("[yellow]No alternative proxy in pool — cannot rotate.[/yellow]")
                break
        elif has_warn:
            _log.warning(f"MITM warning on {proxy_label} — proceeding with caution")
            break
        else:
            _log.info(f"MITM check PASSED on {proxy_label} — proxy is clean")
            break
    else:
        _log.warning(f"MITM check FAILED after {max_retries} attempts — chain may be compromised")
        console.print(
            f"[red bold]⚠ MITM still detected after {max_retries} proxy rotations. "
            "Use with caution.[/red bold]"
        )


def run(
    country_arg: str,
    local_port: int,
    verbose: bool,
    list_countries_only: bool,
    skip_verify: bool,
    tor_port_arg: int = None,
    skip_mitm_check: bool = False,
    watchdog_interval: int = 30,
    fail_threshold: int = 3,
    rate_limit_hosts: Optional[str] = None,
    headless: bool = False,
    status_port: Optional[int] = None,
):
    _setup_logging(verbose)
    console.print(BANNER)
    console.print()

    # ── Step 1: Tor ───────────────────────────────────────────────────────────
    if tor_port_arg:
        step1_label = f"Step 1/4: Attaching to existing Tor on port {tor_port_arg}"
    else:
        step1_label = "Step 1/4: Connecting to the Tor network"

    console.print(Panel(
        f"[bold cyan]{step1_label}[/bold cyan]",
        border_style="cyan", padding=(0, 1),
    ))

    tor = TorManager(external_port=tor_port_arg)
    if not tor.start():
        console.print("[red]Could not connect to Tor. Check your installation or --tor-port value.[/red]")
        sys.exit(1)

    active_tor_port = tor.socks_port
    console.print(f"[green]Tor ready at socks5://127.0.0.1:{active_tor_port}[/green]")
    console.print()

    # ── Step 2: Fetch proxies ────────────────────────────────────────────────
    console.print(Panel(
        "[bold cyan]Step 2/4: Fetching public SOCKS proxies[/bold cyan]",
        border_style="cyan", padding=(0, 1),
    ))
    raw_proxies = fetch_all_proxies(verbose=verbose)

    if not raw_proxies:
        console.print("[red]No proxies fetched. Check your internet connection.[/red]")
        tor.stop()
        sys.exit(1)

    # ── Step 3: Geolocation (with SQLite cache) ───────────────────────────────
    console.print()
    console.print("[cyan]Resolving proxy countries...[/cyan]")

    cached = load_cached_proxies()
    cache_map = {(p.host, p.port): p for p in cached}
    age = cache_age_hours()

    if cached:
        age_str = f"{age:.1f}h" if age is not None else "?"
        console.print(f"[dim]  Cache: {len(cached)} geolocated proxies (age: {age_str})[/dim]")

    for p in raw_proxies:
        cached_p = cache_map.get((p.host, p.port))
        if cached_p and cached_p.country:
            p.country = cached_p.country
            p.country_name = cached_p.country_name

    need_resolve = [p for p in raw_proxies if not p.country]
    if need_resolve:
        console.print(f"[dim]  Geolocating {len(need_resolve)} proxies via ip-api.com...[/dim]")
        proxies_with_geo = resolve_countries_batch(raw_proxies, via_tor_port=active_tor_port)
        newly_resolved = [
            p for p in proxies_with_geo
            if p.country and (p.host, p.port) not in cache_map
        ]
        if newly_resolved:
            save_proxies_to_cache(newly_resolved)
            console.print(f"[dim]  Cached {len(newly_resolved)} new geolocation entries.[/dim]")
    else:
        proxies_with_geo = raw_proxies
        console.print("[dim]  All proxies already geolocated from cache.[/dim]")

    countries = get_countries_available(proxies_with_geo)
    console.print(
        f"[green]{len(countries)} countries available "
        f"({sum(countries.values())} geolocated proxies)[/green]"
    )
    console.print()

    if list_countries_only:
        display_countries(countries, proxies_with_geo)
        tor.stop()
        return

    # ── Country selection ─────────────────────────────────────────────────────
    console.print(Panel(
        "[bold cyan]Step 3/4: Selecting exit country[/bold cyan]",
        border_style="cyan", padding=(0, 1),
    ))

    if not countries:
        console.print("[yellow]No geolocated proxies — proceeding without country filter.[/yellow]")
        proxies_with_geo = raw_proxies
        selected_country = None
    elif country_arg:
        cc = country_arg.upper().strip()
        if cc not in countries:
            console.print(f"[yellow]Country '{cc}' not in current list.[/yellow]")
            if headless:
                console.print("[yellow]Headless mode: proceeding without country filter.[/yellow]")
                cc = None
            else:
                cc = select_country_interactive(countries, proxies_with_geo)
        else:
            console.print(
                f"[green]Country: {flag(cc)} [bold]{cc}[/bold] "
                f"({countries[cc]} proxies available)[/green]"
            )
        selected_country = cc
    elif headless:
        console.print("[yellow]No country specified — using all available proxies.[/yellow]")
        selected_country = None
    else:
        selected_country = select_country_interactive(countries, proxies_with_geo)
        console.print(f"[green]Country: {flag(selected_country)} [bold]{selected_country}[/bold][/green]")

    console.print()

    # ── Step 4: Verify and activate ──────────────────────────────────────────
    console.print(Panel(
        "[bold cyan]Step 4/4: Verifying proxies and activating chain[/bold cyan]",
        border_style="cyan", padding=(0, 1),
    ))

    if selected_country:
        candidates = filter_by_country(proxies_with_geo, selected_country)
        console.print(f"[cyan]{len(candidates)} proxies found for {flag(selected_country)} {selected_country}[/cyan]")
    else:
        candidates = proxies_with_geo

    if not candidates:
        console.print("[red]No proxies available for this country.[/red]")
        tor.stop()
        sys.exit(1)

    if not skip_verify:
        console.print("[cyan]Checking proxies through Tor...[/cyan]")
        alive_proxies = check_proxies(
            candidates[:200],
            via_tor_port=active_tor_port,
            max_workers=20,
        )
    else:
        alive_proxies = candidates

    if not alive_proxies:
        console.print("[red]No live proxies found for this country.[/red]")
        console.print("[yellow]Try another country or run without --skip-verify.[/yellow]")
        tor.stop()
        sys.exit(1)

    console.print(f"[green]{len(alive_proxies)} live proxies found.[/green]")

    active_proxy = alive_proxies[0]
    console.print(
        f"[green]Selected proxy: [bold]{active_proxy.address}[/bold] "
        f"(latency: {active_proxy.latency_ms:.0f} ms)[/green]"
    )
    console.print()

    # ── Start chain server ────────────────────────────────────────────────────
    extra_hosts: Set[str] = set()
    if rate_limit_hosts:
        extra_hosts = {h.strip() for h in rate_limit_hosts.split(",") if h.strip()}

    server = ProxyChainServer(
        exit_proxy=active_proxy,
        tor_port=active_tor_port,
        local_port=local_port,
        proxy_pool=alive_proxies,
        watchdog_interval=watchdog_interval,
        fail_threshold=fail_threshold,
        trigger_hosts=DEFAULT_TRIGGER_HOSTS | extra_hosts,
        status_port=status_port,
    )
    if not server.start():
        tor.stop()
        sys.exit(1)

    write_pid(os.getpid(), local_port, selected_country or "ALL")

    console.print("[cyan]Verifying chain (this may take a few seconds)...[/cyan]")
    ip_info = None
    for attempt in range(1, 4):   # up to 3 attempts with increasing delay
        time.sleep(attempt * 3)
        ip_info = get_chained_ip(local_port=local_port)
        if ip_info:
            break
        console.print(f"[dim]  Attempt {attempt}/3 — chain not ready yet, retrying...[/dim]")
        if attempt < 3 and len(alive_proxies) > 1:
            server.rotate()   # try next proxy if current one is unresponsive

    if ip_info:
        display_chain_status(server.exit_proxy, local_port, ip_info)
    else:
        console.print("[yellow]Could not verify chain IP after 3 attempts.[/yellow]")
        console.print(f"[cyan]SOCKS5 server is active at socks5://127.0.0.1:{local_port}[/cyan]")
        _log.warning("Chain IP verification failed after 3 attempts — proxy may be unresponsive")

    # ── MITM check (automatic at chain mount) ────────────────────────────────
    if not skip_mitm_check:
        _run_mitm_and_react(server, local_port, alive_proxies)

    # ── Headless mode — block until signal ───────────────────────────────────
    if headless:
        console.print("[green]Headless mode active. Proxy running. Send SIGTERM to stop.[/green]")
        def _headless_signal(sig, frame):
            console.print("\n[yellow]Signal received, shutting down...[/yellow]")
            server.stop()
            tor.stop()
            clear_pid()
            sys.exit(0)
        signal.signal(signal.SIGINT, _headless_signal)
        signal.signal(signal.SIGTERM, _headless_signal)
        try:
            while True:
                time.sleep(60)
        except (KeyboardInterrupt, SystemExit):
            pass
        server.stop()
        tor.stop()
        clear_pid()
        return

    # ── Interactive loop ──────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        "[bold]Controls:[/bold]\n\n"
        "  [cyan][r][/cyan] → Rotate exit proxy\n"
        "  [cyan][n][/cyan] → New Tor circuit\n"
        "  [cyan][i][/cyan] → Check current IP\n"
        "  [cyan][m][/cyan] → Re-run MITM detection\n"
        "  [cyan][d][/cyan] → Detach (exit UI, keep server running)\n"
        "  [cyan][q][/cyan] → Quit and stop server",
        title="⌨️  Controls",
        border_style="blue",
        padding=(0, 2),
    ))

    def signal_handler(sig, frame):
        console.print("\n[yellow]Signal received, shutting down...[/yellow]")
        server.stop()
        tor.stop()
        clear_pid()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    detached = False
    while True:
        try:
            cmd = Prompt.ask(
                "\n[bold cyan]>[/bold cyan]",
                choices=["r", "n", "i", "m", "d", "q"],
                show_choices=True,
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd == "q":
            break

        elif cmd == "d":
            detached = True
            console.print(Panel(
                f"[bold green]Server running in the background.[/bold green]\n\n"
                f"  SOCKS5 proxy active: [cyan]socks5://127.0.0.1:{local_port}[/cyan]\n"
                f"  PID: [yellow]{os.getpid()}[/yellow]\n\n"
                f"  To stop later:\n"
                f"  [dim]python main.py --kill[/dim]\n"
                f"  [dim]or:  kill {os.getpid()}[/dim]",
                title="⛓️  Detached",
                border_style="green",
                padding=(1, 2),
            ))
            break

        elif cmd == "r":
            new_proxy = server.rotate()
            console.print(
                f"[cyan]Rotated → {flag(new_proxy.country)} {new_proxy.address} "
                f"({new_proxy.latency_ms:.0f} ms)[/cyan]"
            )

        elif cmd == "n":
            tor.new_circuit()

        elif cmd == "i":
            console.print("[cyan]Checking current IP...[/cyan]")
            ip_info = get_chained_ip(local_port=local_port)
            if ip_info:
                console.print(
                    f"[green]  IP: [bold]{ip_info['ip']}[/bold] | "
                    f"Country: {ip_info['country']} | "
                    f"City: {ip_info['city']} | "
                    f"ISP: {ip_info['org']}[/green]"
                )
            else:
                console.print("[yellow]  Could not retrieve IP.[/yellow]")

        elif cmd == "m":
            console.print("[cyan]Running MITM detection...[/cyan]")
            results = run_mitm_checks(local_port)
            display_mitm_results(results)

    if detached:
        console.print("[dim]Detached session. Proxy remains active. (Ctrl+C to force stop)[/dim]")
        try:
            while True:
                time.sleep(60)
        except (KeyboardInterrupt, SystemExit):
            pass
        server.stop()
        tor.stop()
        clear_pid()
        return

    console.print("\n[yellow]Stopping server...[/yellow]")
    server.stop()
    tor.stop()
    clear_pid()
    console.print("[green]Clean shutdown. Goodbye![/green]")


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.command(help=__doc__, context_settings={"auto_envvar_prefix": "TORPROXY"})
@click.option("--country",        "-c", default=None,               metavar="CODE",  help="ISO 2-letter exit country code (e.g. FR, US, DE). Interactive if omitted.")
@click.option("--list-countries", "-l", is_flag=True, default=False,                 help="List available countries and exit.")
@click.option("--local-port",     "-p", default=DEFAULT_LOCAL_PORT,  show_default=True, type=int, help="Local SOCKS5 server port.")
@click.option("--tor-port",             default=None,                type=int,        help="Use an already-running Tor SOCKS port (skip starting Tor).")
@click.option("--verbose",        "-v", is_flag=True, default=False,                 help="Verbose output.")
@click.option("--skip-verify",          is_flag=True, default=False,                 help="Skip proxy liveness check (faster startup).")
@click.option("--skip-mitm-check",      is_flag=True, default=False,                 help="Skip automatic MITM detection after chain setup.")
@click.option("--scan-mitm",            is_flag=True, default=False,                 help="Scan all proxies in the cache for MITM and show a report.")
@click.option("--scan-limit",           default=200,  show_default=True, type=int,   help="Max number of proxies to test during --scan-mitm.")
@click.option("--kill",             "-k", is_flag=True, default=False,                   help="Stop a detached TorProxy-Chain server.")
@click.option("--clear-cache",            is_flag=True, default=False,                   help="Clear the proxy geolocation SQLite cache.")
@click.option("--watchdog-interval",      default=30,   show_default=True, type=int,     help="Watchdog probe interval in seconds.")
@click.option("--fail-threshold",         default=3,    show_default=True, type=int,     help="Consecutive failures before auto-rotation.")
@click.option("--rate-limit-hosts",       default="",                                    help="Extra redirect hostnames that trigger auto-rotation (comma-separated).")
@click.option("--headless",               is_flag=True, default=False,                   help="Headless mode: no interactive prompts, block until SIGTERM.")
@click.option("--status-port",            default=None, type=int,                        help="Enable HTTP status API on this port (e.g. 10801).")
def main(country, list_countries, local_port, tor_port, verbose, skip_verify, skip_mitm_check, scan_mitm, scan_limit, kill, clear_cache, watchdog_interval, fail_threshold, rate_limit_hosts, headless, status_port):
    if kill:
        info = read_pid()
        if not info:
            console.print("[yellow]No active TorProxy-Chain server found.[/yellow]")
            return
        pid = info["pid"]
        console.print(
            f"[cyan]Stopping detached server "
            f"(PID {pid}, port {info['local_port']}, country {info['country']})...[/cyan]"
        )
        try:
            os.kill(pid, signal.SIGTERM)
            console.print(f"[green]SIGTERM sent to PID {pid}.[/green]")
            clear_pid()
        except ProcessLookupError:
            console.print(f"[yellow]Process {pid} no longer exists. Cleaning up PID file.[/yellow]")
            clear_pid()
        except PermissionError:
            console.print(f"[red]Permission denied to terminate PID {pid}.[/red]")
        return

    if clear_cache:
        from proxy_cache import clear_cache as _clear_cache
        _clear_cache()
        console.print("[green]SQLite cache cleared.[/green]")
        return

    if scan_mitm:
        _run_scan_mitm(tor_port_arg=tor_port, limit=scan_limit)
        return

    run(
        country_arg=country,
        local_port=local_port,
        verbose=verbose,
        list_countries_only=list_countries,
        skip_verify=skip_verify,
        tor_port_arg=tor_port,
        skip_mitm_check=skip_mitm_check,
        watchdog_interval=watchdog_interval,
        fail_threshold=fail_threshold,
        rate_limit_hosts=rate_limit_hosts or None,
        headless=headless,
        status_port=status_port,
    )


if __name__ == "__main__":
    main()
