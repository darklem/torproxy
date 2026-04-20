#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              🧅  TorProxy-Chain  ⛓️                              ║
║   Tor + Chainage de proxies SOCKS publics par pays               ║
╚══════════════════════════════════════════════════════════════════╝

Architecture :
  Vous ──► Tor (9050) ──► Proxy SOCKS public [pays choisi] ──► Internet

Usage :
  python main.py                      # Mode interactif
  python main.py --country FR         # Pays direct
  python main.py --list-countries     # Lister les pays disponibles
  python main.py --country US --local-port 1080
"""

import sys
import time
import signal
import os
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

console = Console()

# ──────────────────────────────────────────────
# Bannière
# ──────────────────────────────────────────────

BANNER = """[bold cyan]
  ████████╗ ██████╗ ██████╗    ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
     ██╔══╝██╔═══██╗██╔══██╗  ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
     ██║   ██║   ██║██████╔╝  ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ 
     ██║   ██║   ██║██╔══██╗  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  
     ██║   ╚██████╔╝██║  ██║  ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   
     ╚═╝    ╚═════╝ ╚═╝  ╚═╝  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝  
[/bold cyan]
[dim]         ⛓️  CHAIN  |  🧅 TOR  |  🌍 SOCKS PROXY PAR PAYS  ⛓️[/dim]"""


# Drapeaux emoji par code pays (quelques-uns)
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


# ──────────────────────────────────────────────
# Affichage des pays disponibles
# ──────────────────────────────────────────────

def display_countries(countries: dict, proxies: list):
    """Affiche un tableau des pays disponibles avec nombre de proxies."""
    # Construire un mapping code → nom
    name_map = {}
    for p in proxies:
        if p.country and p.country_name:
            name_map[p.country] = p.country_name

    table = Table(
        title="🌍 Pays disponibles",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        title_style="bold white",
    )
    table.add_column("Drapeau", justify="center", no_wrap=True)
    table.add_column("Code", justify="center", style="bold yellow", no_wrap=True)
    table.add_column("Pays", style="white")
    table.add_column("Proxies dispo", justify="right", style="green")

    for cc, count in countries.items():
        name = name_map.get(cc, cc)
        table.add_row(
            flag(cc),
            cc,
            name,
            str(count),
        )

    console.print()
    console.print(table)
    console.print()


# ──────────────────────────────────────────────
# Sélection interactive du pays
# ──────────────────────────────────────────────

def select_country_interactive(countries: dict, proxies: list) -> str:
    """Interface interactive de sélection de pays."""
    display_countries(countries, proxies)

    available_codes = set(countries.keys())
    while True:
        try:
            console.print("[bold cyan]Entrez le code pays[/bold cyan] (ex: [yellow]FR[/yellow], [yellow]US[/yellow], [yellow]DE[/yellow]): ", end="")
            choice = input().strip().upper()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

        if not choice:
            console.print("[yellow]⚠ Entrée vide. Veuillez saisir un code pays valide (ex: FR, US, DE).[/yellow]")
            continue

        if choice in available_codes:
            return choice
        else:
            console.print(f"[red]❌ Code pays '{choice}' non disponible. Choisissez parmi la liste ci-dessus.[/red]")


# ──────────────────────────────────────────────
# Affichage du statut de la chaîne
# ──────────────────────────────────────────────

def display_chain_status(proxy: Proxy, local_port: int, ip_info: dict):
    """Affiche un panneau récapitulatif de la chaîne active."""
    chain_visual = (
        f"[bold white]Vous[/bold white] "
        f"[dim]──►[/dim] "
        f"[bold cyan]🧅 Tor[/bold cyan] "
        f"[dim]──►[/dim] "
        f"[bold yellow]{flag(proxy.country)} {proxy.address}[/bold yellow] "
        f"[dim]({proxy.country or '??'})[/dim] "
        f"[dim]──►[/dim] "
        f"[bold green]🌐 Internet[/bold green]"
    )

    ip_display = ip_info.get("ip", "?")
    country_display = ip_info.get("country", "?")
    city_display = ip_info.get("city", "?")
    org_display = ip_info.get("org", "?")

    content = "\n".join([
        f"  {chain_visual}",
        "",
        f"  [bold]IP publique finale :[/bold]  [bold green]{ip_display}[/bold green]",
        f"  [bold]Pays détecté      :[/bold]  {country_display}",
        f"  [bold]Ville             :[/bold]  {city_display}",
        f"  [bold]Opérateur         :[/bold]  {org_display}",
        "",
        f"  [bold]Proxy local SOCKS5:[/bold]  [cyan]socks5://127.0.0.1:{local_port}[/cyan]",
        f"  [bold]Proxy exit        :[/bold]  [yellow]{proxy.proto}://{proxy.address}[/yellow]",
        f"  [bold]Latence proxy     :[/bold]  [magenta]{proxy.latency_ms:.0f} ms[/magenta]" if proxy.latency_ms > 0 else "",
    ])

    console.print(Panel(
        content,
        title="[bold green]⛓️  Chaîne active[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))


# ──────────────────────────────────────────────
# Menu interactif principal (boucle active)
# ──────────────────────────────────────────────

def interactive_menu(server: ProxyChainServer, proxies_by_country: list, country: str, local_port: int):
    """Menu interactif pendant que le serveur tourne."""
    console.print()
    console.print(Panel(
        "[bold]Commandes disponibles :[/bold]\n\n"
        "  [cyan]r[/cyan]  → Changer de proxy (rotation)\n"
        "  [cyan]n[/cyan]  → Nouveau circuit Tor\n"
        "  [cyan]i[/cyan]  → Vérifier l'IP actuelle\n"
        "  [cyan]q[/cyan]  → Quitter",
        title="⌨️  Contrôles",
        border_style="blue",
        padding=(0, 2),
    ))

    return  # Le menu est géré dans la boucle principale de run()


# ──────────────────────────────────────────────
# Cœur de l'application
# ──────────────────────────────────────────────

def run(
    country_arg: str,
    local_port: int,
    verbose: bool,
    list_countries_only: bool,
    skip_verify: bool,
):
    """Logique principale de l'outil."""

    # Bannière
    console.print(BANNER)
    console.print()

    # ── 1. Démarrage Tor ──
    console.print(Panel(
        "[bold cyan]Étape 1/4 :[/bold cyan] Connexion au réseau Tor",
        border_style="cyan", padding=(0, 1)
    ))
    tor = TorManager()
    if not tor.start():
        console.print("[red]Impossible de démarrer Tor. Vérifiez l'installation.[/red]")
        sys.exit(1)
    console.print(f"[green]✓ Tor opérationnel sur socks5://127.0.0.1:{TOR_SOCKS_PORT}[/green]")
    console.print()

    # ── 2. Récupération des proxies ──
    console.print(Panel(
        "[bold cyan]Étape 2/4 :[/bold cyan] Récupération des proxies SOCKS publics",
        border_style="cyan", padding=(0, 1)
    ))
    raw_proxies = fetch_all_proxies(verbose=verbose)

    if not raw_proxies:
        console.print("[red]❌ Aucun proxy récupéré. Vérifiez votre connexion Internet.[/red]")
        tor.stop()
        sys.exit(1)

    # ── 3. Résolution des pays (avec cache SQLite) ──
    console.print()
    console.print("[cyan]🌍 Résolution géographique des proxies...[/cyan]")

    # Charger le cache existant
    cached = load_cached_proxies()
    cache_map = {(p.host, p.port): p for p in cached}
    age = cache_age_hours()

    if cached:
        age_str = f"{age:.1f}h" if age is not None else "?"
        console.print(f"[dim]  📦 Cache : {len(cached)} proxies géolocalisés (âge : {age_str})[/dim]")

    # Appliquer le cache aux proxies scrapés
    for p in raw_proxies:
        cached_p = cache_map.get((p.host, p.port))
        if cached_p and cached_p.country:
            p.country = cached_p.country
            p.country_name = cached_p.country_name

    # Ne résoudre que les proxies sans pays
    need_resolve = [p for p in raw_proxies if not p.country]
    if need_resolve:
        console.print(f"[dim]  🔍 {len(need_resolve)} proxies à géolocaliser via ip-api.com...[/dim]")
        proxies_with_geo = resolve_countries_batch(raw_proxies, via_tor_port=TOR_SOCKS_PORT)
        # Sauvegarder les nouvellement résolus dans le cache
        newly_resolved = [p for p in proxies_with_geo if p.country and (p.host, p.port) not in cache_map]
        if newly_resolved:
            save_proxies_to_cache(newly_resolved)
            console.print(f"[dim]  💾 {len(newly_resolved)} nouveaux proxies mis en cache[/dim]")
    else:
        proxies_with_geo = raw_proxies
        console.print(f"[dim]  ✅ Tous les proxies déjà géolocalisés depuis le cache[/dim]")

    countries = get_countries_available(proxies_with_geo)
    console.print(f"[green]✓ {len(countries)} pays disponibles avec {sum(countries.values())} proxies géolocalisés[/green]")
    console.print()

    # Mode liste uniquement
    if list_countries_only:
        display_countries(countries, proxies_with_geo)
        tor.stop()
        return

    if not countries:
        console.print("[yellow]⚠ Aucun proxy géolocalisé. Utilisation sans filtre pays...[/yellow]")
        proxies_with_geo = raw_proxies
        selected_country = None
    else:
        # ── Sélection du pays ──
        console.print(Panel(
            "[bold cyan]Étape 3/4 :[/bold cyan] Sélection du pays de sortie",
            border_style="cyan", padding=(0, 1)
        ))

        if country_arg:
            cc = country_arg.upper().strip()
            if cc not in countries:
                console.print(f"[yellow]⚠ Pays '{cc}' non disponible dans la liste actuelle.[/yellow]")
                console.print("[yellow]  Pays disponibles :[/yellow]", ", ".join(sorted(countries.keys())))
                cc = select_country_interactive(countries, proxies_with_geo)
            else:
                console.print(f"[green]✓ Pays sélectionné : {flag(cc)} [bold]{cc}[/bold] ({countries[cc]} proxies disponibles)[/green]")
            selected_country = cc
        else:
            selected_country = select_country_interactive(countries, proxies_with_geo)
            console.print(f"[green]✓ Pays sélectionné : {flag(selected_country)} [bold]{selected_country}[/bold][/green]")

    console.print()

    # ── Filtrage et vérification des proxies ──
    console.print(Panel(
        "[bold cyan]Étape 4/4 :[/bold cyan] Vérification et activation de la chaîne",
        border_style="cyan", padding=(0, 1)
    ))

    if selected_country:
        candidates = filter_by_country(proxies_with_geo, selected_country)
        console.print(f"[cyan]{len(candidates)} proxies trouvés pour {flag(selected_country)} {selected_country}[/cyan]")
    else:
        candidates = proxies_with_geo

    if not candidates:
        console.print(f"[red]❌ Aucun proxy disponible pour ce pays.[/red]")
        tor.stop()
        sys.exit(1)

    # Vérifier les proxies (via Tor pour authentifier l'accessibilité réelle)
    if not skip_verify:
        console.print("[cyan]🔍 Vérification des proxies via Tor...[/cyan]")
        alive_proxies = check_proxies(
            candidates[:200],  # Limiter à 200 pour la vitesse
            via_tor_port=TOR_SOCKS_PORT,
            max_workers=20,
        )
    else:
        alive_proxies = candidates

    if not alive_proxies:
        console.print("[red]❌ Aucun proxy vivant trouvé pour ce pays.[/red]")
        console.print("[yellow]💡 Essayez un autre pays ou relancez sans --skip-verify.[/yellow]")
        tor.stop()
        sys.exit(1)

    console.print(f"[green]✓ {len(alive_proxies)} proxies vivants[/green]")

    # Choisir le meilleur proxy (latence la plus faible)
    active_proxy = alive_proxies[0]
    console.print(
        f"[green]✓ Proxy sélectionné : [bold]{active_proxy.address}[/bold] "
        f"(latence: {active_proxy.latency_ms:.0f}ms)[/green]"
    )
    console.print()

    # ── Démarrage du serveur de chainage ──
    server = ProxyChainServer(
        exit_proxy=active_proxy,
        tor_port=TOR_SOCKS_PORT,
        local_port=local_port,
    )
    if not server.start():
        tor.stop()
        sys.exit(1)

    # Enregistrer le PID pour pouvoir tuer le serveur plus tard
    write_pid(os.getpid(), local_port, selected_country or "ALL")

    # ── Vérification de l'IP finale ──
    console.print("[cyan]🌐 Vérification de l'IP publique finale...[/cyan]")
    time.sleep(2)
    ip_info = get_chained_ip(local_port=local_port)

    if ip_info:
        display_chain_status(active_proxy, local_port, ip_info)
    else:
        console.print("[yellow]⚠ Impossible de vérifier l'IP finale (proxy peut-être lent).[/yellow]")
        console.print(f"[cyan]  Le serveur SOCKS5 est actif sur socks5://127.0.0.1:{local_port}[/cyan]")

    # ── Boucle interactive ──
    proxy_index = 0

    console.print()
    console.print(Panel(
        "[bold]Commandes :[/bold]\n\n"
        "  [cyan][r][/cyan] → Rotation du proxy de sortie\n"
        "  [cyan][n][/cyan] → Nouveau circuit Tor\n"
        "  [cyan][i][/cyan] → Vérifier l'IP actuelle\n"
        "  [cyan][d][/cyan] → Détacher (quitter sans arrêter le serveur)\n"
        "  [cyan][q][/cyan] → Quitter et arrêter le serveur",
        title="⌨️  Contrôles",
        border_style="blue",
        padding=(0, 2),
    ))

    def signal_handler(sig, frame):
        console.print("\n[yellow]⚡ Signal reçu, arrêt...[/yellow]")
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
                choices=["r", "n", "i", "d", "q"],
                show_choices=True,
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd == "q":
            break

        elif cmd == "d":
            # Détacher : quitter sans arrêter le serveur
            detached = True
            console.print(Panel(
                f"[bold green]Le serveur tourne en arrière-plan.[/bold green]\n\n"
                f"  🔌 Proxy SOCKS5 actif : [cyan]socks5://127.0.0.1:{local_port}[/cyan]\n"
                f"  🆔 PID : [yellow]{os.getpid()}[/yellow]\n\n"
                f"  Pour arrêter plus tard :\n"
                f"  [dim]python main.py --kill[/dim]\n"
                f"  [dim]ou :[/dim]  [dim]kill {os.getpid()}[/dim]",
                title="⛓️  Détaché",
                border_style="green",
                padding=(1, 2),
            ))
            break

        elif cmd == "r":
            # Rotation : passer au proxy suivant
            proxy_index = (proxy_index + 1) % len(alive_proxies)
            new_proxy = alive_proxies[proxy_index]
            server.swap_exit_proxy(new_proxy)
            console.print(f"[cyan]🔄 Nouveau proxy : {flag(new_proxy.country)} {new_proxy.address} ({new_proxy.latency_ms:.0f}ms)[/cyan]")

        elif cmd == "n":
            # Nouveau circuit Tor
            tor.new_circuit()

        elif cmd == "i":
            # Vérifier l'IP actuelle
            console.print("[cyan]🌐 Vérification de l'IP...[/cyan]")
            ip_info = get_chained_ip(local_port=local_port)
            if ip_info:
                console.print(
                    f"[green]  IP : [bold]{ip_info['ip']}[/bold] | "
                    f"Pays : {ip_info['country']} | "
                    f"Ville : {ip_info['city']} | "
                    f"Org : {ip_info['org']}[/green]"
                )
            else:
                console.print("[yellow]  Impossible de récupérer l'IP.[/yellow]")

    if detached:
        # Le serveur continue de tourner, on garde le processus en vie silencieusement
        console.print("[dim]Session détachée. Le proxy reste actif. (Ctrl+C pour forcer l'arrêt)[/dim]")
        try:
            while True:
                time.sleep(60)
        except (KeyboardInterrupt, SystemExit):
            pass
        server.stop()
        tor.stop()
        clear_pid()
        return

    # ── Nettoyage ──
    console.print("\n[yellow]⏹ Arrêt du serveur...[/yellow]")
    server.stop()
    tor.stop()
    clear_pid()
    console.print("[green]✓ Arrêt propre. À bientôt ![/green]")


# ──────────────────────────────────────────────
# Interface Click (CLI)
# ──────────────────────────────────────────────

@click.command(help=__doc__)
@click.option(
    "--country", "-c",
    default=None,
    metavar="CODE",
    help="Code pays ISO 2 lettres (ex: FR, US, DE). Mode interactif si non spécifié.",
)
@click.option(
    "--list-countries", "-l",
    is_flag=True,
    default=False,
    help="Afficher les pays disponibles et quitter.",
)
@click.option(
    "--local-port", "-p",
    default=DEFAULT_LOCAL_PORT,
    show_default=True,
    type=int,
    help="Port du serveur SOCKS5 local.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Affichage détaillé.",
)
@click.option(
    "--skip-verify",
    is_flag=True,
    default=False,
    help="Ne pas vérifier les proxies avant utilisation (plus rapide).",
)
@click.option(
    "--kill", "-k",
    is_flag=True,
    default=False,
    help="Arrêter un serveur TorProxy-Chain détaché en arrière-plan.",
)
@click.option(
    "--clear-cache",
    is_flag=True,
    default=False,
    help="Vider le cache SQLite de géolocalisation des proxies.",
)
def main(country, list_countries, local_port, verbose, skip_verify, kill, clear_cache):
    # ── Commande : tuer le serveur détaché ──
    if kill:
        info = read_pid()
        if not info:
            console.print("[yellow]⚠ Aucun serveur TorProxy-Chain actif trouvé.[/yellow]")
            return
        pid = info["pid"]
        console.print(
            f"[cyan]⏹ Arrêt du serveur détaché "
            f"(PID {pid}, port {info['local_port']}, pays {info['country']})...[/cyan]"
        )
        try:
            os.kill(pid, signal.SIGTERM)
            console.print(f"[green]✓ Signal SIGTERM envoyé au PID {pid}.[/green]")
            clear_pid()
        except ProcessLookupError:
            console.print(f"[yellow]⚠ Le processus {pid} n'existe plus. Nettoyage du PID.[/yellow]")
            clear_pid()
        except PermissionError:
            console.print(f"[red]❌ Permission refusée pour terminer le PID {pid}.[/red]")
        return

    # ── Commande : vider le cache ──
    if clear_cache:
        from proxy_cache import clear_cache as _clear_cache
        _clear_cache()
        console.print("[green]✓ Cache SQLite vidé.[/green]")
        return

    run(
        country_arg=country,
        local_port=local_port,
        verbose=verbose,
        list_countries_only=list_countries,
        skip_verify=skip_verify,
    )


if __name__ == "__main__":
    main()
