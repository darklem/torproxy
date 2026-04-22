"""
Proxy source definitions.

Each ProxySource with fmt="text" is fetched generically (one IP:PORT per line).
Add entries to SOURCES to extend the pool — no other file needs to change.

Special sources that return JSON (proxy-list.download) are handled by a
dedicated fetcher in proxy_scraper.py and not listed here.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class ProxySource:
    name: str
    urls: List[str]
    proto: str = "socks5"   # "socks4" or "socks5"


# ── Built-in sources ──────────────────────────────────────────────────────────

SOURCES: List[ProxySource] = [
    ProxySource(
        name="proxyscrape SOCKS5",
        proto="socks5",
        urls=[
            "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_type=socks5&timeout=10000&country=all&simplified=true",
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
        ],
    ),
    ProxySource(
        name="proxyscrape SOCKS4",
        proto="socks4",
        urls=[
            "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_type=socks4&timeout=10000&country=all&simplified=true",
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
        ],
    ),
    ProxySource(
        name="GitHub hookzof",
        proto="socks5",
        urls=["https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"],
    ),
    ProxySource(
        name="GitHub proxifly",
        proto="socks5",
        urls=["https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"],
    ),
    ProxySource(
        name="GitHub TheSpeedX SOCKS5",
        proto="socks5",
        urls=["https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"],
    ),
    ProxySource(
        name="GitHub TheSpeedX SOCKS4",
        proto="socks4",
        urls=["https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"],
    ),
    ProxySource(
        name="GitHub monosans",
        proto="socks5",
        urls=[
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks5.txt",
        ],
    ),
    ProxySource(
        name="openproxylist.xyz",
        proto="socks5",
        urls=["https://openproxylist.xyz/socks5.txt"],
    ),

    # ── Add your own sources below ────────────────────────────────────────────
    # ProxySource(
    #     name="my-source",
    #     proto="socks5",
    #     urls=["https://example.com/socks5.txt"],
    # ),
]
