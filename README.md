# TorProxy-Chain

Route your traffic through Tor, then chain it through a public SOCKS proxy of your choice — with country selection.

```
You ──► Tor (port 9050) ──► SOCKS4/5 public proxy [country] ──► Internet
```

## Features

- Automatic Tor connection and circuit management
- Scrapes SOCKS4/5 proxies from multiple public sources
- Interactive or CLI country selection (ISO 2-letter code)
- SQLite cache for geolocation results (24h TTL) — near-instant on second run
- Proxy liveness check via Tor before activation
- Auto-rotation on proxy failure
- Detach mode: keep the proxy running in background, reconnect or kill later
- Listens on `0.0.0.0` — usable from any device on your LAN
- No DNS leaks: remote DNS resolution via Tor + ATYP=0x03

## Requirements

- Python 3.9+
- `tor` installed: `sudo apt install tor`

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Interactive mode (recommended)
python main.py

# Direct country selection
python main.py --country FR

# List available countries
python main.py --list-countries

# Custom local port
python main.py --country US --local-port 1080

# Skip proxy verification (faster startup)
python main.py --country DE --skip-verify

# Verbose output
python main.py --country JP --verbose
```

## Runtime controls

Once the proxy chain is active, use these keys in the interactive loop:

| Key | Action |
|-----|--------|
| `r` | Rotate to next exit proxy |
| `n` | Request a new Tor circuit |
| `i` | Check current public IP |
| `d` | Detach — quit the UI, keep proxy running |
| `q` | Quit and stop everything |

## Background mode

```bash
# Detach with [d] during the session, then later:
python main.py --kill          # send SIGTERM to the detached server

# Or kill manually:
kill $(cat ~/.torproxy-chain/torproxy.pid | head -1)
```

## Cache management

```bash
python main.py --clear-cache   # force full re-geolocation on next run
```

Cache is stored at `~/.torproxy-chain/proxy_cache.db`.

## Test the proxy

```bash
# From the same machine
curl --proxy socks5h://127.0.0.1:10800 https://ipinfo.io

# From another device on the LAN
curl --proxy socks5h://<machine-ip>:10800 https://ipinfo.io
```

## Architecture

| File | Role |
|------|------|
| `main.py` | CLI (Click + Rich), main orchestration loop |
| `proxy_scraper.py` | Proxy scraping + batch geolocation via ip-api.com |
| `proxy_chain.py` | Local SOCKS5 server — chains requests through Tor then exit proxy |
| `proxy_cache.py` | SQLite cache for geolocation + PID file management |
| `tor_manager.py` | Tor process lifecycle and circuit control |

## Disclaimer

For educational and privacy research purposes. Respect local laws and service terms of use. Public SOCKS proxies are untrusted — the Tor layer protects your identity from the exit proxy.
