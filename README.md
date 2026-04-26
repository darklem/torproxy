# TorProxy-Chain

A SOCKS5 proxy server that chains your traffic through Tor and then through a public exit proxy, giving you a two-hop anonymity layer with automatic country selection and proxy rotation.

```
Your app → Local SOCKS5 (port 10800) → Tor → Public SOCKS proxy → Internet
```

---

## Features

- **Double-hop routing** — Tor hides your IP from the exit proxy; the exit proxy hides Tor from the destination
- **Country selection** — pick an exit country; the server picks the fastest live proxy in that country
- **MITM detection** — every proxy is TLS-fingerprinted during verification; proxies intercepting TLS are excluded from the pool
- **Automatic rotation** — watchdog probes the active proxy every N seconds and rotates on failure; optional request-count rotation
- **Web admin UI** — live dashboard at `http://localhost:10801` with pool status, MITM verdict, and database stats
- **Background rescrape** — purge + re-fetch from the UI without restarting the server

---

## Requirements

### Docker (recommended)

- Docker + Docker Compose

### Local (development)

```bash
pip install requests pysocks stem rich click
apt install tor   # or brew install tor on macOS
```

---

## Quick Start

### Docker Compose

```bash
git clone https://github.com/darklem/torproxy-chain
cd torproxy-chain
docker compose up -d
```

The server is ready when `docker compose logs -f` shows:
```
Local SOCKS5 server ready: socks5://0.0.0.0:10800
```

Configure your browser or tool to use `socks5://localhost:10800` as a SOCKS5 proxy.

### Local

```bash
python main.py                          # interactive country selection
python main.py --country FR             # direct country selection
python main.py --country US --headless  # headless, block until Ctrl-C
```

---

## Configuration

All options are available as CLI flags and as environment variables (prefix `TORPROXY_`).

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `TORPROXY_COUNTRY` | `--country` | (interactive) | ISO 2-letter exit country code (e.g. `FR`, `US`) |
| `TORPROXY_LOCAL_PORT` | `--local-port` | `10800` | Local SOCKS5 listening port |
| `TORPROXY_TOR_PORT` | `--tor-port` | (start Tor) | Reuse an existing Tor SOCKS port; skip starting Tor |
| `TORPROXY_STATUS_PORT` | `--status-port` | (disabled) | Enable HTTP admin UI on this port (e.g. `10801`) |
| `TORPROXY_HEADLESS` | `--headless` | `0` | `1` = no interactive prompt, block until SIGTERM |
| `TORPROXY_SKIP_VERIFY` | `--skip-verify` | `0` | `1` = skip proxy liveness check (faster startup, less safe) |
| `TORPROXY_WATCHDOG_INTERVAL` | `--watchdog-interval` | `30` | Seconds between watchdog probes |
| `TORPROXY_FAIL_THRESHOLD` | `--fail-threshold` | `3` | Consecutive probe failures before auto-rotation |
| `TORPROXY_ROTATE_EVERY` | `--rotate-every` | `0` | Rotate after N TCP connections (`0` = disabled) |
| `TORPROXY_RATE_LIMIT_HOSTS` | `--rate-limit-hosts` | (none) | Comma-separated hostnames that trigger instant rotation on CONNECT |
| `TORPROXY_VERBOSE` | `--verbose` | `0` | `1` = debug logging |

### Example docker-compose.yml

```yaml
services:
  torproxy:
    build: .
    ports:
      - "10800:10800"
      - "10801:10801"
    volumes:
      - torproxy-cache:/root/.torproxy-chain
    environment:
      TORPROXY_HEADLESS: "1"
      TORPROXY_STATUS_PORT: "10801"
      TORPROXY_COUNTRY: "FR"           # optional — omit for any country
      TORPROXY_ROTATE_EVERY: "200"     # rotate after 200 connections
      TORPROXY_WATCHDOG_INTERVAL: "30"
      TORPROXY_FAIL_THRESHOLD: "3"
    restart: unless-stopped

volumes:
  torproxy-cache:
```

---

## CLI Reference

```
python main.py [OPTIONS]

Options:
  -c, --country CODE        Exit country (ISO 2-letter). Interactive if omitted.
  -l, --list-countries      Print available countries and exit.
  -p, --local-port INT      Local SOCKS5 port. [default: 10800]
      --tor-port INT        Use existing Tor SOCKS port instead of starting Tor.
  -v, --verbose             Enable debug logging.
      --skip-verify         Skip full-chain proxy verification.
      --watchdog-interval   Seconds between watchdog probes. [default: 30]
      --fail-threshold      Failures before rotation. [default: 3]
      --rotate-every INT    Rotate every N connections (0 = off). [default: 0]
      --rate-limit-hosts    Extra hostnames that trigger instant rotation.
      --headless            No prompts; block until SIGTERM.
      --status-port INT     Enable HTTP admin UI on this port.
  -k, --kill                Stop a detached server.
      --clear-cache         Wipe the SQLite proxy cache.
      --help                Show this message and exit.
```

### Interactive controls (non-headless mode)

| Key | Action |
|-----|--------|
| `r` | Rotate to next exit proxy |
| `n` | New Tor circuit (new identity) |
| `i` | Check current public IP |
| `d` | Detach (keep server running, exit UI) |
| `q` | Quit and stop server |

---

## Architecture

### Startup pipeline

```
1. Start Tor (or attach to existing Tor on --tor-port)
2. Fetch proxies from public sources (proxy_sources.py)
3. Geolocate proxy IPs via ip-api.com in batches (cached in SQLite)
4. Filter by selected country
5. Verify up to 200 candidates via full chain:
     us → Tor → proxy → ipconfig.io:443 (HTTPS)
   Each verification:
     a. Confirms the proxy is alive and routes HTTPS
     b. Records round-trip latency
     c. Detects TLS MITM by comparing the cert fingerprint
        against a direct (no-proxy) baseline
     d. Geolocates the exit IP from the JSON response
6. Start local SOCKS5 server with the verified pool
7. Start watchdog thread
```

### Proxy chain (per connection)

```
Client
  │  SOCKS5
  ▼
Local SOCKS5 server (port 10800)
  │  PySocks tunnels TCP through Tor
  ▼
Tor (port 9050)
  │  speaks SOCKS4/5 to exit proxy
  ▼
Exit proxy (public SOCKS4/5)
  │  TCP
  ▼
Destination
```

Each incoming TCP `accept()` on port 10800 spawns a `_ClientHandler` thread that:
1. Completes the server-side SOCKS5 handshake with the client
2. Opens a PySocks socket through Tor to the exit proxy
3. Speaks SOCKS4a or SOCKS5 to the exit proxy to reach the destination
4. Relays data bidirectionally until either side closes

### Connection counting and rotation

`--rotate-every N` counts **TCP connections** (one `accept()` = one connection). A browser creates 5–30 connections per page load (one CONNECT per hostname). At `N=200` a typical browsing session rotates roughly every few pages.

The counter resets to 0 on every rotation (manual, watchdog, or request-count).

### Watchdog

A background thread probes the active exit proxy every `--watchdog-interval` seconds via a TCP connect through Tor. If the probe fails `--fail-threshold` consecutive times, the server auto-rotates to the next proxy in the pool.

Chain connection failures (the client connected but the proxy couldn't reach the destination) also increment the failure counter.

### MITM detection

During the verification step, every proxy is checked for TLS interception:

1. A direct TLS connection to `ipconfig.io:443` is made (no proxy) and the SHA-256 of the DER certificate is recorded as the **baseline**.
2. For each proxy, the same connection is made through the full chain. The certificate fingerprint seen through the chain is compared to the baseline.
3. If they differ, the proxy is presenting its own certificate — a clear MITM. The proxy is stored in the SQLite cache (`mitm_clean=0`) but excluded from the active pool.

If the direct baseline fetch fails (network issue), the comparison is skipped and proxies get the benefit of the doubt.

### Proxy sources

Sources are defined in `proxy_sources.py`. To add your own:

```python
# proxy_sources.py
ProxySource(
    name="my-source",
    proto="socks5",
    urls=["https://example.com/socks5.txt"],
),
```

Each URL must return one `IP:PORT` per line. No code changes outside `proxy_sources.py` are needed.

### SQLite cache

Tested proxies are persisted in `~/.torproxy-chain/proxy_cache.db` (Docker: volume `torproxy-cache`). Cache entries expire after 24 hours. This avoids re-geolocating the same IPs on every run.

Schema: `host, port, proto, country, country_name, latency_ms, mitm_clean, alive, checked_at`

---

## Admin UI

When `--status-port` (or `TORPROXY_STATUS_PORT`) is set, an HTTP server is available:

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Dashboard — current proxy, pool table, MITM verdict, rotation stats |
| `/database` | GET | Database page — cache stats, loading summary, rescrape button |
| `/status` | GET | JSON status blob |
| `/pool` | GET | JSON array of proxies in the pool |
| `/rotate` | POST | Manually rotate to next proxy |
| `/proxy/{n}` | POST | Switch to pool index `n` |
| `/db/purge` | POST | Clear cache and trigger background rescrape |

---

## Development

### Run locally without Docker

```bash
pip install -r requirements.txt
python main.py --status-port 10801
```

### Kill a detached server

```bash
python main.py --kill
```

### Clear the proxy cache

```bash
python main.py --clear-cache
```

### Add a new proxy source

Edit `proxy_sources.py` and add a `ProxySource` entry. Restart the server or trigger a rescrape from the admin UI (`/database` → Purge & Rescrape).
