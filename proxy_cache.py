"""
SQLite cache for geolocated proxies.
Avoids re-querying ip-api.com on every run.
"""

import sqlite3
import time
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from proxy_scraper import Proxy

CACHE_DIR  = Path.home() / ".torproxy-chain"
CACHE_FILE = CACHE_DIR / "proxy_cache.db"
CACHE_TTL  = 24 * 3600   # 24 hours in seconds
PID_FILE   = CACHE_DIR / "torproxy.pid"


def _get_conn() -> sqlite3.Connection:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CACHE_FILE))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS proxies (
            host         TEXT    NOT NULL,
            port         INTEGER NOT NULL,
            proto        TEXT    NOT NULL DEFAULT 'socks5',
            country      TEXT    NOT NULL DEFAULT '',
            country_name TEXT    NOT NULL DEFAULT '',
            cached_at    REAL    NOT NULL,
            PRIMARY KEY (host, port)
        )
    """)
    conn.commit()
    return conn


def load_cached_proxies(ttl: int = CACHE_TTL) -> List["Proxy"]:
    """Load non-expired proxies from the cache."""
    from proxy_scraper import Proxy
    try:
        conn = _get_conn()
        cutoff = time.time() - ttl
        rows = conn.execute(
            """SELECT host, port, proto, country, country_name
               FROM proxies
               WHERE cached_at > ?
               ORDER BY cached_at DESC""",
            (cutoff,),
        ).fetchall()
        conn.close()
        return [
            Proxy(host=r[0], port=r[1], proto=r[2], country=r[3], country_name=r[4])
            for r in rows
        ]
    except Exception:
        return []


def save_proxies_to_cache(proxies: List["Proxy"]) -> None:
    """Upsert proxies into the cache."""
    try:
        conn = _get_conn()
        now = time.time()
        conn.executemany(
            """INSERT OR REPLACE INTO proxies
               (host, port, proto, country, country_name, cached_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(p.host, p.port, p.proto, p.country, p.country_name, now) for p in proxies],
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def count_cached_proxies(ttl: int = CACHE_TTL) -> int:
    """Return the number of valid (non-expired) entries in the cache."""
    try:
        conn = _get_conn()
        cutoff = time.time() - ttl
        count = conn.execute(
            "SELECT COUNT(*) FROM proxies WHERE cached_at > ?", (cutoff,)
        ).fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def cache_age_hours(ttl: int = CACHE_TTL) -> Optional[float]:
    """
    Return the age in hours of the most recent cache entry,
    or None if the cache is empty or fully expired.
    """
    try:
        conn = _get_conn()
        row = conn.execute("SELECT MAX(cached_at) FROM proxies").fetchone()
        conn.close()
        if row and row[0]:
            age = (time.time() - row[0]) / 3600
            return age if age < (ttl / 3600) else None
        return None
    except Exception:
        return None


def clear_cache() -> None:
    """Delete all entries from the cache."""
    try:
        conn = _get_conn()
        conn.execute("DELETE FROM proxies")
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── PID file (background server) ──────────────────────────────────────────────

def write_pid(pid: int, local_port: int, country: str) -> None:
    """Write the PID and server metadata to the PID file."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(f"{pid}\n{local_port}\n{country}\n")


def read_pid() -> Optional[dict]:
    """
    Read the PID file and verify the process is still alive.
    Returns None if the process is gone or the file does not exist.
    """
    try:
        lines = PID_FILE.read_text().strip().splitlines()
        pid        = int(lines[0])
        local_port = int(lines[1]) if len(lines) > 1 else 10800
        country    = lines[2].strip() if len(lines) > 2 else "?"
        import os
        os.kill(pid, 0)   # signal 0 = existence check only
        return {"pid": pid, "local_port": local_port, "country": country}
    except Exception:
        return None


def clear_pid() -> None:
    """Remove the PID file."""
    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass
