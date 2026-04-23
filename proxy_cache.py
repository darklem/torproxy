"""
SQLite cache for tested proxies.

Every proxy that completes a full-chain verification (Tor → proxy → ipconfig.io)
is stored here with its last known result: geolocation, latency, and MITM status.

This serves two purposes:
  1. Avoid repeating ip-api.com geo lookups across runs.
  2. When mounting the chain, only MITM-clean proxies are offered as candidates.

Dirty proxies are stored too so they are not re-tested unnecessarily on the
next run — they are simply kept out of the active pool.
"""

import os
import sqlite3
import time
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from proxy_scraper import Proxy

CACHE_DIR  = Path.home() / ".torproxy-chain"
CACHE_FILE = CACHE_DIR / "proxy_cache.db"
CACHE_TTL  = 24 * 3600   # entries older than 24 h are considered stale
PID_FILE   = CACHE_DIR / "torproxy.pid"

# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS proxies (
        host         TEXT    NOT NULL,
        port         INTEGER NOT NULL,
        proto        TEXT    NOT NULL DEFAULT 'socks5',
        country      TEXT    NOT NULL DEFAULT '',
        country_name TEXT    NOT NULL DEFAULT '',
        latency_ms   REAL    NOT NULL DEFAULT -1,
        -- 1 = TLS cert matched the direct baseline (clean); 0 = mismatch (MITM suspected)
        mitm_clean   INTEGER NOT NULL DEFAULT 1,
        -- 1 = proxy responded during last chain test; 0 = connection failed (HS)
        -- geo-only entries (never chain-tested) keep the default value of 1
        alive        INTEGER NOT NULL DEFAULT 1,
        checked_at   REAL    NOT NULL,
        PRIMARY KEY (host, port)
    )
"""

# Columns added after the initial release — applied via _migrate() at open time.
_MIGRATIONS = {
    "latency_ms": "ALTER TABLE proxies ADD COLUMN latency_ms   REAL    NOT NULL DEFAULT -1",
    "mitm_clean": "ALTER TABLE proxies ADD COLUMN mitm_clean   INTEGER NOT NULL DEFAULT 1",
    "alive":      "ALTER TABLE proxies ADD COLUMN alive        INTEGER NOT NULL DEFAULT 1",
}


def _get_conn() -> sqlite3.Connection:
    """Open (or create) the database and ensure the schema is current."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CACHE_FILE))
    conn.execute(_CREATE_TABLE)
    conn.commit()
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add any columns that are missing from an older database."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(proxies)")}
    for col, sql in _MIGRATIONS.items():
        if col not in existing:
            conn.execute(sql)
    conn.commit()


# ── Read ──────────────────────────────────────────────────────────────────────

def load_cached_proxies(
    ttl: int = CACHE_TTL,
    mitm_clean_only: bool = False,
) -> List["Proxy"]:
    """
    Return non-expired proxies from the cache, sorted by latency (fastest first).

    Args:
        ttl:            Maximum age (seconds) for an entry to be considered valid.
        mitm_clean_only: When True, exclude proxies where mitm_clean = 0.
                         Pass True when building the active proxy pool.
    """
    from proxy_scraper import Proxy
    try:
        conn = _get_conn()
        cutoff = time.time() - ttl

        # Build WHERE clause
        where  = "checked_at > ?"
        params: list = [cutoff]
        if mitm_clean_only:
            where += " AND mitm_clean = 1"

        rows = conn.execute(
            f"""SELECT host, port, proto, country, country_name, latency_ms, mitm_clean, alive
                FROM proxies
                WHERE {where}
                ORDER BY latency_ms ASC""",
            params,
        ).fetchall()
        conn.close()

        return [
            Proxy(
                host=r[0], port=r[1], proto=r[2],
                country=r[3], country_name=r[4],
                latency_ms=r[5],
                mitm_clean=bool(r[6]),
                alive=bool(r[7]),
            )
            for r in rows
        ]
    except Exception:
        return []


def count_cached_proxies(ttl: int = CACHE_TTL) -> int:
    """Number of valid (non-expired) entries, regardless of MITM status."""
    try:
        conn = _get_conn()
        cutoff = time.time() - ttl
        n = conn.execute(
            "SELECT COUNT(*) FROM proxies WHERE checked_at > ?", (cutoff,)
        ).fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0


def cache_age_hours(ttl: int = CACHE_TTL) -> Optional[float]:
    """
    Age in hours of the most recent entry, or None if the cache is empty / fully expired.
    Useful for deciding whether to skip a fresh scrape.
    """
    try:
        conn = _get_conn()
        row = conn.execute("SELECT MAX(checked_at) FROM proxies").fetchone()
        conn.close()
        if row and row[0]:
            age = (time.time() - row[0]) / 3600
            return age if age < (ttl / 3600) else None
        return None
    except Exception:
        return None


# ── Write ─────────────────────────────────────────────────────────────────────

def save_proxies_to_cache(proxies: List["Proxy"]) -> None:
    """
    Upsert all tested proxies, including MITM-dirty ones.

    Storing dirty proxies prevents them from being re-tested on every run.
    They are excluded from the active pool by load_cached_proxies(mitm_clean_only=True).
    """
    try:
        conn = _get_conn()
        now = time.time()
        conn.executemany(
            """INSERT OR REPLACE INTO proxies
               (host, port, proto, country, country_name, latency_ms, mitm_clean, alive, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (p.host, p.port, p.proto,
                 p.country, p.country_name,
                 p.latency_ms, int(p.mitm_clean), int(p.alive),
                 now)
                for p in proxies
            ],
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_cache_stats(ttl: int = CACHE_TTL) -> dict:
    """
    Return per-category proxy counts from the DB (non-expired entries only).

    Categories:
      verified_clean — alive=1, mitm_clean=1, latency_ms > 0  (chain-tested and clean)
      mitm           — mitm_clean=0                             (MITM cert mismatch)
      dead           — alive=0                                  (tested and unreachable)
      geo_only       — alive=1, latency_ms <= 0                 (geolocated, never chain-tested)
    """
    try:
        conn = _get_conn()
        cutoff = time.time() - ttl
        row = conn.execute(
            """SELECT
                   COUNT(*)                                                         AS total,
                   SUM(CASE WHEN alive=1 AND mitm_clean=1 AND latency_ms > 0
                            THEN 1 ELSE 0 END)                                     AS verified_clean,
                   SUM(CASE WHEN mitm_clean=0                THEN 1 ELSE 0 END)    AS mitm,
                   SUM(CASE WHEN alive=0                     THEN 1 ELSE 0 END)    AS dead,
                   SUM(CASE WHEN alive=1 AND latency_ms <= 0 THEN 1 ELSE 0 END)    AS geo_only
               FROM proxies
               WHERE checked_at > ?""",
            (cutoff,),
        ).fetchone()
        conn.close()
        total    = row[0] or 0
        clean    = row[1] or 0
        mitm     = row[2] or 0
        dead     = row[3] or 0
        geo_only = row[4] or 0
        return {
            "total":          total,
            "verified_clean": clean,
            "mitm":           mitm,
            "dead":           dead,
            "geo_only":       geo_only,
            "pct_clean":      round(100 * clean    / total, 1) if total else 0,
            "pct_mitm":       round(100 * mitm     / total, 1) if total else 0,
            "pct_dead":       round(100 * dead     / total, 1) if total else 0,
            "pct_geo_only":   round(100 * geo_only / total, 1) if total else 0,
        }
    except Exception:
        return {
            "total": 0, "verified_clean": 0, "mitm": 0, "dead": 0, "geo_only": 0,
            "pct_clean": 0, "pct_mitm": 0, "pct_dead": 0, "pct_geo_only": 0,
        }


def clear_cache() -> None:
    """Delete all entries (wipes geo data, latency, and MITM records)."""
    try:
        conn = _get_conn()
        conn.execute("DELETE FROM proxies")
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── PID file ──────────────────────────────────────────────────────────────────
# The PID file tracks a detached server process so --kill can terminate it.

def write_pid(pid: int, local_port: int, country: str) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(f"{pid}\n{local_port}\n{country}\n")


def read_pid() -> Optional[dict]:
    """
    Read the PID file and confirm the process is still alive.
    Returns None if the process is gone or the file does not exist.
    """
    try:
        lines = PID_FILE.read_text().strip().splitlines()
        pid        = int(lines[0])
        local_port = int(lines[1]) if len(lines) > 1 else 10800
        country    = lines[2].strip() if len(lines) > 2 else "?"
        os.kill(pid, 0)   # signal 0 = existence check, raises if dead
        return {"pid": pid, "local_port": local_port, "country": country}
    except Exception:
        return None


def clear_pid() -> None:
    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass
