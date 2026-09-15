#!/usr/bin/env python3
"""NEMESIS database layer - SQLite, single file, thread-safe, stdlib only."""
import hashlib
import json
import os
import sqlite3
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "nemesis.db")
_lock = threading.Lock()


def _stable_token(label):
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:16]
    return f"tok_{digest}"


def init_db():
    with _lock, sqlite3.connect(DB_PATH) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            service TEXT,
            src_ip TEXT,
            src_port INTEGER,
            session_id INTEGER,
            commands TEXT,
            credentials TEXT,
            drops TEXT);""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_src ON attacks(src_ip);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ts ON attacks(timestamp);")
        con.execute("""CREATE TABLE IF NOT EXISTS honeytokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE, label TEXT, created REAL);""")
        con.execute("""CREATE TABLE IF NOT EXISTS honeytoken_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id INTEGER, src_ip TEXT, timestamp REAL);""")


def dblog(session):
    init_db()
    with _lock, sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO attacks (timestamp, service, src_ip, src_port, session_id, commands, credentials, drops) VALUES (?,?,?,?,?,?,?,?)",
            (
                time.time(),
                session["service"],
                session["src_ip"],
                session["src_port"],
                session["session_id"],
                json.dumps(session["commands"]),
                json.dumps(session["credentials"]),
                session.get("drops", ""),
            ),
        )


def fetch_raw():
    init_db()
    with _lock, sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute("SELECT * FROM attacks ORDER BY id")]


def log_honeytoken_hit(src_ip, label="decoy credential"):
    """Simulate an insider touching a decoy credential (honeytoken)."""
    init_db()
    token = _stable_token(label)
    with _lock, sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT OR IGNORE INTO honeytokens (token, label, created) VALUES (?,?,?)",
            (token, label, time.time()),
        )
        row = con.execute("SELECT id FROM honeytokens WHERE token=?", (token,)).fetchone()
        con.execute(
            "INSERT INTO honeytoken_hits (token_id, src_ip, timestamp) VALUES (?,?,?)",
            (row[0], src_ip, time.time()),
        )


def fetch_honeytoken_ips():
    init_db()
    with _lock, sqlite3.connect(DB_PATH) as con:
        return [r[0] for r in con.execute("SELECT DISTINCT src_ip FROM honeytoken_hits")]


def fetch_honeytoken_count():
    init_db()
    with _lock, sqlite3.connect(DB_PATH) as con:
        return con.execute("SELECT COUNT(*) FROM honeytoken_hits").fetchone()[0]
