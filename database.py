import sqlite3
from datetime import datetime


# ─────────────────────────────────────────
# CREATE DATABASE AND ALL TABLES
# ─────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("honeytrap.db")
    cursor = conn.cursor()

    # Table 1 — every single attack event
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            service   TEXT,
            ip        TEXT,
            data      TEXT
        )
    """)

    # Table 2 — one row per unique attacker IP
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attackers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip            TEXT UNIQUE,
            first_seen    TEXT,
            last_seen     TEXT,
            total_attacks INTEGER DEFAULT 1
        )
    """)

    conn.commit()
    conn.close()
    print("[*] Database ready → honeytrap.db")


# ─────────────────────────────────────────
# SAVE ONE ATTACK
# ─────────────────────────────────────────
def save_attack(service, ip, data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect("honeytrap.db")
    cursor = conn.cursor()

    # Insert into attacks table
    cursor.execute("""
        INSERT INTO attacks (timestamp, service, ip, data)
        VALUES (?, ?, ?, ?)
    """, (timestamp, service, ip, data))

    # Insert or update attackers table
    cursor.execute("SELECT id FROM attackers WHERE ip = ?", (ip,))
    existing = cursor.fetchone()

    if existing:
        # IP seen before → update count and last_seen
        cursor.execute("""
            UPDATE attackers
            SET total_attacks = total_attacks + 1,
                last_seen = ?
            WHERE ip = ?
        """, (timestamp, ip))
    else:
        # New IP → create new row
        cursor.execute("""
            INSERT INTO attackers (ip, first_seen, last_seen, total_attacks)
            VALUES (?, ?, ?, 1)
        """, (ip, timestamp, timestamp))

    conn.commit()
    conn.close()

    return {
	'timestamp':  timestamp,
	'service':    service,
	'ip':	      ip,
	'data':       data[:60] if data else 'connection attempt'
# ─────────────────────────────────────────
# READ — ALL ATTACKS
# ─────────────────────────────────────────
def get_all_attacks():
    conn = sqlite3.connect("honeytrap.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────
# READ — ALL ATTACKERS
# ─────────────────────────────────────────
def get_all_attackers():
    conn = sqlite3.connect("honeytrap.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attackers ORDER BY total_attacks DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────
# READ — ATTACKS BY ONE IP
# ─────────────────────────────────────────
def get_attacks_by_ip(ip):
    conn = sqlite3.connect("honeytrap.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks WHERE ip = ? ORDER BY id DESC", (ip,))
    rows = cursor.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────
# READ — ATTACKS BY SERVICE
# ─────────────────────────────────────────
def get_attacks_by_service(service):
    conn = sqlite3.connect("honeytrap.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks WHERE service = ? ORDER BY id DESC", (service,))
    rows = cursor.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────
# READ — TOTAL COUNT
# ─────────────────────────────────────────
def get_total_count():
    conn = sqlite3.connect("honeytrap.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM attacks")
    count = cursor.fetchone()[0]
    conn.close()
    return count
