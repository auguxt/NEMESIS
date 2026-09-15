#!/usr/bin/env python3
"""NEMESIS profiler engine - 5-category classification + 0-100 risk scoring + attack-type detection."""
import ipaddress
import json
from collections import Counter, defaultdict

from db import fetch_honeytoken_ips, fetch_raw

CATEGORIES = ["Curious User", "Script Kiddie", "Bot", "Targeted", "Insider"]
RFC1918_NETS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
DECOY_HTTP_PATHS = {"/config.ini", "/.env", "/passwords.txt", "/backup.sql", "/backup/backup.sql"}
DECOY_FTP_FILES = {"passwords.txt", "backup.sql", "config.ini"}

# MITRE ATT&CK technique mapping (attack type -> (technique ID, name))
# Standard IDs from attack.mitre.org: T1110 Brute Force, T1046 Network Service Scanning,
# T1190 Exploit Public-Facing Application, T1078 Valid Accounts, T1189 Drive-by Compromise.
MITRE = {
    "Brute Force": ("T1110", "Brute Force"),
    "Login Probe": ("T1110.001", "Password Guessing"),
    "Banner Grab": ("T1046", "Network Service Scanning"),
    "Directory Traversal": ("T1190", "Exploit Public-Facing Application"),
    "SQL Injection": ("T1190", "Exploit Public-Facing Application"),
    "XSS Attempt": ("T1189", "Drive-by Compromise"),
    "Admin Scanner": ("T1190", "Exploit Public-Facing Application"),
    "HTTP Scan": ("T1046", "Network Service Scanning"),
    "Telnet Probe": ("T1046", "Network Service Scanning"),
    "Honeytoken Access": ("T1078", "Valid Accounts"),
    "Scan": ("T1046", "Network Service Scanning"),
}


def is_internal_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in RFC1918_NETS)


def detect_attack_type(service, commands):
    """Classify what kind of attack a session was, from its captured commands."""
    normalized = [c.strip() for c in commands if c and c.strip()]
    joined = " ".join(normalized).lower()

    if service == "ssh":
        if len(normalized) >= 2:
            return "Brute Force"
        if normalized:
            return "Login Probe"
        return "Banner Grab"

    if service == "ftp":
        upper = [c.upper() for c in normalized]
        retrieved = {
            cmd.split(maxsplit=1)[1].strip().lower()
            for cmd in normalized
            if cmd.upper().startswith("RETR ") and len(cmd.split(maxsplit=1)) > 1
        }
        if retrieved & DECOY_FTP_FILES:
            return "Honeytoken Access"
        if any(cmd.startswith("USER ") for cmd in upper) and any(cmd.startswith("PASS ") for cmd in upper):
            return "Brute Force"
        if normalized:
            return "Login Probe"
        return "Banner Grab"

    if service == "http":
        if any(path in joined for path in DECOY_HTTP_PATHS):
            return "Honeytoken Access"
        if any(k in joined for k in ("../", "..%2f", "etc/passwd")):
            return "Directory Traversal"
        if any(k in joined for k in ("union select", "' or", "or 1=1", "--")):
            return "SQL Injection"
        if any(k in joined for k in ("<script", "onerror=", "javascript:")):
            return "XSS Attempt"
        if any(k in joined for k in ("wp-login", "/admin", ".env")):
            return "Admin Scanner"
        return "HTTP Scan"

    if service == "telnet":
        return "Telnet Probe"
    return "Scan"


def classify(f):
    if f.get("honeytoken") or f.get("internal"):
        return "Insider"
    if f["total"] == 1 and f["diversity"] == 1:
        return "Curious User"
    if f["total"] <= 8 and f["diversity"] <= 2:
        return "Script Kiddie"
    if f["total"] > 30 or f["diversity"] >= 4 or (f["total"] > 12 and f["speed"] > 70):
        return "Bot"
    return "Targeted"


def compute(f):
    score = 0
    score += min(30, f["total"] * 3)  # volume
    score += min(20, f["diversity"] * 8)  # how many services
    speed_term = min(35, int(f["speed"] * min(1.0, f["total"] / 8)))
    score += speed_term  # intensity (damped for small counts)
    if f.get("honeytoken") or f.get("internal"):
        score += 25  # insider bonus
    return min(100, score), classify(f)


def build_profiles(rows):
    got = defaultdict(lambda: {"total": 0, "services": set(), "first": 1e18, "last": 0})
    types = defaultdict(Counter)
    for r in rows:
        p = got[r["src_ip"]]
        p["total"] += 1
        p["services"].add(r["service"])
        p["first"] = min(p["first"], r["timestamp"])
        p["last"] = max(p["last"], r["timestamp"])
        cmds = json.loads(r["commands"]) if r.get("commands") else []
        types[r["src_ip"]][detect_attack_type(r["service"], cmds)] += 1
    profiles = {}
    for ip, p in got.items():
        span = max(1.0, p["last"] - p["first"])
        speed = min(100, int(60 * p["total"] / span))
        profiles[ip] = {
            "ip": ip,
            "total": p["total"],
            "diversity": len(p["services"]),
            "speed": speed,
            "internal": is_internal_ip(ip),
            "honeytoken": False,
            "top_type": types[ip].most_common(1)[0][0] if types[ip] else "Scan",
            "mitre": sorted({MITRE[t][0] for t in types[ip]}) if types[ip] else ["T1046"],
        }
    return profiles


def score_all(rows=None):
    rows = rows if rows is not None else fetch_raw()
    profiles = build_profiles(rows)
    for hip in fetch_honeytoken_ips():
        if hip in profiles:
            profiles[hip]["honeytoken"] = True
        else:
            profiles[hip] = {
                "ip": hip,
                "total": 0,
                "diversity": 0,
                "speed": 0,
                "internal": False,
                "honeytoken": True,
                "top_type": "Honeytoken Access",
                "mitre": ["T1078"],
            }
    out = []
    for ip, f in profiles.items():
        score, cat = compute(f)
        out.append({"ip": ip, "category": cat, "risk": score, **f})
    return sorted(out, key=lambda x: -x["risk"])
