#!/usr/bin/env python3
"""NEMESIS profiler engine - 5-category classification + 0-100 risk scoring + attack-type detection."""
import json
from collections import defaultdict, Counter
from db import fetch_raw, fetch_honeytoken_ips

CATEGORIES = ["Curious User", "Script Kiddie", "Bot", "Targeted", "Insider"]

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
    "Honeytoken Hit": ("T1078", "Valid Accounts"),
    "Scan": ("T1046", "Network Service Scanning"),
}

def detect_attack_type(service, commands):
    """Classify what kind of attack a session was, from its captured commands."""
    joined = " ".join(commands).lower()
    if service in ("ssh", "ftp"):
        if len(commands) >= 2:
            return "Brute Force"
        if commands:
            return "Login Probe"
        return "Banner Grab"
    if service == "http":
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
    score += min(30, f["total"] * 3)                      # volume
    score += min(20, f["diversity"] * 8)                  # how many services
    speed_term = min(35, int(f["speed"] * min(1.0, f["total"] / 8)))
    score += speed_term                                   # intensity (damped for small counts)
    if f.get("honeytoken") or f.get("internal"):
        score += 25                                       # insider bonus
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
        profiles[ip] = {"ip": ip, "total": p["total"], "diversity": len(p["services"]),
                        "speed": speed,
                        "internal": ip.startswith(("10.", "192.168.", "172.")),
                        "honeytoken": False,
                        "top_type": types[ip].most_common(1)[0][0] if types[ip] else "Scan",
                        "mitre": sorted({MITRE[t][0] for t in types[ip]}) if types[ip] else ["T1046"]}
    return profiles

def score_all(rows=None):
    rows = rows if rows is not None else fetch_raw()
    profiles = build_profiles(rows)
    for hip in fetch_honeytoken_ips():
        if hip in profiles:
            profiles[hip]["honeytoken"] = True
        else:
            profiles[hip] = {"ip": hip, "total": 0, "diversity": 0, "speed": 0,
                             "internal": False, "honeytoken": True, "top_type": "Honeytoken Hit", "mitre": ["T1078"]}
    out = []
    for ip, f in profiles.items():
        score, cat = compute(f)
        out.append({"ip": ip, "category": cat, "risk": score, **f})
    return sorted(out, key=lambda x: -x["risk"])
