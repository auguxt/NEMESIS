#!/usr/bin/env python3
"""NEMESIS dashboard server - pure stdlib http.server, JSON API + live UI."""
import json, time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from db import fetch_raw, fetch_honeytoken_count
from profiler import score_all, detect_attack_type

PORT = 5000
STATE_FILE = "dashboard.html"
START = time.time()

def threat_level(risk):
    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 30:
        return "MEDIUM"
    if risk > 0:
        return "LOW"
    return "IDLE"

def render():
    rows = fetch_raw()
    profiles = score_all(rows)
    top_risk = max((p["risk"] for p in profiles), default=0)
    services = {"ssh": 0, "http": 0, "ftp": 0, "telnet": 0}
    categories = Counter()
    for r in rows:
        services[r["service"]] = services.get(r["service"], 0) + 1
    for p in profiles:
        categories[p["category"]] += 1
    recent = []
    for r in rows[-14:]:
        cmds = json.loads(r["commands"]) if r["commands"] else []
        recent.append({
            "ip": r["src_ip"], "service": r["service"],
            "type": detect_attack_type(r["service"], cmds),
            "cmd": cmds[-1] if cmds else "connected",
            "time": time.strftime("%H:%M:%S", time.localtime(r["timestamp"]))})
    recent.reverse()
    return {
        "attacks": len(rows),
        "attackers": len(profiles),
        "top_risk": top_risk,
        "threat": threat_level(top_risk),
        "categories": dict(categories),
        "services": services,
        "attackers_list": profiles,
        "recent": recent,
        "uptime": int(time.time() - START),
        "honeytoken_hits": fetch_honeytoken_count(),
    }

def handler_factory():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                with open(STATE_FILE, "rb") as f:
                    self.wfile.write(f.read())
            elif path == "/api":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(render()).encode())
            else:
                self.send_response(404)
                self.end_headers()
    return Handler

def main():
    print("=" * 52)
    print("  NEMESIS Dashboard — http://localhost:5000")
    print("=" * 52)
    ThreadingHTTPServer(("0.0.0.0", PORT), handler_factory()).serve_forever()

if __name__ == "__main__":
    main()
