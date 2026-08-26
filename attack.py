#!/usr/bin/env python3
"""NEMESIS attack simulator - fire every major attack class at your own honeypot.

Runs real TCP traffic from distinct fake sources (127.0.0.2 - 127.0.0.11,
the Linux loopback range), so the profiler sees MANY different "attackers"
and every category lights up on the dashboard.

Usage:
  python3 attack.py              # full assault (11 attack classes + insider sim)
  python3 attack.py --no-insider # skip the simulated insider/honeytoken hit
"""
import socket, time, threading, argparse
from db import init_db, log_honeytoken_hit

PORTS = {"ssh": 2222, "http": 8080, "ftp": 2121, "telnet": 2323}

def send(port, data=b"", src="127.0.0.1", wait=0.3, banner_wait=0.3, linger=0.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((src, 0))
    except OSError:
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        src = "127.0.0.1"
    s.settimeout(6)
    try:
        s.connect(("127.0.0.1", port))
        time.sleep(banner_wait)
        if data:
            s.sendall(data)
            time.sleep(linger if linger else wait)
        else:
            time.sleep(wait)
    finally:
        s.close()

def run(name, fn):
    def w():
        print(f"    -> {name}")
        fn()
    t = threading.Thread(target=w, daemon=True)
    t.start()
    return t

def port_scan():
    ip = "127.0.0.2"
    for port in PORTS.values():
        send(port, b"", src=ip, wait=0.07)
        send(port, b"", src=ip, wait=0.07)

def ssh_bruteforce():
    ip = "127.0.0.3"
    for u, p in [("root", "123456"), ("root", "password"), ("admin", "admin"),
                 ("admin", "123456"), ("test", "test")]:
        send(2222, f"{u}\r\n{p}\r\n".encode(), src=ip, wait=0.12)

def ftp_bruteforce():
    ip = "127.0.0.4"
    for u, p in [("admin", "123456"), ("admin", "password"), ("root", "toor"),
                 ("test", "test"), ("ftp", "ftp"), ("admin", "admin"),
                 ("guest", "guest"), ("root", "123456"), ("admin", "root"),
                 ("user", "pass")]:
        send(2121, f"USER {u}\r\nPASS {p}\r\nQUIT\r\n".encode(), src=ip, wait=0.09)

def web_exploit():
    ip = "127.0.0.5"
    reqs = [
        b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /..%2f..%2f..%2fetc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /login?id=1' OR '1'='1 HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /search?q=1 UNION SELECT user,pass FROM users HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /post?id=1&name=<img src=x onerror=alert(2)> HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /admin/config.php HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n",
    ]
    for req in reqs:
        send(8080, req, src=ip, wait=0.1)

def telnet_banner():
    ip = "127.0.0.7"
    for line in (b"root\r\n", b"admin\r\n", b"help\r\n"):
        send(2323, line, src=ip, wait=0.2)

def slowloris():
    ip = "127.0.0.8"
    for _ in range(3):
        send(8080, b"GET / HTTP/1.1\r\nHost: victim\r\n", src=ip, wait=0.1, linger=1.1)

def connect_flood():
    ip = "127.0.0.9"
    ports = list(PORTS.values())
    for i in range(12):
        send(ports[i % 4], b"", src=ip, wait=0.04)

def credential_stuffing():
    ip = "127.0.0.10"
    for u in ("admin", "support", "it", "student", "faculty", "library"):
        send(2222, f"{u}\r\nWelcome@2024\r\n".encode(), src=ip, wait=0.1)

def curious_user():
    ip = "127.0.0.11"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((ip, 0))
    except OSError:
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    s.connect(("127.0.0.1", 2323))
    time.sleep(2.0)                       # hesitant - just reads the banner
    s.sendall(b"help\r\n")
    time.sleep(0.5)
    s.close()

def insider_decoy():
    """Insider: an employee machine fetches 'config backups' - classic insider behaviour."""
    ip = "127.0.0.6"
    send(8080, b"GET /config.ini HTTP/1.1\r\nHost: localhost\r\n\r\n", src=ip, wait=0.15)
    send(8080, b"GET /.env HTTP/1.1\r\nHost: localhost\r\n\r\n", src=ip, wait=0.15)
    send(2121, b"USER admin\r\nPASS S3cr3t!Campus2024\r\nRETR passwords.txt\r\nQUIT\r\n", src=ip, wait=0.25)
    send(2121, b"USER admin\r\nPASS S3cr3t!Campus2024\r\nRETR backup.sql\r\nQUIT\r\n", src=ip, wait=0.25)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-insider", action="store_true", help="skip the simulated insider (honeytoken) hit")
    args = ap.parse_args()
    init_db()
    print("=" * 56)
    print("  NEMESIS Attack Simulator — firing ALL attack classes")
    print("=" * 56)
    threads = [
        run("Port scan over all services          [127.0.0.2]", port_scan),
        run("SSH brute force (5 attempts)         [127.0.0.3]", ssh_bruteforce),
        run("FTP brute force (10 attempts)        [127.0.0.4]", ftp_bruteforce),
        run("Web exploits: traversal/SQLi/XSS     [127.0.0.5]", web_exploit),
        run("Telnet banner probing                [127.0.0.7]", telnet_banner),
        run("Slowloris slow-HTTP                  [127.0.0.8]", slowloris),
        run("Connect flood (12 sessions)          [127.0.0.9]", connect_flood),
        run("Credential stuffing                  [127.0.0.10]", credential_stuffing),
        run("Curious user single poke             [127.0.0.11]", curious_user),
        run("Insider: decoy config retrieval      [127.0.0.6]", insider_decoy),
    ]
    for t in threads:
        t.join()
    if not args.no_insider:
        time.sleep(0.4)
        print("    -> [simulated] Insider: decoy college-DB credential used   [10.0.0.44]")
        log_honeytoken_hit("10.0.0.44", "decoy college-db password")
    print("=" * 56)
    print("[*] Done. Open http://localhost:5000 to watch every category light up.")

if __name__ == "__main__":
    main()
