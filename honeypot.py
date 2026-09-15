#!/usr/bin/env python3
"""NEMESIS honeypot - 4 fake services that log everything (pure stdlib).

SSH 2222 | HTTP 8080 | FTP 2121 | Telnet 2323
Attack with:  nc localhost <port>
"""
import socket
import threading
import time
from itertools import count

import canary
from db import dblog

PORTS = {"ssh": 2222, "http": 8080, "ftp": 2121, "telnet": 2323}
BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "ftp": b"220 (vsFTPd 3.0.5)\r\n",
    "telnet": b"\xff\xfb\x01\xff\xfb\x03\r\nUbuntu 22.04 LTS login: ",
}
HTTP_LOGIN_PAGE = (
    b"<html><body><h1>Welcome</h1>"
    b"<form action='/login' method='POST'>"
    b"<input name='user'><input name='pass' type='password'><button>Login</button>"
    b"</form></body></html>"
)

sessions = {}
session_ids = count(1)
lock = threading.Lock()


def http_response(status_line, body=b"", ctype=b"text/plain"):
    return (
        status_line
        + b"\r\nServer: nginx/1.18.0"
        + b"\r\nContent-Type: " + ctype
        + b"\r\nContent-Length: " + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )


def new_session(service, ip, sport):
    with lock:
        sid = next(session_ids)
        sessions[sid] = {
            "service": service,
            "src_ip": ip,
            "src_port": sport,
            "session_id": sid,
            "start": time.time(),
            "commands": [],
            "credentials": [],
        }
        return sid


def record_command(sid, text):
    with lock:
        s = sessions[sid]
        s["commands"].append(text[:200])
        if len(s["commands"]) > 100:
            s["commands"] = s["commands"][-100:]


def process_line(service, sid, line, conn):
    """Handle one decoded, stripped line from an attacker."""
    if service == "ssh":
        record_command(sid, line)
    elif service == "http":
        parts = line.split()
        record_command(sid, line)  # request line e.g. GET /wp-login.php HTTP/1.1
        if len(parts) < 2:
            conn.sendall(http_response(b"HTTP/1.1 400 Bad Request"))
            return False
        method, path = parts[0].upper(), parts[1]
        decoy = canary.match_http(path, sessions[sid]["src_ip"])
        if decoy:
            body, ctype = decoy
            conn.sendall(http_response(b"HTTP/1.1 200 OK", body, ctype))
        elif method in {"GET", "POST"} and path in {"/", "/login", "/index.html"}:
            conn.sendall(http_response(b"HTTP/1.1 200 OK", HTTP_LOGIN_PAGE, b"text/html"))
        else:
            conn.sendall(http_response(b"HTTP/1.1 404 Not Found"))
        return False
    elif service == "ftp":
        up = line.upper()
        record_command(sid, line)
        if up.startswith("USER"):
            parts = line.split()
            sessions[sid]["credentials"].append((parts[1] if len(parts) > 1 else "", None))
            conn.sendall(b"331 Please specify the password.\r\n")
        elif up.startswith("PASS"):
            parts = line.split(maxsplit=1)
            if sessions[sid]["credentials"]:
                u, _ = sessions[sid]["credentials"][-1]
                p = parts[1] if len(parts) > 1 else ""
                sessions[sid]["credentials"][-1] = (u, p)
            conn.sendall(b"530 Login incorrect.\r\n")
        elif up.startswith("RETR"):
            fname = line.split()[1] if len(line.split()) > 1 else ""
            payload = canary.match_ftp(fname, sessions[sid]["src_ip"])
            if payload:
                conn.sendall(b"150 Opening data connection.\r\n")
                conn.sendall(payload + b"\r\n")
            else:
                conn.sendall(b"550 File not found.\r\n")
        elif up.startswith("QUIT"):
            conn.sendall(b"221 Goodbye.\r\n")
            return False
        elif up.startswith("SYST"):
            conn.sendall(b"215 UNIX Type: L8\r\n")
        else:
            conn.sendall(b"502 Command not implemented.\r\n")
    elif service == "telnet":
        record_command(sid, line)
        conn.sendall(b"Password: ")
    return True


def handle(service, conn, addr):
    ip, sport = addr
    sid = new_session(service, ip, sport)
    try:
        conn.settimeout(15)
        banner = BANNERS.get(service)
        if banner:
            conn.sendall(banner)
        buf = b""
        while True:
            data = conn.recv(512)
            if not data:
                break
            buf += data
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.rstrip(b"\r").decode("utf-8", errors="replace").strip()
                if line and not process_line(service, sid, line, conn):
                    raise ConnectionError("close")
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        with lock:
            session = sessions.pop(sid, None)
            if session is not None:
                session["end"] = time.time()
        if session is not None:
            dblog(session)
        try:
            conn.close()
        except OSError:
            pass


def serve(service, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(20)
    print(f"[+] {service.upper()} honeypot on 0.0.0.0:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(service, conn, addr), daemon=True).start()


if __name__ == "__main__":
    print("=" * 50)
    print("  NEMESIS Honeypot — Network Entrapment System")
    print("=" * 50)
    planted = canary.plant()
    print(f"[*] Canary decoy files planted: {planted} (canary/config.ini, .env, passwords.txt, backup.sql)")
    for svc, port in PORTS.items():
        threading.Thread(target=serve, args=(svc, port), daemon=True).start()
    print("[*] Listening. Attack with:  nc localhost <port>")
    print("[*] SSH 2222 | HTTP 8080 | FTP 2121 | Telnet 2323")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
