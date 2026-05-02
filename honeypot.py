import socket
import threading
from datetime import datetime
from database import init_db, save_attack


# SocketIO will be passed in from dahboard
socketio_instance = None

def ser_socketio(sio):
    global socketio_instance
    socketio_instance = sio
# ─────────────────────────────────────────
# HANDLE ONE CLIENT
# ─────────────────────────────────────────
def handle_client(client, address, service, banner):
    ip = address[0]
    try:
        client.send(banner)
        data = client.recv(1024).decode(errors='ignore').strip()
        save_attack(service, ip, data)
        print(f"[{service}] {ip} → {data[:60]}")
    except:
        save_attack(service, ip, "connection attempt")
        print(f"[{service}] {ip} → connection attempt")
    finally:
        client.close()


# ─────────────────────────────────────────
# START ONE SERVICE
# ─────────────────────────────────────────
def start_service(port, service, banner):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[+] Fake {service} running on port {port}")
    while True:
        client, address = server.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(client, address, service, banner),
            daemon=True
        )
        thread.start()


# ─────────────────────────────────────────
# BANNERS
# ─────────────────────────────────────────
SSH_BANNER    = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
HTTP_BANNER   = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"
FTP_BANNER    = b"220 Welcome to FTP Server\r\n"
TELNET_BANNER = b"Welcome to Ubuntu 20.04\r\nlogin: "


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
init_db()

services = [
    (2222,  "SSH",    SSH_BANNER),
    (8080,  "HTTP",   HTTP_BANNER),
    (2121,  "FTP",    FTP_BANNER),
    (2323,  "Telnet", TELNET_BANNER),
]

print("=" * 45)
print("        NEMESIS Honeypot Starting")
print("=" * 45)

for port, service, banner in services:
    t = threading.Thread(
        target=start_service,
        args=(port, service, banner),
        daemon=True
    )
    t.start()

print("\n[*] All services running. Waiting for attackers...")
print("[*] Data saved to honeytrap.db")
print("[*] Press Ctrl+C to stop\n")

try:
    while True:
        pass
except KeyboardInterrupt:
    print("\n[!] NEMESIS stopped.")
