import socket
import threading
from database import init_db, save_attack

# SocketIO instance (set by dashboard.py)
socketio_instance = None

def set_socketio(sio):
    """Set the SocketIO instance from dashboard.py"""
    global socketio_instance
    socketio_instance = sio


# ─────────────────────────────────────────
# HANDLE ONE CLIENT
# ─────────────────────────────────────────
def handle_client(client, address, service, banner):
    ip = address[0]
    try:
        # Send banner first
        client.send(banner)
        
        # Read what attacker sends
        data = client.recv(1024).decode(errors='ignore').strip()
        
        # Save to database and get data back
        attack_data = save_attack(service, ip, data)
        
        # Print to terminal
        print(f"[{service}] {ip} → {data[:60]}")
        
        # Emit real-time alert to all connected browsers
        if socketio_instance:
            socketio_instance.emit('new_attack', attack_data, broadcast=True)
            
    except:
        attack_data = save_attack(service, ip, "connection attempt")
        print(f"[{service}] {ip} → connection attempt")
        if socketio_instance:
            socketio_instance.emit('new_attack', attack_data, broadcast=True)
    finally:
        client.close()


# ─────────────────────────────────────────
# START ONE FAKE SERVICE
# ─────────────────────────────────────────
def start_service(port, service, banner):
    """Start a fake service on given port"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"[+] Fake {service} running on port {port}")
    
    while True:
        try:
            client, address = server.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(client, address, service, banner),
                daemon=True
            )
            thread.start()
        except:
            pass


# ─────────────────────────────────────────
# FAKE SERVICE BANNERS
# ─────────────────────────────────────────
SSH_BANNER    = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
HTTP_BANNER   = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n"
FTP_BANNER    = b"220 Welcome to FTP Server\r\n"
TELNET_BANNER = b"Welcome to Ubuntu 20.04\r\nlogin: "


# ─────────────────────────────────────────
# START ALL HONEYPOTS
# ─────────────────────────────────────────
def start_all_honeypots():
    """Start all 4 fake services"""
    services = [
        (2222,  "SSH",    SSH_BANNER),
        (8080,  "HTTP",   HTTP_BANNER),
        (2121,  "FTP",    FTP_BANNER),
        (2323,  "Telnet", TELNET_BANNER),
    ]

    print("=" * 50)
    print("        🍯 NEMESIS HONEYPOT STARTING 🍯")
    print("=" * 50)

    for port, service, banner in services:
        t = threading.Thread(
            target=start_service,
            args=(port, service, banner),
            daemon=True
        )
        t.start()

    print("\n[*] All 4 services running. Waiting for attackers...")
    print("[*] SSH (2222) | HTTP (8080) | FTP (2121) | Telnet (2323)")
