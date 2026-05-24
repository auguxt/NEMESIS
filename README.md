# 🍯 NEMESIS

**Network Entrapment & Malicious Entity Surveillance Intelligence System**

A lightweight honeypot-based intrusion detection system designed for Indian educational networks.

## Features

- ✅ 4 Fake Services (SSH, HTTP, FTP, Telnet)
- ✅ Real-time Attack Detection
- ✅ Attacker Profiling with Risk Scoring
- ✅ SQLite Database
- ✅ Flask Dashboard with SocketIO Alerts
- ✅ Zero Cost Deployment

## Installation

```bash
pip install flask flask-socketio eventlet
```

## Usage

```bash
python3 dashboard.py
```

Open browser: `http://localhost:5000`

## Architecture

- **honeypot.py** — 4 fake servers
- **database.py** — SQLite storage
- **profiler.py** — Attacker classification
- **dashboard.py** — Flask + SocketIO
- **dashboard.html** — Web interface

## Testing

```bash
nc localhost 2222  # SSH
nc localhost 8080  # HTTP
nc localhost 2121  # FTP
nc localhost 2323  # Telnet
```

## IEEE Papers Reviewed

15 papers analyzed covering honeypot research from 2008-2025.

## Authors

- Team of 3 B.E. CSE Cybersecurity Students
- Final Year Project
- College Name: [Your College]

## License

MIT License

---

**Status**: Ready for Final Year Review ✅
