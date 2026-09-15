# NEMESIS

**Network Entrapment & Monitoring Engine for Security Insight Systems**

NEMESIS is a lightweight, multi-service honeypot built as a final-year cybersecurity project. It simulates common exposed services, logs attacker interactions, plants honeytokens, scores hostile behavior, and visualizes activity through a SOC-style dashboard.

> **Positioning:** This project is designed for academic, lab, and portfolio use. It demonstrates networking, threat detection, attacker profiling, and dashboarding concepts in a self-contained Python codebase.

## Features

- Simulated **SSH, HTTP, FTP, and Telnet** services using Python sockets
- **Honeytokens / decoy files** to flag suspicious access attempts
- SQLite-backed **attack logging and event persistence**
- **Attacker profiling engine** with category labels and 0–100 risk scores
- Basic **MITRE ATT&CK technique mapping** for observed behavior
- Live **SOC-style dashboard** with attack counts, event feed, and ranked attacker profiles
- Built-in **attack simulator** for demos and testing
- **Pure Python standard library** implementation — no third-party dependencies required

## Architecture

```text
                +--------------------+
                |    attack.py       |
                | Demo traffic gen   |
                +---------+----------+
                          |
                          v
+----------------------------------------------------------+
|                    honeypot.py                           |
|  Fake SSH / HTTP / FTP / Telnet listeners               |
|  - Captures commands / probes                           |
|  - Serves decoy resources                               |
|  - Writes session data                                  |
+-----------------------------+----------------------------+
                              |
                              v
                    +------------------+
                    |      db.py       |
                    | SQLite event log |
                    +------------------+
                              |
               +--------------+--------------+
               |                             |
               v                             v
      +------------------+          +-------------------+
      |   profiler.py    |          |    canary.py      |
      | Risk scoring +   |          | Honeytokens and   |
      | classification   |          | decoy file hooks  |
      +---------+--------+          +-------------------+
                |
                v
      +----------------------+
      |    dashboard.py      |
      | JSON API + UI page   |
      +----------+-----------+
                 |
                 v
         +---------------+
         | dashboard.html|
         | SOC frontend  |
         +---------------+
```

## Project Structure

```text
NEMESIS/
├── attack-demo.sh      # one-command demo runner
├── attack.py           # traffic simulator
├── canary.py           # decoy file / honeytoken logic
├── dashboard.html      # SOC dashboard frontend
├── dashboard.py        # HTTP server + JSON API
├── db.py               # SQLite storage layer
├── honeypot.py         # fake services and session capture
├── profiler.py         # attacker scoring and labeling
├── run.sh              # starts honeypot + dashboard
├── tests/
│   └── test_profiler.py
└── PORTFOLIO_NOTES.md  # resume bullets + interview talking points
```

## Threat Model Demonstrated

NEMESIS is built to surface recognizable attacker behavior patterns such as:

- Port scanning
- Banner grabbing
- Brute-force login attempts
- Directory traversal probes
- SQL injection attempts
- Cross-site scripting attempts
- Admin panel scanning
- Honeytoken / decoy file access

## Attacker Categories

The profiler groups observed sources into five simple categories:

- **Curious User**
- **Script Kiddie**
- **Bot**
- **Targeted**
- **Insider**

Risk is calculated from a combination of:

- event volume
- number of services touched
- interaction speed
- honeytoken/internal-network indicators

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/auguxt/NEMESIS.git
cd NEMESIS
```

### 2. Start the honeypot and dashboard

```bash
bash run.sh
```

Services exposed by default:

- SSH: `2222`
- HTTP: `8080`
- FTP: `2121`
- Telnet: `2323`
- Dashboard: `5000`

### 3. Generate demo traffic

In another terminal:

```bash
python3 attack.py
```

Or use the wrapper:

```bash
bash attack-demo.sh
```

### 4. Open the dashboard

```text
http://localhost:5000
```

## Demo Workflow

1. Start the listeners with `bash run.sh`
2. Launch `python3 attack.py`
3. Watch the dashboard update with:
   - attack totals
   - attacker categories
   - honeytoken hits
   - recent events
   - per-service activity
   - MITRE ATT&CK tags

## Testing

Run the lightweight unit tests:

```bash
python3 -m unittest discover -s tests -v
```

## Example Resume Description

> Built a Python-based multi-service honeypot simulating SSH, HTTP, FTP, and Telnet interactions, with SQLite logging, honeytoken detection, attacker risk scoring, and a live SOC-style monitoring dashboard.

More polished resume bullets are included in `PORTFOLIO_NOTES.md`.

## Key Engineering Choices

- **Standard library only:** keeps the project easy to run and review
- **SQLite storage:** simple local persistence for attacks and honeytoken hits
- **Threaded listeners:** lightweight concurrency for multiple connections
- **Heuristic scoring:** explainable attacker classification instead of black-box detection

## Limitations

This is a **lab/demo honeypot**, not a production deception platform.

Current limitations include:

- simplified protocol emulation
- heuristic, rule-based classification
- local SQLite storage only
- no authentication backend or real session emulation
- no distributed deployment / alerting pipeline

## Suggested Future Work

- add configuration via CLI or environment variables
- export reports as CSV / JSON
- Dockerize the project for simpler demos
- add more realistic protocol handling and fingerprints
- integrate alerting via email, Slack, or SIEM tools
- add authentication-attempt analytics and geo/IP enrichment
- extend test coverage

## Safe Use Notice

Use this project only in:

- your own lab
- local VMs / containers
- controlled academic environments

Do **not** expose it to the public internet without proper approval, monitoring, and isolation.

## Why This Project Matters

NEMESIS demonstrates:

- socket programming
- multithreading
- protocol-aware logging
- behavioral threat profiling
- SQLite persistence
- dashboard-driven visualization
- cybersecurity-focused system design

These make it a strong academic project for cybersecurity, backend, or systems-focused internship applications.
