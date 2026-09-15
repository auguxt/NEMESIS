# Portfolio Notes for NEMESIS

Use this file to present the project well on your resume, LinkedIn, GitHub, or in interviews.

## 1-Line Summary

**NEMESIS is a Python-based multi-service honeypot and threat-profiling dashboard that simulates attacker interaction, captures malicious behavior, and visualizes risk in real time.**

## Resume Project Title

**NEMESIS — Multi-Service Honeypot and Threat Profiling Dashboard**

## Resume Bullet Points

- Built a Python-based honeypot that simulates **SSH, HTTP, FTP, and Telnet** services using sockets and multithreading.
- Designed an **attacker profiling engine** that classifies hostile sources into behavioral categories and assigns **0–100 risk scores** using activity volume, service diversity, and interaction speed.
- Implemented **honeytoken / decoy file detection** to flag suspicious access to planted credentials and sensitive-looking assets.
- Developed a live **SOC-style monitoring dashboard** showing attacker rankings, service-wise hits, recent event feeds, and MITRE ATT&CK technique mappings.
- Created an **attack simulator** that generates scanning, brute-force, exploitation, and insider-style activity for repeatable demos and testing.
- Used **SQLite** for event persistence and built the entire project with the **Python standard library**, keeping setup lightweight and portable.

## 30-Second Interview Pitch

I built NEMESIS as a final-year cybersecurity project to demonstrate networking, system design, and attack detection concepts in one system. It simulates exposed services like SSH, HTTP, FTP, and Telnet, logs attacker interactions into SQLite, uses heuristics to profile behavior and assign risk, and visualizes everything in a live SOC-style dashboard. I also added honeytokens and an attack simulator so the project is easy to demo and discuss in interviews.

## 60-Second Interview Explanation

The idea behind NEMESIS was to go beyond a generic web app and build something more systems- and security-oriented. The application exposes multiple fake services using socket programming and handles concurrent interactions with threads. Each session is logged and stored in SQLite. On top of that, I built a profiling engine that looks at factors like the number of hits, number of services touched, speed of interaction, and whether any honeytokens were accessed. Based on that, it classifies attackers into simple categories such as Bot, Script Kiddie, Targeted, or Insider. Finally, the dashboard presents all of this in a SOC-style view so the behavior is easy to interpret.

## What to Emphasize in Interviews

### Technical depth
- socket programming
- concurrency with threads
- protocol-aware service emulation
- SQLite persistence
- rule-based attack classification
- dashboard-driven monitoring

### Security depth
- honeypot design
- honeytokens / decoy data
- brute-force and probe detection
- MITRE ATT&CK mapping
- attack simulation for repeatable testing

### Engineering maturity
- modular design
- debugging protocol behavior
- explainable scoring logic
- balancing realism vs simplicity
- documentation and testability

## Honest Positioning

Say this:

> NEMESIS is a lightweight academic honeypot built to demonstrate threat detection and attacker profiling concepts, not a full production deception platform.

Avoid claiming:

- enterprise-grade detection
- real attacker attribution
- production-ready deployment
- complete protocol emulation

## Common Interview Questions and Strong Answers

### Why did you build this?
I wanted a project that combined cybersecurity concepts with real engineering work. A honeypot let me demonstrate sockets, concurrency, logging, analysis, and visualization in one system.

### What was the hardest part?
Balancing simplicity and realism. I wanted the project to stay self-contained and easy to run, while still producing meaningful telemetry and useful behavioral classification.

### What did you learn?
I learned how to build network listeners, structure session logging, design heuristic detection logic, and present security telemetry in a way that is understandable to users.

### What would you improve next?
I would add more realistic protocol emulation, better configurability, report export features, Docker packaging, and stronger automated testing.

## Best Resume Placement

This project fits well under:

- Projects
- Academic Projects
- Cybersecurity Projects
- Selected Work

## Best Job Targets for This Project

NEMESIS is especially useful for applying to:

- cybersecurity internships
- SOC analyst roles
- security engineering internships
- Python/backend internships
- systems-focused software roles

## Final Tip

The code matters, but **presentation matters almost as much**. A strong README, clear explanation, and confident demo can make this project much more valuable in placements and interviews.
