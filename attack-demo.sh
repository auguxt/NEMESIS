#!/usr/bin/env bash
# NEMESIS one-command demo: full attack simulator (no netcat needed).
# Usage: bash attack-demo.sh
cd "$(dirname "$0")"
python3 attack.py
