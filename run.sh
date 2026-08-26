#!/usr/bin/env bash
# NEMESIS launcher — honeypot + dashboard in one command.
cd "$(dirname "$0")"
python3 honeypot.py & HP=$!
sleep 1
python3 dashboard.py & DP=$!
echo "Dashboard: http://localhost:5000   (Ctrl+C to stop)"
trap "kill $HP $DP 2>/dev/null" EXIT
wait
