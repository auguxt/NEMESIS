from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from database import init_db, get_all_attacks, get_all_attackers, get_total_count
from profiler import profile_all
import honeypot
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Give honeypot.py access to socketio for real-time alerts
honeypot.set_socketio(socketio)


# ─────────────────────────────────────────
# HOME PAGE
# ─────────────────────────────────────────
@app.route('/')
def home():
    """Render main dashboard"""
    attacks   = get_all_attacks()
    attackers = get_all_attackers()
    profiles  = profile_all()
    total     = get_total_count()

    return render_template(
        'dashboard.html',
        attacks   = attacks,
        attackers = attackers,
        profiles  = profiles,
        total     = total
    )


# ─────────────────────────────────────────
# API — GET ATTACKS AS JSON
# ─────────────────────────────────────────
@app.route('/api/attacks')
def api_attacks():
    """Return all attacks as JSON"""
    attacks = get_all_attacks()
    result = []
    for row in attacks:
        result.append({
            'id':        row[0],
            'timestamp': row[1],
            'service':   row[2],
            'ip':        row[3],
            'data':      row[4][:60] if row[4] else ''
        })
    return jsonify(result)


# ─────────────────────────────────────────
# API — GET PROFILES AS JSON
# ─────────────────────────────────────────
@app.route('/api/profiles')
def api_profiles():
    """Return all attacker profiles as JSON"""
    profiles = profile_all()
    return jsonify(profiles)


# ─────────────────────────────────────────
# RUN EVERYTHING TOGETHER
# ─────────────────────────────────────────
if __name__ == '__main__':
    # Initialize database
    init_db()

    # Start honeypots in background thread
    print("\n[*] Starting NEMESIS components...\n")
    honeypot_thread = threading.Thread(
        target=honeypot.start_all_honeypots,
        daemon=True
    )
    honeypot_thread.start()

    # Small delay to let honeypots start
    import time
    time.sleep(1)

    print("\n" + "=" * 50)
    print("   🍯 NEMESIS DASHBOARD READY 🍯")
    print("=" * 50)
    print("\n   Open your browser: http://localhost:5000")
    print("   All services running on ports: 2222, 8080, 2121, 2323")
    print("\n")

    # Run SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
