from flask import Flask, render_template, jsonify
from database import get_all_attacks, get_all_attackers, get_total_count
from profiler import profile_all

app = Flask(__name__)


# ─────────────────────────────────────────
# HOME PAGE — shows the dashboard
# ─────────────────────────────────────────
@app.route('/')
def home():
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
# API — returns latest attacks as JSON
# (for live refresh later)
# ─────────────────────────────────────────
@app.route('/api/attacks')
def api_attacks():
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
# RUN THE DASHBOARD
# ─────────────────────────────────────────
if __name__ == '__main__':
    print("[*] NEMESIS Dashboard starting...")
    print("[*] Open your browser: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
