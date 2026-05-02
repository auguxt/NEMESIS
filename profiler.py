from database import get_attacks_by_ip, get_all_attackers
from datetime import datetime


# ─────────────────────────────────────────
# CALCULATE ATTACK SPEED
# ─────────────────────────────────────────
def calculate_speed(attacks):
    if len(attacks) < 2:
        return "slow"
    try:
        first_time = datetime.strptime(attacks[-1][1], "%Y-%m-%d %H:%M:%S")
        last_time  = datetime.strptime(attacks[0][1],  "%Y-%m-%d %H:%M:%S")
        total_seconds = (last_time - first_time).total_seconds()
        if total_seconds == 0:
            return "fast"
        rate = len(attacks) / total_seconds
        if rate > 2:
            return "fast"
        elif rate > 0.5:
            return "medium"
        else:
            return "slow"
    except:
        return "slow"


# ─────────────────────────────────────────
# CALCULATE RISK SCORE
# ─────────────────────────────────────────
def calculate_risk_score(total_attacks, unique_services, speed):
    score = 0
    if total_attacks == 1:
        score += 5
    elif total_attacks <= 5:
        score += 15
    elif total_attacks <= 20:
        score += 30
    else:
        score += 50
    if unique_services == 1:
        score += 5
    elif unique_services == 2:
        score += 15
    elif unique_services == 3:
        score += 25
    else:
        score += 35
    if speed == "fast":
        score += 15
    elif speed == "medium":
        score += 10
    return min(score, 100)


# ─────────────────────────────────────────
# CLASSIFY ONE ATTACKER
# ─────────────────────────────────────────
def classify_attacker(ip):
    attacks = get_attacks_by_ip(ip)
    if not attacks:
        return None
    total_attacks   = len(attacks)
    services_hit    = set(attack[2] for attack in attacks)
    unique_services = len(services_hit)
    speed           = calculate_speed(attacks)
    risk_score      = calculate_risk_score(total_attacks, unique_services, speed)

    if total_attacks == 1:
        category, level = "Curious User",       "LOW"
    elif speed == "fast" and total_attacks > 10:
        category, level = "Automated Bot",      "HIGH"
    elif unique_services >= 3:
        category, level = "Script Kiddie",      "MEDIUM"
    elif total_attacks > 10 and unique_services == 1:
        category, level = "Targeted Attacker",  "CRITICAL"
    elif total_attacks > 5:
        category, level = "Script Kiddie",      "MEDIUM"
    else:
        category, level = "Curious User",       "LOW"

    return {
        "ip":              ip,
        "total_attacks":   total_attacks,
        "services_hit":    list(services_hit),
        "unique_services": unique_services,
        "speed":           speed,
        "risk_score":      risk_score,
        "category":        category,
        "level":           level,
        "first_seen":      attacks[-1][1],
        "last_seen":       attacks[0][1],
    }


# ─────────────────────────────────────────
# PROFILE ALL ATTACKERS
# ─────────────────────────────────────────
def profile_all():
    attackers = get_all_attackers()
    if not attackers:
        return []
    profiles = []
    for attacker in attackers:
        profile = classify_attacker(attacker[1])
        if profile:
            profiles.append(profile)
    profiles.sort(key=lambda x: x["risk_score"], reverse=True)
    return profiles


# ─────────────────────────────────────────
# PRINT PROFILES
# ─────────────────────────────────────────
def print_profiles():
    profiles = profile_all()
    print("\n" + "=" * 60)
    print("      NEMESIS — ATTACKER PROFILES")
    print("=" * 60)
    if not profiles:
        print("  No attackers detected yet.")
        return
    for p in profiles:
        level_display = {
            "LOW":      "[ LOW      ]",
            "MEDIUM":   "[ MEDIUM   ]",
            "HIGH":     "[ HIGH     ]",
            "CRITICAL": "[ CRITICAL ]",
        }.get(p["level"], "[ UNKNOWN  ]")
        print(f"""
IP Address   : {p['ip']}
Category     : {p['category']}
Threat Level : {level_display}
Risk Score   : {p['risk_score']} / 100
Total Attacks: {p['total_attacks']}
Services Hit : {', '.join(p['services_hit'])}
Attack Speed : {p['speed']}
First Seen   : {p['first_seen']}
Last Seen    : {p['last_seen']}
{'-' * 45}""")


# ─────────────────────────────────────────
# RUN DIRECTLY TO SEE PROFILES
# ─────────────────────────────────────────
if __name__ == "__main__":
    print_profiles()
