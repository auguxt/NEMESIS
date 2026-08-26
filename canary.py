#!/usr/bin/env python3
"""NEMESIS canary (honeytoken) module - decoy files that fire alerts when used.

Deploys realistic decoy files (config.ini, .env, passwords.txt, backup.sql)
and hooks them into the honeypot's HTTP and FTP services. Anyone who fetches
these files is almost certainly an insider or a compromised account - the
profiler flags that source as "Insider" with MITRE ATT&CK T1078.
"""
import os
from db import log_honeytoken_hit

CANARY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canary")

FILES = {
    "config.ini": (
        "[database]\nhost=192.168.1.50\ndbname=campus_erp\n"
        "user=erp_admin\npassword=S3cr3t!Campus2024\n\n"
        "[ldap]\nserver=ldap.campus.local\n"
        "bind_ou=CN=Admins,CN=Users,DC=campus,DC=ac,DC=in\n"),
    ".env": (
        "DB_PASSWORD=S3cr3t!Campus2024\n"
        "API_KEY=camp-9f8a-7d2e-4b1c-0c3a\n"
        "JWT_SECRET=sup3r-s3cret-campus-2024\n"
        "VPN_SHARED_SECRET=campus-vpn-2024\n"),
    "passwords.txt": (
        "admin : P@ssw0rd\n"
        "root : toor123\n"
        "wifi_staff : wifi@campus123\n"
        "vpn_user : vpn@2024\n"),
    "backup.sql": (
        "-- campus ERP sanitised dump (DECOY - do not trust)\n"
        "CREATE TABLE staff (id TEXT, role TEXT, password TEXT);\n"
        "INSERT INTO staff VALUES ('EMP-118','admin','S3cr3t!Campus2024');\n"
        "INSERT INTO staff VALUES ('EMP-077','network','Net@dmin2024');\n"),
}

# path on the wire -> (filename, content-type)
HTTP_DECOYS = {
    "/config.ini": ("config.ini", "text/plain"),
    "/.env": (".env", "text/plain"),
    "/passwords.txt": ("passwords.txt", "text/plain"),
    "/backup.sql": ("backup.sql", "text/plain"),
    "/backup/backup.sql": ("backup.sql", "text/plain"),
}
FTP_DECOYS = {"passwords.txt", "backup.sql", "config.ini"}


def plant():
    """Write the decoy files to disk (they are physically present for the demo)."""
    os.makedirs(CANARY_DIR, exist_ok=True)
    for name, content in FILES.items():
        with open(os.path.join(CANARY_DIR, name), "w") as f:
            f.write(content)
    return len(FILES)


def match_http(path, src_ip):
    """HTTP honeypot hook: decoy path -> (payload bytes, content-type bytes) or None."""
    hit = HTTP_DECOYS.get(path)
    if not hit:
        return None
    fname, ctype = hit
    log_honeytoken_hit(src_ip, f"decoy {fname} fetched over HTTP")
    return FILES[fname].encode(), ctype.encode()


def match_ftp(fname, src_ip):
    """FTP honeypot hook: decoy filename -> payload bytes or None."""
    if fname not in FTP_DECOYS or fname not in FILES:
        return None
    log_honeytoken_hit(src_ip, f"decoy {fname} retrieved over FTP")
    return FILES[fname].encode()
