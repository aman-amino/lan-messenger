import json
import os
import subprocess
import ssl
from pathlib import Path

DEFAULT_SETTINGS = {
    "username": "User",
    "tcp_chat_port": 12347,
    "tcp_file_port": 12346,
    "bind_ip": "0.0.0.0",
    "auth_token": "",  # empty means no auth
    "allowed_ips": []  # empty list means allow all
}

SETTINGS_FILE = "settings.json"

def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS
    try:
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    except:
        return DEFAULT_SETTINGS


def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=4)

# TLS configuration
TLS_CERT_FILE = Path("tls_cert.pem")
TLS_KEY_FILE  = Path("tls_key.pem")

def generate_tls_cert():
    """Create a self‑signed cert/key pair (run once)."""
    if TLS_CERT_FILE.exists() and TLS_KEY_FILE.exists():
        return

    cmd = [
        "openssl", "req", "-x509", "-nodes", "-days", "3650",
        "-newkey", "rsa:2048",
        "-keyout", str(TLS_KEY_FILE),
        "-out", str(TLS_CERT_FILE),
        "-subj", "/CN=LANMessenger"
    ]
    try:
        # Note: We assume openssl is available in the environment (e.g. WSL/Linux or Path)
        subprocess.check_call(cmd)
        print(f"[DEBUG] TLS certificate generated at {TLS_CERT_FILE}")
    except Exception as e:
        print(f"[DEBUG] TLS generation failed: {e}")

# Call once on module load
generate_tls_cert()

# TLS helper – wrap a raw socket with our self‑signed cert/key
def wrap_socket(sock, server_side: bool = False):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if server_side else ssl.Purpose.SERVER_AUTH)
    ctx.load_cert_chain(certfile=str(TLS_CERT_FILE),
                        keyfile=str(TLS_KEY_FILE))
    if not server_side:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_side=server_side)
