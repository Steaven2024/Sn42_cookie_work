import subprocess
import time
import requests
import random
import os
import pathlib
import subprocess
import urllib.request

# === CONFIGURATION ===
OPENVPN_EXE = r"C:\Program Files\OpenVPN\bin\openvpn.exe"   # path to openvpn.exe
OVPN_PATH    = r"C:\Users\PC\OneDrive\Documents\42\open_vpn\57.ovpn"      # full path to your .ovpn file
AUTH_PATH    = r"C:\Users\PC\OpenVPN\config\auth.txt"     # where credentials will be stored
VPN_USERNAME = "bestwonderdev"                     # e.g. t1234567
VPN_PASSWORD = "kisiskis"                     # replace or set via env vars
RECONNECT_DELAY = 10                                        # seconds to wait after connect

def get_public_ip_with_retry():
    for attempt in range(10):
        try:
            ip = urllib.request.urlopen("https://ifconfig.me", timeout=10).read().decode()
            return ip.strip()
        except Exception as e:
            print(f"[DEBUG] DNS not ready yet (attempt {attempt+1}/10): {e}")
            time.sleep(3)
    raise RuntimeError("VPN DNS failed to stabilize after 10 attempts.")

# ------------------------------------------------------------
# Helper: write auth file safely
def write_auth_file(auth_path, username, password):
    """Write username/password to a file with limited permissions."""
    p = pathlib.Path(auth_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(f"{username}\n{password}\n")
    # Hide file (optional)
    subprocess.run(["attrib", "+h", str(p)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return str(p)


# ------------------------------------------------------------
# Helper: rotate one of the 'remote' servers in the .ovpn
def rotate_server_in_ovpn(ovpn_path=OVPN_PATH):
    """Rotate remote servers by moving a random one to the top instead of removing others."""
    if not os.path.exists(ovpn_path):
        print(f"[VPN] File not found: {ovpn_path}")
        return None

    with open(ovpn_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    remote_lines = [line for line in lines if line.strip().startswith("remote ")]
    if not remote_lines:
        print("[VPN] No 'remote' entries found.")
        return None

    chosen = random.choice(remote_lines).strip()
    print(f"[VPN] Selected server: {chosen}")

    # Remove all remote lines
    new_lines = [line for line in lines if not line.strip().startswith("remote ")]

    # Reinsert all, but with chosen first
    remotes_reordered = [chosen + "\n"] + [r for r in remote_lines if r.strip() != chosen]
    insert_index = 0
    for i, line in enumerate(new_lines):
        if line.strip().startswith("proto "):
            insert_index = i + 1
            break

    new_lines[insert_index:insert_index] = remotes_reordered

    with open(ovpn_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print(f"[VPN] Updated .ovpn to use: {chosen}")
    return chosen



# ------------------------------------------------------------
# Helper: get current external IP
def get_public_ip():
    try:
        return requests.get("https://ifconfig.me", timeout=10).text.strip()
    except Exception as e:
        return f"Error getting IP: {e}"


# ------------------------------------------------------------
# Disconnect any running OpenVPN instance
def disconnect_vpn():
    subprocess.run(["taskkill", "/IM", "openvpn.exe", "/F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ------------------------------------------------------------
# Main reconnect logic (using openvpn.exe CLI)
import subprocess
import os

def reconnect_vpn(ovpn_path=OVPN_PATH, auth_path=AUTH_PATH, delay=RECONNECT_DELAY):

    log_path = r"C:\Users\PC\OpenVPN\vpn_log.txt"
    disconnect_vpn()
    time.sleep(1)
    with open(log_path, "w") as log_file:
        cmd = [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            "--config", ovpn_path,
            "--auth-user-pass", auth_path
        ]
        print(f"[VPN] Launching: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(r"C:\Program Files\OpenVPN\bin\openvpn.exe"),
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    print(f"[VPN] Started OpenVPN (PID {process.pid}). Logging to {log_path}")
    time.sleep(5)
    ip = get_public_ip_with_retry()
    print(f"[VPN] Connected. Current IP: {ip}")


# ------------------------------------------------------------
# === TEST ENTRY POINT ===
if __name__ == "__main__":
    print("\n=== VPN SERVER ROTATION & CONNECT TEST ===")

    disconnect_vpn()
    # 1. write credentials
    #write_auth_file(AUTH_PATH, VPN_USERNAME, VPN_PASSWORD)

    # 2. pick random remote server from the .ovpn
    rotate_server_in_ovpn()

    # 3. connect using openvpn.exe
    reconnect_vpn()
    while(1):
        time.sleep(3)
    print("[TEST] Done.")
