import os
import socket
import threading
import time
import json
import requests
import paramiko
import pandas as pd
from sklearn.cluster import KMeans
import folium

# ==========================================
# CONFIGURATION & SIMULATION LOGGING SETUP
# ==========================================
LOG_FILE = "honeypot_attacks.json"
HOST_KEY = paramiko.RSAKey(filename="server.key")

def log_attack_event(ip, username, password, timestamp=None):
    """Logs incoming SSH login attempts to a local JSON dataset."""
    event = {
        "timestamp": timestamp or time.time(),
        "ip": ip,
        "username": username,
        "password": password,
        "payload_len": len(username) + len(password)
    }
    events = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                events = json.load(f)
        except Exception:
            events = []
    events.append(event)
    with open(LOG_FILE, "w") as f:
        json.dump(events, f, indent=4)

# ==========================================
# LOW-INTERACTION PARAMIKO SSH SERVER
# ==========================================
class BasicHoneypotInterface(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.client_address = client_address

    def check_auth_password(self, username, password):
        # Capture and log credentials, then deliberately deny access
        print(f"[+] Captured login attempt from {self.client_address[0]} | User: {username} | Pass: {password}")
        log_attack_event(self.client_address[0], username, password)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def start_honeypot_listener(port=2222):
    """Starts the SSH honeypot socket server listener."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(100)
    print(f"[*] Honeypot SSH Server listening on port {port}...")

    def handle_client(client_socket, addr):
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = BasicHoneypotInterface(addr)
        try:
            transport.start_server(server=server)
            transport.accept(20)
        except Exception as e:
            pass
        finally:
            transport.close()

    while True:
        try:
            client, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
        except KeyboardInterrupt:
            break

# ==========================================
# ATTACKER PROFILING & FOLIUM GEOLOCATION
# ==========================================
def fetch_ip_geo(ip):
    """Fetches IP geolocation (fallback to default coords for local/mock IPs)."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon", timeout=2)
        data = response.json()
        if data.get("status") == "success":
            return data["lat"], data["lon"], data["country"]
    except Exception:
        pass
    return 37.7749, -122.4194, "Unknown/Local"  # Default fallback coordinate

def generate_profiling_and_map():
    """Performs KMeans clustering on attack vectors and renders a Folium map."""
    if not os.path.exists(LOG_FILE):
        print("[-] No logs found to analyze.")
        return

    with open(LOG_FILE, "r") as f:
        data = json.load(f)

    if len(data) == 0:
        print("[-] Log file empty.")
        return

    df = pd.DataFrame(data)

    # Calculate basic attack features per IP
    feature_df = df.groupby("ip").agg(
        attempt_count=("username", "count"),
        avg_payload_len=("payload_len", "mean")
    ).reset_index()

    # KMeans Clustering (2 clusters: opportunistic vs high-frequency bot traffic)
    n_clusters = min(2, len(feature_df))
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    feature_df["cluster"] = kmeans.fit_predict(feature_df[["attempt_count", "avg_payload_len"]])

    print("\n--- ATTACKER PROFILING CLUSTER SUMMARY ---")
    print(feature_df)

    # Generate Folium Map
    attack_map = folium.Map(location=[20, 0], zoom_start=2)

    for _, row in feature_df.iterrows():
        lat, lon, country = fetch_ip_geo(row["ip"])
        color = "red" if row["cluster"] == 1 else "blue"
        popup_text = f"IP: {row['ip']}<br>Attempts: {row['attempt_count']}<br>Cluster: {row['cluster']} ({country})"
        folium.Marker(
            location=[lat, lon],
            popup=popup_text,
            icon=folium.Icon(color=color, icon="shield-alt", prefix="fa")
        ).add_to(attack_map)

    map_filename = "attacker_map.html"
    attack_map.save(map_filename)
    print(f"\n[+] Interactive map successfully generated: {map_filename}")

# ==========================================
# QUICK TESTING HARNESS
# ==========================================
def seed_dummy_logs():
    """Seeds baseline synthetic attack logs for instant profiling test."""
    dummy_data = [
        {"ip": "185.220.101.5", "user": "root", "pass": "123456"},
        {"ip": "185.220.101.5", "user": "admin", "pass": "admin"},
        {"ip": "185.220.101.5", "user": "support", "pass": "support"},
        {"ip": "198.51.100.24", "user": "user", "pass": "password"},
        {"ip": "45.33.32.156", "user": "oracle", "pass": "oracle123"},
        {"ip": "45.33.32.156", "user": "test", "pass": "test"},
    ]
    for d in dummy_data:
        log_attack_event(d["ip"], d["user"], d["pass"])

if __name__ == "__main__":
    print("[1] Seed dummy data & generate analysis map immediately")
    print("[2] Run active SSH Honeypot Server")
    choice = input("Select option (1/2): ").strip()

    if choice == "1":
        seed_dummy_logs()
        generate_profiling_and_map()
    else:
        # Start honeypot in background and listener
        start_honeypot_listener(port=2222)
