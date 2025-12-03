import sys
import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, Raw
from flask import Flask, render_template
from flask_socketio import SocketIO

# --- IMPORT THE LOGGER ---
# Ensure secure_logger.py is in the same folder
from secure_logger import SecureLogger 

# --- Flask & SocketIO Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key!'

# [FIX 1] CORS: Allow all origins so GitHub Codespaces/Cloud proxies work
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# --- INITIALIZE THE LOGGER ---
logger = SecureLogger()

# --- Data Storage & Globals ---
packet_counts = defaultdict(int)
data_lock = threading.Lock()
scan_tracker = defaultdict(lambda: defaultdict(set))

# [FIX 2] Rate Limiting Globals
last_alert_time = {} 
ALERT_COOLDOWN = 2.0  # Seconds to wait before repeating the exact same alert

PORT_SCAN_THRESHOLD = 10 

MALICIOUS_SIGNATURES = [
    b"ncat -e /bin/bash",
    b"cmd.exe",
    b"powershell.exe",
]

# --- HELPER FUNCTIONS ---

def send_alert(message):
    """
    Helper function to print, send to web, AND send to secure log.
    Includes Rate Limiting to prevent browser crashes.
    """
    global last_alert_time
    current_time = time.time()
    
    # [FIX 2] Rate Limiting Logic:
    # If we sent this exact message less than 2 seconds ago, skip it.
    if message in last_alert_time:
        if current_time - last_alert_time[message] < ALERT_COOLDOWN:
            return 

    # Update the last time we saw this alert
    last_alert_time[message] = current_time

    print(message) 
    socketio.emit('alert', {'message': message})
    logger.log_alert(message)

def check_signatures(packet):
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load
            
            # [FIX 3] Signature Echo Prevention:
            # If the packet contains Socket.IO data or JSON formatting, 
            # it is likely our own alert being sent to the browser. Ignore it.
            if b'socket.io' in payload or b'"message":' in payload:
                return

            for sig in MALICIOUS_SIGNATURES:
                if sig in payload:
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    msg = f"[ALERT] MALICIOUS SIGNATURE from {ip_src} to {ip_dst}: {sig.decode(errors='ignore')}"
                    send_alert(msg)
        except Exception:
            # Packet payload might be malformed or non-decodable, skip it
            pass

def detect_port_scan(packet, ip_src, ip_dst, dport, flags):
    msg = None
    if flags == 0:
        msg = f"[ALERT] NULL SCAN DETECTED from {ip_src} to {ip_dst}:{dport}"
    elif flags == 'F':
        msg = f"[ALERT] FIN SCAN DETECTED from {ip_src} to {ip_dst}:{dport}"
    elif flags == 'FPU':
        msg = f"[ALERT] XMAS SCAN DETECTED from {ip_src} to {ip_dst}:{dport}"
    
    if msg:
        send_alert(msg)
        return

    if flags == 'S': 
        port_set = scan_tracker[ip_src][ip_dst]
        port_set.add(dport)
        
        if len(port_set) > PORT_SCAN_THRESHOLD:
            msg = f"[ALERT] POTENTIAL PORT SCAN DETECTED from {ip_src} to {ip_dst}! ({len(port_set)} unique ports)"
            send_alert(msg)
            port_set.clear()

# --- SCAPY CALLBACK ---

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    # [FIX 4] Anti-Loop Logic: 
    # Explicitly ignore any TCP traffic involving port 5000 (Flask).
    # This acts as a backup even if the BPF filter fails.
    if packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        if tcp.sport == 5000 or tcp.dport == 5000:
            return 

    ip_layer = packet.getlayer(IP)
    ip_src = ip_layer.src
    ip_dst = ip_layer.dst
    proto = None

    if packet.haslayer(TCP):
        proto = "TCP"
        tcp_layer = packet.getlayer(TCP)
        detect_port_scan(packet, ip_src, ip_dst, tcp_layer.dport, tcp_layer.flags)
    elif packet.haslayer(UDP):
        proto = "UDP"
    elif packet.haslayer('ICMP'):
        proto = "ICMP"

    if proto:
        with data_lock:
            packet_counts[proto] += 1
            # Note: We don't rate limit packet counts, only alerts.
            # But we are inside a thread, so this emit is non-blocking.
            socketio.emit('packet_update', dict(packet_counts))
            
    check_signatures(packet)

# --- FLASK ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

# --- MAIN ---

def main():
    print("Starting NIDS Web Dashboard with Secure Logging...")
    
    # BPF Filter: Primary defense against feedback loops
    bpf_filter = "not port 5000"
    print(f"Starting Scapy sniffer on 'lo' with filter: '{bpf_filter}'")
    
    try:
        sniffer_thread = threading.Thread(
            target=lambda: sniff(iface="lo", prn=packet_callback, store=0, filter=bpf_filter),
            daemon=True
        )
        sniffer_thread.start()
    except PermissionError:
        print("\n[FATAL ERROR] Permission denied. Scapy sniffer thread failed.")
        print("Please run this script with 'sudo -E python3 nids.py'\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Sniffer thread crashed: {e}")
        sys.exit(1)

    print("Web server starting... Open the URL in your 'PORTS' tab.")
    # host='0.0.0.0' allows external access (required for GitHub Codespaces)
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Dashboard stopped by user. Exiting.")
        sys.exit(0)