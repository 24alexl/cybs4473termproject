# nids.py (Updated to include SecureLogger)

import sys
import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, Raw
from flask import Flask, render_template
from flask_socketio import SocketIO

# --- NEW: IMPORT THE LOGGER ---
from secure_logger import SecureLogger

# --- Flask & SocketIO Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key!'
socketio = SocketIO(app, async_mode='threading')

# --- NEW: INITIALIZE THE LOGGER ---
logger = SecureLogger()

# --- Data Storage ---
packet_counts = defaultdict(int)
data_lock = threading.Lock()

# --- DETECTION ENGINE (Functions) ---
MALICIOUS_SIGNATURES = [
    b"ncat -e /bin/bash",
    b"cmd.exe",
    b"powershell.exe",
]

def send_alert(message):
    """
    Helper function to print, send to web, AND send to secure log.
    """
    print(message) 
    socketio.emit('alert', {'message': message})
    
    # --- NEW: LOG THE ALERT ---
    logger.log_alert(message)


# (Rest of the detection functions are unchanged)
def check_signatures(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        for sig in MALICIOUS_SIGNATURES:
            if sig in payload:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                msg = f"[ALERT] MALICIOUS SIGNATURE from {ip_src} to {ip_dst}: {sig.decode(errors='ignore')}"
                send_alert(msg)
                
scan_tracker = defaultdict(lambda: defaultdict(set))
PORT_SCAN_THRESHOLD = 10 

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

# --- Scapy Sniffing Logic (Unchanged) ---
def packet_callback(packet):
    proto = None
    if not packet.haslayer(IP):
        return

    ip_layer = packet.getlayer(IP)
    ip_src = ip_layer.src
    ip_dst = ip_layer.dst

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
        with data_lock:
            socketio.emit('packet_update', dict(packet_counts))
    check_signatures(packet)

# --- Flask Web Server Routes (Unchanged) ---
@app.route('/')
def index():
    return render_template('index.html')

# --- Main Function (Unchanged from last fix) ---
def main():
    print("Starting NIDS Web Dashboard with Secure Logging...")
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
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Dashboard stopped by user. Exiting.")
        sys.exit(0)