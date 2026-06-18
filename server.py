from flask import Flask, jsonify, send_from_directory
from scapy.all import sniff, IP
from collections import Counter, deque
from datetime import datetime
import threading

# Point Flask precisely to your current project folder
app = Flask(__name__, static_folder='.', template_folder='.')

# Fast in-memory array to store packets without hitting the SD card
packet_buffer = deque(maxlen=200)

def live_packet_sniffer():
    """Background thread that captures live packets on eth0 safely."""
    def process_packet(pkt):
        if IP in pkt:
            packet_buffer.append(pkt)

    while True:
        try:
            # 2-second timeout windows keeps the thread highly responsive
            sniff(iface="eth0", prn=process_packet, store=0, timeout=2)
        except Exception as e:
            print(f"Sniffer error: {e}")

@app.route("/api/traffic")
def get_traffic():
    try:
        packet_log = []
        devices = {}
        protocols = Counter()

        # Snapshot the current RAM buffer
        current_packets = list(packet_buffer)

        for pkt in current_packets:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto_num = pkt[IP].proto

            if proto_num == 6: proto = "TCP"
            elif proto_num == 17: proto = "UDP"
            elif proto_num == 1: proto = "ICMP"
            else: proto = "OTHER"

            protocols[proto] += 1
            
            # Match the exact dictionary syntax your frontend script parses
            packet_log.append({
                "time": datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                "source": src,
                "destination": dst,
                "protocol": proto,
                "size": round(len(pkt) / 1024, 2),
                "status": "ALLOWED"
            })
            devices[src] = True
            devices[dst] = True

        # Return the exact keys script.js needs to render tables and graphs
        return jsonify({
            "packet_count": len(packet_log),
            "packets": packet_log[-100:],  # Send the latest 100 packets to fill log rows
            "devices": list(devices.keys()),
            "protocols": dict(protocols)
        })

    except Exception as e:
        return jsonify({"error": str(e), "packets": [], "packet_count": 0})

# --- Web Server Asset Core Endpoints ---
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/script.js")
def javascript():
    return send_from_directory(".", "script.js")

@app.route("/styles.css")
def styles():
    return send_from_directory(".", "styles.css")

if __name__ == "__main__":
    # Fire up the background sniffer engine
    sniffer_thread = threading.Thread(target=live_packet_sniffer, daemon=True)
    sniffer_thread.start()
    
    # Run the webapp with full multi-threading enabled
    app.run(host="0.0.0.0", port=5000, threaded=True)
