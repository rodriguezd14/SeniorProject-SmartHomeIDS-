from scapy.all import rdpcap, IP
from collections import Counter
import json

def analyze_pcap(filename):
    packets = rdpcap(filename)

    packet_log = []
    protocol_counts = Counter()
    devices = {}

    for pkt in packets:

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

            proto_num = pkt[IP].proto

            protocols = {
                1: "ICMP",
                6: "TCP",
                17: "UDP"
            }

            protocol = protocols.get(proto_num, "OTHER")

            protocol_counts[protocol] += 1

            size = len(pkt)

            packet_log.append({
                "time": str(pkt.time),
                "source": src,
                "destination": dst,
                "protocol": protocol,
                "size": round(size / 1024, 2),
                "status": "ALLOWED"
            })

            if src not in devices:
                devices[src] = {
                    "id": len(devices) + 1,
                    "name": f"Host-{len(devices)+1}",
                    "ip": src,
                    "status": "Normal"
                }

            if dst not in devices:
                devices[dst] = {
                    "id": len(devices) + 1,
                    "name": f"Host-{len(devices)+1}",
                    "ip": dst,
                    "status": "Normal"
                }

    results = {
        "devices": list(devices.values()),
        "packets": packet_log[-500:],
        "protocols": protocol_counts,
        "packet_count": len(packet_log)
    }

    with open("traffic_data.json", "w") as f:
        json.dump(results, f, indent=4)

    print(f"Processed {len(packet_log)} packets")


if __name__ == "__main__":
    analyze_pcap("capture.pcap")
