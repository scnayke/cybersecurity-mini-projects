from scapy.all import sniff
from detection import analyze_packet
from datetime import datetime
import argparse

# Parse CLI arguments
parser = argparse.ArgumentParser(description="Lightweight Network Anomaly Detector")
parser.add_argument("--iface", type=str, default="any", help="Network interface to sniff on (e.g., eth0, wlan0, or any)")
parser.add_argument("--threshold", type=int, default=500, help="Traffic volume threshold for anomaly detection")
args = parser.parse_args()

def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    analyze_packet(packet, timestamp, args.threshold)

if __name__ == "__main__":
    print("🚀 Starting packet capture on interface '{}'... Press Ctrl+C to stop.".format(args.iface))
    try:
        sniff(prn=packet_callback, iface=args.iface, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Packet capture stopped.")
    except Exception as e:
        print(f"\n❌ Error during packet capture: {e}")
