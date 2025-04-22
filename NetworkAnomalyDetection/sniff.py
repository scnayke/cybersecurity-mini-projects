from scapy.all import sniff, get_if_list, conf
from detection import analyze_packet
from datetime import datetime
import argparse
import platform
import socket

# Parse CLI arguments
parser = argparse.ArgumentParser(description="Lightweight Network Anomaly Detector")
parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on (e.g., eth0, wlan0, \\Device\\NPF_{GUID})")
parser.add_argument("--threshold", type=int, default=500, help="Traffic volume threshold for anomaly detection")
args = parser.parse_args()

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def select_interface():
    """Select a network interface based on local IP."""
    local_ip = get_local_ip()
    if not local_ip:
        print("❌ Unable to determine local IP. Specify --iface manually.")
        return None

    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            for iface in interfaces:
                for ip in iface.get('ips', []):
                    if ip == local_ip:
                        return f"\\Device\\NPF_{iface['guid']}"
            print(f"⚠️ No Windows interface with IP {local_ip} found, falling back to get_if_list")
        except (ImportError, AttributeError):
            print("⚠️ get_windows_if_list not available, falling back to get_if_list")
        interfaces = get_if_list()
        if interfaces:
            return interfaces[0]
    else:  # Linux or other OS
        interfaces = get_if_list()
        for iface in interfaces:
            try:
                if conf.ifaces.dev_from_name(iface).ip == local_ip:
                    return iface
            except Exception:
                continue
        if interfaces:
            return interfaces[0]

    print("❌ No network interfaces found. Run 'python -c \"from scapy.all import get_if_list; print(get_if_list())\"' to list interfaces.")
    return None

def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[DEBUG] Packet captured: {packet.summary()}")  # Debug to confirm capture
    analyze_packet(packet, timestamp, args.threshold)

if __name__ == "__main__":
    # Default interface selection
    if args.iface is None:
        args.iface = select_interface()
        if args.iface is None:
            exit(1)
        print(f"ℹ️ Auto-selected interface: {args.iface}")

    print(f"🚀 Starting packet capture on interface '{args.iface}'... Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, iface=args.iface, store=False)  # Capture all packets
    except KeyboardInterrupt:
        print("\n🛑 Packet capture stopped.")
    except Exception as e:
        print(f"\n❌ Error during packet capture: {e}")