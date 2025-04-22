from scapy.all import ARP, Ether, sendp
from scapy.all import get_if_list, conf
import platform
import socket

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
        print("❌ Unable to determine local IP.")
        return None

    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            for iface in interfaces:
                for ip in iface.get('ips', []):
                    if ip == local_ip:
                        return f"\\Device\\NPF_{iface['guid']}"
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

    print("❌ No network interfaces found. Run 'python -c \"from scapy.all import get_if_list; print(get_if_list())\"'")
    return None

# Configuration
iface = select_interface()
if iface is None:
    exit(1)
target_ip = "192.168.1.1"  # Router IP (adjust if needed)

# Create ARP request packet
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

# Send ARP request
print(f"Sending ARP ping to {target_ip} on interface {iface}...")
sendp(packet, iface=iface, count=4, inter=1)

print("ARP ping sent.")