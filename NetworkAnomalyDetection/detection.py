from scapy.all import IP, TCP, UDP, ARP, DNS, Ether
from collections import defaultdict, Counter
import time
import logging

# Setup logging to file for dashboard
logging.basicConfig(filename='anomalies.log', level=logging.INFO, format='%(message)s')

# Data structures for tracking
traffic_counter = defaultdict(int)  # Tracks packets per source IP
port_counter = defaultdict(lambda: defaultdict(int))  # Tracks destination ports per source IP
arp_table = {}  # Tracks IP-to-MAC mappings for ARP spoofing
mac_counter = defaultdict(int)  # Tracks packets per MAC for MAC flooding
dns_requests = defaultdict(list)  # Tracks DNS queries for tunneling
packet_timestamps = []  # Tracks packet timestamps for spike detection
broadcast_counter = defaultdict(int)  # Tracks broadcast packets

# Configuration
SUSPICIOUS_PORTS = [23, 31337, 6667, 4444]  # Telnet, backdoors, IRC, etc.
STANDARD_PROTOCOLS = [6, 17]  # TCP, UDP
TRAFFIC_THRESHOLD = 500  # Default packets per IP
SPIKE_WINDOW = 10  # Seconds for traffic spike detection
SPIKE_THRESHOLD = 1000  # Tune based on network
PORT_SCAN_THRESHOLD = 10  # Different ports targeted by single IP
MAC_FLOOD_THRESHOLD = 1000  # Tune based on network
BROADCAST_THRESHOLD = 50  # Broadcast packets in window
DNS_TUNNEL_THRESHOLD = 1000  # Bytes in DNS query

def analyze_packet(packet, timestamp, threshold):
    global packet_timestamps
    TRAFFIC_THRESHOLD = threshold

    # Log anomaly to file
    def log_anomaly(message):
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        logging.info(log_message)

    # Update packet timestamps for spike detection
    current_time = time.time()
    packet_timestamps = [t for t in packet_timestamps if current_time - t < SPIKE_WINDOW]
    packet_timestamps.append(current_time)

    # Traffic spike detection
    if len(packet_timestamps) > SPIKE_THRESHOLD:
        log_anomaly("⚠️ Traffic spike detected: High packet rate")

    # Default src_ip for non-IP packets
    src_ip = "Unknown"

    # IP layer analysis
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto
        traffic_counter[src_ip] += 1

        # Unusual traffic volume
        if traffic_counter[src_ip] > TRAFFIC_THRESHOLD:
            log_anomaly(f"⚠️ High traffic volume from {src_ip} (Count: {traffic_counter[src_ip]})")

        # Non-standard protocols
        if proto not in STANDARD_PROTOCOLS:
            log_anomaly(f"⚠️ Non-standard protocol used: {proto} from {src_ip}")

        # Suspicious ports and port scans
        if TCP in packet or UDP in packet:
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            port_counter[src_ip][dst_port] += 1

            if dst_port in SUSPICIOUS_PORTS:
                log_anomaly(f"🚨 Suspicious port activity: {dst_port} from {src_ip}")

            # Port scan detection
            if len(port_counter[src_ip]) > PORT_SCAN_THRESHOLD:
                log_anomaly(f"🚨 Possible port scan from {src_ip}: {len(port_counter[src_ip])} ports targeted")

        # DNS tunneling detection
        if UDP in packet and DNS in packet and packet[UDP].dport == 53:
            dns_query = packet[DNS].qd.qname if packet[DNS].qd else b""
            dns_requests[src_ip].append(len(str(dns_query)))
            if sum(dns_requests[src_ip][-10:]) > DNS_TUNNEL_THRESHOLD:
                log_anomaly(f"🚨 Possible DNS tunneling from {src_ip}: Large query sizes")

        # Malformed packets (basic check)
        if packet[IP].len < 20 or (TCP in packet and packet[TCP].dataofs < 5):
            log_anomaly(f"🚨 Malformed packet detected from {src_ip}")

    # ARP detection
    if ARP in packet:
        # Optional debug for ARP packets
        # print(f"[DEBUG] ARP packet captured: op={packet[ARP].op}, psrc={packet[ARP].psrc}, hwsrc={packet[ARP].hwsrc}")
        if packet[ARP].op == 2:  # ARP reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            log_anomaly(f"⚠️ ARP Reply from {ip} with MAC {mac}")
            if ip in arp_table and arp_table[ip] != mac:
                log_anomaly(f"🚨 Possible ARP spoofing: {ip} mapped to {mac}, previously {arp_table[ip]}")
            arp_table[ip] = mac

    # MAC flooding and broadcast storms
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        mac_counter[src_mac] += 1

        # MAC flooding detection
        if mac_counter[src_mac] > MAC_FLOOD_THRESHOLD:
            log_anomaly(f"🚨 Possible MAC flooding from {src_mac} (Count: {mac_counter[src_mac]})")

        # Broadcast storm detection
        if dst_mac == "ff:ff:ff:ff:ff:ff":
            broadcast_counter[src_ip] += 1
            if broadcast_counter[src_ip] > BROADCAST_THRESHOLD:
                log_anomaly(f"🚨 Broadcast storm detected from {src_ip} (Count: {broadcast_counter[src_ip]})")

    # Unexpected protocols/ports (only for IP packets with raw data)
    if IP in packet and packet.haslayer("Raw") and not (TCP in packet or UDP in packet):
        log_anomaly(f"⚠️ Unexpected protocol or raw data from {src_ip}")