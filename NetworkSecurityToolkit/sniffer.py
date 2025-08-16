import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

# --- FEATURE 1: Protocol Name Resolution ---
# A dictionary to map common port numbers to their protocol names
protocol_map = {
    20: "FTP-Data", 21: "FTP-Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    179: "BGP", 443: "HTTPS", 514: "Syslog", 3389: "RDP"
}

# --- FEATURE 2: Anomaly Detection ---
# Threshold: If we see more than this many packets from one IP in our time window, we'll alert.
PACKET_THRESHOLD = 50 
TIME_WINDOW = 10  # in seconds
# Dictionary to store packet counts for each source IP.
# defaultdict(int) means if a key doesn't exist, it's created with a value of 0.
packet_counts = defaultdict(int)
# Keep track of the start time of the current window
window_start_time = time.time()

def process_packet(packet):
    """
    This function now also identifies protocols and detects anomalies.
    """
    global window_start_time, packet_counts

    # Check if the current time window has expired
    if time.time() - window_start_time > TIME_WINDOW:
        print(f"\n--- Resetting counts for new {TIME_WINDOW}s window ---")
        # Reset the counts and the timer
        packet_counts.clear()
        window_start_time = time.time()

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        # Increment the packet count for this source IP
        packet_counts[source_ip] += 1
        
        # --- Anomaly Detection Check ---
        if packet_counts[source_ip] > PACKET_THRESHOLD:
            print(f"🚨 SECURITY ALERT: High traffic detected from {source_ip} ({packet_counts[source_ip]} packets in <{TIME_WINDOW}s) 🚨")

        protocol_name = "Unknown"
        
        if packet.haslayer(TCP):
            dest_port = packet[TCP].dport
            # Look up the protocol name from our map, default to the port number if not found
            protocol_name = protocol_map.get(dest_port, f"Port {dest_port}")
            print(f"[TCP] {source_ip} -> {destination_ip} (Service: {protocol_name})")
            
        elif packet.haslayer(UDP):
            dest_port = packet[UDP].dport
            protocol_name = protocol_map.get(dest_port, f"Port {dest_port}")
            print(f"[UDP] {source_ip} -> {destination_ip} (Service: {protocol_name})")

def main():
    print("Starting Intelligent Network Monitor...")
    print(f"Alerting on >{PACKET_THRESHOLD} packets/IP within a {TIME_WINDOW}s window.")
    print("Press Ctrl+C to stop.")
    try:
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] Monitor stopped by user.")

if __name__ == '__main__':
    main()