from scapy.all import sniff, ARP

def arp_spoof_detector(packet):
    """
    Callback function to detect ARP spoofing.
    It's called for every packet sniffed.
    """
    # We are only interested in ARP packets. 'op=2' means it's an ARP "is-at" reply.
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        
        print(f"[DEBUG] ARP Reply Captured: IP {packet[ARP].psrc} is at MAC {packet[ARP].hwsrc}")
        
        try:
            # The real MAC address of the gateway that you saved.
            # ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
            trusted_gateway_mac = ""  # <-- PASTE YOUR ROUTER'S MAC ADDRESS HERE
            # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

            # The real IP address of the gateway.
            # ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
            trusted_gateway_ip = ""      # <-- PASTE YOUR ROUTER'S IP ADDRESS HERE
            # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

            # Extract the source MAC and IP from the captured ARP packet
            response_mac = packet[ARP].hwsrc
            response_ip = packet[ARP].psrc

            # Check if the packet is about the gateway
            if response_ip == trusted_gateway_ip:
                # If the packet's MAC address doesn't match our trusted one, it's a spoof!
                if response_mac != trusted_gateway_mac:
                    print(f"[*] ALERT! ARP Spoofing Detected!")
                    print(f"[*] Your gateway {trusted_gateway_ip} is being impersonated by MAC {response_mac}.")
                    print(f"[*] The legitimate MAC address is {trusted_gateway_mac}.")

        except IndexError:
            # Ignore malformed packets
            pass

# --- Main part of the script ---
print("🚀 Starting ARP Spoof Detector... (Press CTRL+C to stop)")
# Start sniffing. 'store=0' saves memory, 'prn' specifies our callback function.
# 'filter="arp"' makes sniffing much more efficient.

sniff(store=0, prn=arp_spoof_detector, filter="arp", iface="Intel(R) Wi-Fi 6E AX211 160MHz")
