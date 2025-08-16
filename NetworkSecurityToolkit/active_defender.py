import scapy.all as scapy
import time

def get_mac(ip):
    """
    Gets the real MAC address for a given IP.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def send_correction_arp(gateway_ip, gateway_mac):
    """
    Sends a corrective ARP packet to the entire network (broadcast).
    """
    # We create a legitimate ARP reply and send it to the broadcast MAC address
    # This tells every device on the network the correct IP-MAC mapping.
    packet = scapy.ARP(op=2, pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(packet, verbose=False)
    print(f"[+] Sent corrective ARP broadcast: {gateway_ip} is at {gateway_mac}")

def process_packet(packet, gateway_ip, real_gateway_mac):
    """
    Detects spoofing and triggers the active defense.
    """
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            # Check if the ARP reply is about our gateway
            if packet[scapy.ARP].psrc == gateway_ip:
                response_mac = packet[scapy.ARP].hwsrc
                
                # If the MAC in the packet is not the real one, we are under attack!
                if real_gateway_mac != response_mac:
                    print("\n" + "="*50)
                    print("[!] ALERT: YOU ARE UNDER ATTACK!")
                    print(f"[!] Real Gateway MAC: {real_gateway_mac}")
                    print(f"[!] Fake Gateway MAC from Attacker: {response_mac}")
                    
                    # --- ACTIVE DEFENSE ---
                    send_correction_arp(gateway_ip, real_gateway_mac)
                    print("="*50)
        except IndexError:
            pass

def main():
    # --- IMPORTANT: Set your router's IP here ---
    gateway_ip = "192.168.0.1" 
    
    print("[*] Starting Active ARP Defender...")
    print(f"[*] Monitoring for attacks targeting gateway: {gateway_ip}")
    
    real_gateway_mac = get_mac(gateway_ip)
    if not real_gateway_mac:
        print(f"[-] Could not determine real MAC for {gateway_ip}. Exiting.")
        return
        
    print(f"[*] Real gateway MAC address is: {real_gateway_mac}")
    
    # Sniff for ARP packets and pass extra arguments to our callback function
    scapy.sniff(filter="arp", store=False, prn=lambda p: process_packet(p, gateway_ip, real_gateway_mac))

if __name__ == "__main__":
    main()