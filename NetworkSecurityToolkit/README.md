

This project is a Python-based network security suite designed for educational purposes. It demonstrates a Man-in-the-Middle (MitM) attack using ARP spoofing and provides tools for both analyzing the intercepted traffic and actively defending against such attacks.


---

## ## Description

This project provides a hands-on experience with fundamental network security concepts at Layer 2. It contains a set of command-line tools that allow a user to simulate an ARP spoofing attack, harvest unencrypted credentials, and detect and actively counter the attack in real-time. The primary goal is to highlight the vulnerabilities in the ARP protocol and understand the mechanisms for defense.



---

## ## Features

* **ARP Spoofer:** Redirects network traffic from a target device to the user's machine by poisoning the ARP cache of both the target and the gateway.
* **Credential Harvester:** A passive sniffer that analyzes the intercepted traffic to detect and extract usernames and passwords from unencrypted HTTP POST requests.
* **Active Defender:** An ARP spoofing detection tool that not only alerts the user of an attack but also actively fights back by broadcasting corrective ARP packets to restore the network's integrity.

---

## ## ⚠️ Disclaimer

This tool is intended for **educational and research purposes only**. Do not use it on any network that you do not own or have explicit permission to test. Unauthorized use of this tool on a network is illegal. The author is not responsible for any misuse or damage caused by this program.

---

## ## Prerequisites

* Python 3.8+
* Scapy (`pip install scapy`)

---

## ## Installation & Setup

1.  **Clone the repository:**

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Enable IP Forwarding (Crucial for MitM):**
    This allows your machine to forward intercepted packets instead of dropping them.

    * **Linux:**
        ```bash
        sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
        ```
    * **macOS:**
        ```bash
        sudo sysctl -w net.inet.ip.forwarding=1
        ```
    * **Windows (Administrator PowerShell):**
        ```powershell
        Set-NetIPInterface -Forwarding Enabled
        ```

---

## ## Usage

All scripts must be run with `sudo` or as an Administrator. Before running, you must configure the IP addresses inside the scripts (`target_ip`, `gateway_ip`).

#### **1. To Perform the MitM Attack & Harvest Credentials:**

This requires two terminals.

* **Terminal 1: Run the Spoofer**
    ```bash
    sudo python3 arp_spoofer.py
    ```
    *Output:*
    `[*] Starting ARP spoofer... Press Ctrl+C to stop and restore.`
    `[+] Packets sent: 2`

* **Terminal 2: Run the Harvester**
    ```bash
    sudo python3 harvester.py
    ```
    *Output:*
    `[*] Starting Credential Harvester...`
    `[*] Waiting for HTTP POST requests...`

Now, generate traffic on the target machine by logging into an HTTP website. The harvester terminal will display any captured credentials.

#### **2. To Defend a Machine:**

Run the active defender on the machine you want to protect.

* **On the Target/Protected Machine:**
    ```bash
    sudo python3 active_defender.py
    ```
    *Output:*
    `[*] Starting Active ARP Defender...`
    `[*] Real gateway MAC address is: XX:XX:XX:XX:XX:XX`

    If an attack is launched, it will immediately detect it and begin countermeasures.
    *Output upon attack:*
    `[!] ALERT: YOU ARE UNDER ATTACK!`
    `[+] Sent corrective ARP broadcast: 192.168.1.1 is at XX:XX:XX:XX:XX:XX`

---

## ## How It Works

* **ARP Spoofing:** The spoofer sends forged ARP "reply" packets to the target and the gateway, convincing them that the attacker's machine is the other party. This redirects the traffic flow.
* **Active Defense:** The defender establishes a "ground truth" for the gateway's MAC address and sniffs for any ARP packets that contradict this truth. Upon detection, it broadcasts the correct ARP information to the entire network, overwriting the attacker's malicious entries.

---

## ## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
