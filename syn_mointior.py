from scapy.all import sniff, TCP, UDP, ICMP, IP, ARP, Ether, conf
from colorama import Fore, Style
import logging
import time
import os
import threading
import sys

# ========================
# Logging Setup
# ========================
logging.basicConfig(
    filename="sniffer.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ========================
# Packet Sniffer Class
# ========================
class PacketSniffer:

    def __init__(self, iface=None):
        self.iface = iface or conf.iface 
        self.serial = os.urandom(8).hex()
        self.packet_count = 0

        print(Fore.YELLOW + f"[+] Using Interface: {self.iface}" + Style.RESET_ALL)
        print(Fore.GREEN + "[+] Sniffer Ready!" + Style.RESET_ALL)

    # --------------------------
    # Print Layer Information
    # --------------------------
    def show_packet(self, pkt):

        self.packet_count += 1
        print(Fore.CYAN + f"\n[#] Packet #{self.packet_count}" + Style.RESET_ALL)

        # ============================
        # Ethernet Layer
        # ============================
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            print(Fore.LIGHTCYAN_EX + 
                  f"[*] Ether: {eth.src}  ->  {eth.dst} | Type: {eth.type}" 
                  + Style.RESET_ALL)
            logging.info(f"Ether Layer: {eth.src} -> {eth.dst}, type={eth.type}")

        # ============================
        # IP Layer
        # ============================
        if pkt.haslayer(IP):
            ip = pkt[IP]
            print(Fore.LIGHTMAGENTA_EX + 
                  f"[*] IP: {ip.src}  ->  {ip.dst} | TTL:{ip.ttl} | Proto:{ip.proto}" 
                  + Style.RESET_ALL)

            logging.info(f"IP Layer: {ip.src} -> {ip.dst}, proto={ip.proto}, ttl={ip.ttl}")

            seq_num = None

            # ----------------------------
            # TCP Layer
            # ----------------------------
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                seq_num = tcp.seq

                print(Fore.LIGHTBLUE_EX +
                      f"    [TCP] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} | "
                      f"Flags:{tcp.flags} | Seq:{tcp.seq} | Ack:{tcp.ack}" 
                      + Style.RESET_ALL)

                logging.info(f"TCP Layer: seq={tcp.seq}, ack={tcp.ack}, flags={tcp.flags}")

            # ----------------------------
            # UDP Layer
            # ----------------------------
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                print(Fore.LIGHTGREEN_EX +
                      f"    [UDP] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
                      + Style.RESET_ALL)
                logging.info("UDP Layer detected")

            # ----------------------------
            # ICMP Layer
            # ----------------------------
            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                print(Fore.LIGHTYELLOW_EX +
                      f"    [ICMP] Type:{icmp.type} Code:{icmp.code}"
                      + Style.RESET_ALL)

                logging.info("ICMP Layer detected")

            # Return structured info


        # ============================
        # ARP Layer
        # ============================
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            print(Fore.YELLOW +
                  f"[*] ARP: {arp.psrc} is asking about {arp.pdst}"
                  + Style.RESET_ALL)
            logging.info("ARP Packet Detected")

        return None
    def return_packet_info(self, pkt, seq_num=None):
        info = {
            "serial": self.serial,
            "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
            "dst_mac": pkt[Ether].dst if pkt.haslayer(Ether) else None,
            "src_ip": pkt[IP].src if pkt.haslayer(IP) else None,
            "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else None,
            "protocol": None,
            "seq_num": seq_num
        }

        return info
    # --------------------------
    # Start Sniffing
    # --------------------------
#########################################################################3
Instance = PacketSniffer()
def start(self):
        print(Fore.GREEN + "\n[+] Sniffer Started...\n" + Style.RESET_ALL)
        sniff(iface=self.iface, prn=self.show_packet, store=False)
        threading.Thread(target=Instance.return_packet_info).start()

# ========================
# Main Execution
# ========================
if __name__ == "__main__":
    print(Fore.RED + "main monitor interrupted..." + Style.RESET_ALL)
    print(Fore.YELLOW + "starting synced monitor..." + Style.RESET_ALL)
    time.sleep(2)
    print(Fore.GREEN + "Synced monitor started successfully" + Style.RESET_ALL)
    if KeyboardInterrupt:
        Instance.return_packet_info()
    sniffer = PacketSniffer()
    sniffer.start()
