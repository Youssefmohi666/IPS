import re

LOG_FILE = "sniffer.log"

def parse_log(file_path):
    packets = []
    with open(file_path, "r") as f:
        lines = f.readlines()

    current_packet = {}
    for line in lines:
        if "Ether Layer:" in line:
            match = re.search(r'Ether Layer: (.+) -> (.+), type=(.+)', line)
            if match:
                current_packet["src_mac"] = match.group(1)
                current_packet["dst_mac"] = match.group(2)
                current_packet["eth_type"] = match.group(3)
        elif "IP Layer:" in line:
            match = re.search(r'IP Layer: (.+) -> (.+), proto=(.+), ttl=(.+)', line)
            if match:
                current_packet["src_ip"] = match.group(1)
                current_packet["dst_ip"] = match.group(2)
                current_packet["protocol"] = match.group(3)
                current_packet["ttl"] = match.group(4)
        elif "TCP Layer:" in line:
            match = re.search(r'TCP Layer: seq=(.+), ack=(.+), flags=(.+)', line)
            if match:
                current_packet["tcp_seq"] = match.group(1)
                current_packet["tcp_ack"] = match.group(2)
                current_packet["tcp_flags"] = match.group(3)
        elif "UDP Layer detected" in line:
            current_packet["udp"] = True
        elif "ICMP Layer detected" in line:
            current_packet["icmp"] = True
        elif "ARP Packet Detected" in line:
            current_packet["arp"] = True

        if "Ether Layer:" in line and current_packet:
            if current_packet not in packets:
                packets.append(current_packet)
            current_packet = {}

    return packets

def main():
    parsed_packets = parse_log(LOG_FILE)
    print(f"Total Packets Parsed: {len(parsed_packets)}\n")
    for i, pkt in enumerate(parsed_packets, 1):
        print(f"Packet #{i}: {pkt}")

if __name__ == "__main__":
    main()
