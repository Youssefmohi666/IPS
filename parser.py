# parser file 
# import matplotlib
import re 
import logging
import pandas as pd
import subprocess
import syn_mointior as sm
# import engine.cpp as eng

arp_table =  sm.command 
def parseing_arp(arp_table=arp_table):
    arp_entries = []
    current_interface = None

    for line in arp_table.splitlines():
        interface_match = re.match(r'Interface:\s+([\d\.]+)\s+---\s+0x[0-9a-fA-F]+', line)
        if interface_match:
            current_interface = interface_match.group(1)
            continue

        entry_match = re.match(r'\s*([\d\.]+)\s+([0-9a-fA-F\-]+)\s+(\w+)', line)
        if entry_match and current_interface:
            ip_address = entry_match.group(1)
            mac_address = entry_match.group(2)
            entry_type = entry_match.group(3)

            arp_entries.append({
                'Interface': current_interface,
                'IP Address': ip_address,
                'MAC Address': mac_address,
                'Type': entry_type
            })

    df = pd.DataFrame(arp_entries)
    return df

