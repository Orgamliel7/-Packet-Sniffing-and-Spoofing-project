#!/usr/bin/env python3

import logging
# מורכב ואמין, דו צדדי, עם קונג'סטשן קונטרול שמאט את הקצב בכדי לא להעמיס
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def print_pkt(pkt):
	print("Source IP:", pkt[IP].src)
	print("Destination IP:", pkt[IP].dst)
	print("Protocol:", pkt[IP].proto)
	print("\n")
	pkt.show()
	print("\n")


print("Start sniffing")
pkt = sniff(filter='tcp and dst port 23', prn=print_pkt) # the usage of 23 is for Telnet - Remote login service, unencrypted text messages

