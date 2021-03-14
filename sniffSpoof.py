#!/usr/bin/python3


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def send_pkt(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
		print("\n")
		print("Original packet.")
		print("source IP: ", pkt[IP].src)
		print("Destination IP: ", pkt[IP].dst)
		print("\n")
		p = copy.deepcopy(pkt[IP]) # העתקה עמוקה כולל מצביעים וכו' מאחורי הקלעים
		p.src = pkt[IP].dst # המקור של פי הוא היעד של הפקטה ולהפך
		p.dst = pkt[IP].src
		p[ICMP].type = 0
		print("Spoofed packet...")
		print("source IP: ", p.src)
		print("Destination IP: ", p.dst)
		print("\n")
		send(p,verbose=0)

print("Start sniffing")
pkt = sniff(filter='icmp',prn=send_pkt) 
