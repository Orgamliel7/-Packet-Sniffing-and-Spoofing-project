#!/usr/bin/env python3

# מונח של שכבת הרשת . מסכת רשת מגדירה כמה ביטים מתוך כתובת האיי-פי מייצגים את מזהה הרשת

import logging
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
pkt = sniff(filter='net 128.230.0.0/16', prn=print_pkt)

