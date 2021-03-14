#!/usr/bin/env python3

# לשלוח הודעות שגיאה או לספק אבחון למנהלי רשת ע”י הצגת הודעות בעת ביצוע פעולות מסוימות, לדוג' פינג או טרייסראוט
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
pkt = sniff(filter='icmp', prn=print_pkt)

