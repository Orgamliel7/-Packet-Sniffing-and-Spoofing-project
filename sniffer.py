#!/usr/bin/env python3



#רַחְרְחַן מָנוֹת - תוכנה/חומרה המאפשרת להאזין ולתעד תקשורת מחשבים העוברת בנקודה כלשהי ברשת. הסניפר קולט את חבילות מידע היוצרות את התקשורת,
# מנתח אותן בהתאם למסמכי הבקשה להערות הרלוונטי ומציג אותן למשתמש

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def print_pkt(pkt):   #  הדפסת פקטה
	print("Source IP:", pkt[IP].src)
	print("Destination IP:", pkt[IP].dst)
	print("Protocol:", pkt[IP].proto)
	print("\n")
	pkt.show()
	print("\n")


print("Start sniffing")
pkt = sniff(iface='enp0s3', filter='icmp', prn=print_pkt)

