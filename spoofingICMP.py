#!/usr/bin/env python3
# לשלוח הודעות שגיאה או לספק אבחון למנהלי רשת ע”י הצגת הודעות בעת ביצוע פעולות מסוימות, לדוג' פינג או טרייסראוט

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

a = IP()
a.dst = '10.0.2.3'
a.src = '10.10.10.10'
b = ICMP()
p = a/b
send(p)

