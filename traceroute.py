#!/usr/bin/python3

# כלי שמיושם ע"י שידור חבילת אייסיאםפי או יודיפי עם שדות זמן חיים ספציפיות ובדיקת הודעות חוזרות לבדיקת חריגה בזמנים או יעד לא נגיש. ע"י הד והד תשובה
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

i = 1
while i <= 17:
  a = IP()
  a.dst = '142.250.185.110' #found through nslookup google.com
  a.ttl = i
  b = ICMP()
  reply = sr1(a/b, timeout = 5, verbose = 0)
#sr1 function is part of the send and receive packets function and only returns the #packet that answered.

  if reply is None:
    print("%2d *"%i)
  elif reply.type == 0:
    print("%2d "%i, reply.src)
    break
  else:
    print("%2d " %i, reply.src)
  
  i = i + 1
