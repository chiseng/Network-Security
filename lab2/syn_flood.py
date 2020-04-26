from scapy.all import *

def sniffer(pkt):
	if pkt:
		print("SYN-ACK received")

pkt = sniff(filter="tcp",prn=sniffer)
