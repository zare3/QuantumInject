from scapy.all import *
import socket               # Import socket module
from copy import deepcopy
import threading
import re


interface = 'wlan0'

expression = 'tcp port http'


MAX_SIZE = 50
packetLenWithoutLoad = 32
previousPackets = [ ]


def isAForgedPacket(pkt):
	if hasattr(pckt.getlayer('TCP'), 'load'):
		for prevPkt in previousPackets:
			if prevPkt[IP].dst == pkt[IP].dst and prevPkt[IP].src == pkt[IP].src and\
			prevPkt[TCP].sport == pkt[TCP].sport and prevPkt[TCP].dport == pkt[TCP].dport and\
			prevPkt[TCP].seq = pkt[TCP].seq and prevPkt[TCP].ack = pkt[TCP].ack and\
			len(prevPkt[TCP]) > packetLenWithoutLoad and len(pkt[TCP]) > packetLenWithoutLoad and\
			prevPkt[TCP].payload != pkt[TCP].payload:
				print "ATTACK HAS BEEN FOUND AT: "
				print "ORIGINAL PACKET: "
				prevPkt.show()
				print "FORGET PACKET: "
				pkt.show()
		previousPackets.append(pkt)





packets = sniff (count = 0, iface = interface, filter = expression, prn = lambda pkt: customAction(pkt))

