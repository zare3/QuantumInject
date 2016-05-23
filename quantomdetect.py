from scapy.all import *
import argparse
import re


parser = argparse.ArgumentParser()
parser.add_argument("-i", help="network interface to sniff for online mode")
parser.add_argument("-r", help="pcap file for offline mode")
parser.add_argument("-e", help="expression for scapy to filter packets")
terminalArgs = parser.parse_args()
'''
########################
#example things to supply to the terminal to sniff on http packets
interface = 'wlan0'
pcappath = 'sniffed.pcap'
expression = 'tcp port http'
#######################
'''



interface = terminalArgs.i
pcappath = terminalArgs.r
expression = terminalArgs.e


MAX_SIZE = 50
packetLenWithoutLoad = 32
previousPackets = [ ]


def isAForgedPacket(pkt):
	if hasattr(pkt.getlayer('TCP'), 'load'):
		for prevPkt in previousPackets:
			if prevPkt[IP].dst == pkt[IP].dst and prevPkt[IP].src == pkt[IP].src and\
			prevPkt[TCP].sport == pkt[TCP].sport and prevPkt[TCP].dport == pkt[TCP].dport and\
			prevPkt[TCP].seq == pkt[TCP].seq and prevPkt[TCP].ack == pkt[TCP].ack and\
			len(prevPkt[TCP]) > packetLenWithoutLoad and len(pkt[TCP]) > packetLenWithoutLoad and\
			prevPkt[TCP].payload != pkt[TCP].payload:
				print "------------------------------------------------"
				print "------------------------------------------------"
				print "------------------------------------------------"
				print "------------------------------------------------"
				print "------------------------------------------------"
				print "ATTACK HAS BEEN FOUND AT: "
				print "ORIGINAL PACKET: "
				prevPkt.show()
				print "FORGET PACKET: "
				pkt.show()
		previousPackets.append(pkt)




terminalArgs = parser.parse_args()


if not pcappath and not interface:
    interface = "eth0"
elif interface and pcappath:
	print "Dude, make up your mind. online or offline mode? You can't have both"
elif interface:
	print "Using interface: ", interface
	packets = sniff (count = MAX_SIZE, iface = interface, filter = expression, prn = lambda pkt: customAction(pkt))
else:
	print "Using pcap: ", pcappath
	packets = sniff(offline = pcappath, filter = expression, prn = lambda pkt: isAForgedPacket(pkt) )


