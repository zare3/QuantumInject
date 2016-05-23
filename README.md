# QuantumInject

Quantum Inject

For the injection:
We used scapy as our tool for sniffing and injection.
We first sniff the right interface, in our case it was the WiFi interface and we create a deep copy of that packet, which we can then manipulate as we wish.
We exchange the key parts of the packet such as the IP addresses and the ports of the connection.
To allow for this change, we let Scapy recalculate the checksums for the new forged packet.
We also change the payload so that it can be any file that would match the attack. For the latest change, we’re injecting an HTML file which should appear in the browser once the user visits an HTTP page.

Code Usage:

sudo python quantominject.py -i [interface] -e [expression] -d [datafile] 

-i: network interface to sniff
-r: regex to filter the packet according to request type
-d: data file that contains the new payload
-e: expression for scapy to filter packets


Quantum Detect

Basic Idea:
We check for identical packets that have been rerouted. And check whether they have different payloads or not. If they have different payloads - we report an injection attack.


Dependencies:
Scapy
Python

Usage:
Sudo python quantomdetect.py -i [interface] -r [pcap file] -e [expression]
-i: interface for scapy to listen on -- online mode, default is eht0
-r: offline mode: pcap file path
-e: expression for scapy to match

Limitations:

The injection doesn’t work all the time. If the server was able to respond before our forged packet reaches the client, the injection fails. A solution that might work for this, is to DDOS the server to make it slower before resending the packet.






