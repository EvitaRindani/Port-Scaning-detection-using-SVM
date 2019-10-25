import subprocess
import logging
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

try:
	from scapy.all import *
except ImportError:
	sys.exit()

interface = 'wlo1'
subprocess.call(["ifconfig",interface,"promisc"],stdout=None,stderr=None,shell=False)
print ('Capturing packet....')

totalpackets=0
loop=1

while loop==1 :
    totalpackets += 1
    p = sniff(iface='wlo1',timeout=10,count=0)
    wrpcap('pcap{}'.format(totalpackets)+'.pcap',p);
