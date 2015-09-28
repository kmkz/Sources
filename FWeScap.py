#! /usr/bin/env python

import sys, getopt

# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *


	
def Usage():
	print("[-] Missing argument !")
	
	
def Tcp(proto, targ):
	print "[+]Sending tcp!", proto, "request on", targ
	
	start= 20
	end  = 50
	for dport in range(start, end):
		
		# Generate random source port number
		sport=RandNum(1024,65535)
		
		print "Tryning request on port number== ", dport
		res, unans = sr(IP(dst=targ)/TCP(sport=sport,dport=dport,flags="S"),inter=0.5,retry=-2,timeout=1)
		#~ ans,unans
		res.summary()
		#sending.show()
		#~ if Req:
			
			#~ print Req.dport, Req.seq
			 #~ ans,unans
			#~ ans.summary()
			

			


def Udp(proto, targ):
	print "woot udp!", proto


def Arp(proto, targ):
	print "woot arp!"
	
	
def Icmp(proto, targ):
	print "[+]Sending", proto, "request on ", targ

		
	# Basic ICMP request:
	ping=sr1(IP(dst=targ)/ICMP())
	if ping:
		ping.show()
	
	
	
	

def main(argv):
	
	# Default values:
	target= "127.0.0.1"
	protocol= "icmp"
	
	try:
		opts, args = getopt.getopt(argv, "ht:p:", ["help", "target=", "protocol="])
		
	except getopt.GetoptError:
		Usage()
		sys.exit(2)
		
	for opt, arg in opts:
		
		# Usage/help called:
		if opt in ('-h', '--help'):
			print"help"
			Usage()
			sys.exit()
		
		
		elif opt in ('-t', '--target'):
			target=arg
			
		elif opt in ('-p', '--protocol'):
			protocol = arg
			
	# Switch/case:
	if protocol == "tcp":
		Tcp(protocol, target)
	elif protocol == "icmp":
		Icmp(protocol, target)
	elif protocol == "udp":
		Udp(protocol, target)
	elif protocol == "arp":
		Arp(protocol, target)
		
	else:
		assert False, "unknow or invalid options"
		
			

		

if __name__ == "__main__":
	main(sys.argv[1:])



	
	
	