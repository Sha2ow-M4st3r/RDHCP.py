# DHCPSpoofer
DHCP Spoofing Attack   

This is a simple Python script designed to implementing DHCP spoofing attacks on the network. It is important to note that the script is not very fast due to the lack of multi-threading. This script is only useful for learning network socket programming in Python with scapy and for modeling and implementing it on a small network.

## Usage

```markdown
sudo python3 dhcpspoof.py --iface <interface> --gateway <default-gateway> --dns <dns-server> --range <network-range/cidr>
sudo python3 dhcpspoof.py --iface vboxnet0 --gateway 192.168.56.1 --dns 192.168.56.1 --range 192.168.56.0/24
```
