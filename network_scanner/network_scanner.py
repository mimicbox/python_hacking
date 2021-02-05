#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import iptools
import os

if os.getuid() != 0:
    print("Please run with root privileges!")
    quit()
else:
    pass


#Function to scan IPs
def scan(ip):
    #Generates the ARP request
    arp_req = scapy.ARP(pdst=ip)
    
    ###Uncomment below to see info about the ARP request
    #print(arp_req.show())
    #print(arp_req.summary())
    
    #Sets the destination to boardcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    ###Uncomment below to see info about source MAC and Destination MAC
    #print(broadcast.show())
    #print(broadcast.summary())
    
    #Combines the request and the broadcast into one packet
    arp_broadcast = broadcast/arp_req
    
    ###Uncomment below to see both ARP and the boardcast together
    #print(arp_broadcast.show())
    #print(arp_broadcast.summary())

    #srp is send and reply on layer 3... it sends the packets we made and listens for response with a timeout of 1 sec, set the list to a variable
    answer_list = scapy.srp(arp_broadcast, timeout=1, verbose=True)[0]
   
    
    #Creates a list of dictionaries that contain the IP and MAC of the targets
    client_list = []
    for item in answer_list:
        client_dict = {"IP" : item[1].psrc, "MAC" : item[1].hwsrc }
        client_list.append(client_dict)
    return client_list
        
#Function to print the items in the list of dictionaries
def print_results(results_list):
    
    print("IP\t\t\tMAC\n=========================================")
    
    for item in results_list:
        print(item["IP"] + "\t\t" + item["MAC"])


#Setting up argparse and setting description 
parser = argparse.ArgumentParser(description="Supply an IP address or a range in cidr notation and scan the network", usage="network_scanner.py [IP]")

#Adds -i or --p as an command line option
parser.add_argument('-i', '--ip', help='IP address or range of IP in cidr notation', required=True)
#Sets supplied arguments to variable args
args = parser.parse_args()


#Checks to see if a valid IP or cidr notation.... if not exits. Returns true if a single digit... tested 12 and works. Is this short hand for 12.0.0.0?
if iptools.ipv4.validate_cidr(args.ip) == False:
    if iptools.ipv4.validate_ip(args.ip) == True:
       scan_result = scan(args.ip)
       print_results(scan_result)
    else:
        print("Please use a valid IP")
else:
    scan_result = scan(args.ip)
    print_results(scan_result)











