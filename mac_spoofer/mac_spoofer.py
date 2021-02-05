#!/usr/bin/env python3

import subprocess
import optparse
import re

#Allows user to supply interface and MAC as arguments on the command line
def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options, arguments) = parser.parse_args()
    
    #Checks to see if any interface or MAC was supplied, if not returns error message
    if not options.interface:
        parser.error("[-] Please specify an interface, --help for more info")
    elif not options.new_mac:
       parser.error("[-] Please specify a MAC, --help for more info")
    return options


#Functon to change mac with supplied interface and MAC
def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


#Function to return the current mac address using regex
def get_mac(interface):
    ifconfig_output = subprocess.check_output(["ifconfig", interface])


    mac_address_search = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_output))
    #Checks to see if a MAC was found, returns error message if none found 
    if mac_address_search:
        return mac_address_search.group(0)
    else:
        print("[-] Could not find MAC address")

#pulls options from command line
options = get_args()

#prints users current MAC before changing
current_mac = get_mac(options.interface)
print("Current MAC is: " + str(current_mac))

#Changes the users MAC
change_mac(options.interface, options.new_mac)

#Checks to see if MAC was succesfully changed and if not returns error message
current_mac = get_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC was changed to " + current_mac)
else:
    print("[-] MAC change failed")

