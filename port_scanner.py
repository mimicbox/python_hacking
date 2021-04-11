#!/usr/bin/env python3
​
​
import socket
import argparse
import sys
import iptools
​
​
if __name__ == "__main__":
​
    parser = argparse.ArgumentParser(prog="portscanner.py", epilog="Simple port scanner", usage ="portscanner.py -i <Target IP> -p <Port Range> portscanner.py -h for more port options", prefix_chars="-", add_help=True)
    parser.add_argument('-i', action='store', metavar='IP', type=str, help="Target IP", required=True)
    parser.add_argument('-p', action='store', metavar='Ports',help='Target Ports.\tExample: 1-100 for a range, 80 for single port, 0 for all ports', required=True)
​
    args = parser.parse_args()
    ip = args.i
    openports = 0
    
    #Check for valid IP
    if iptools.ipv4.validate_ip(ip) == True:
        
        #Try block is to check for port range or single port
        try:
            p = int(args.p)
​
            #if port is 0 set range to all ports
            if p == 0:
                lowport = 1
                highport = 65535
            #else set lowport to port supplied
            else:
                lowport = p
                
        #If string detected (1-100 for a range!)
        except ValueError:
            #Set port range
            lowport = int(args.p.split('-')[0])
            highport = int(args.p.split('-')[1])
​
        #Try block for scanning range, if no highport defaults to single port scan
        try:
            print("[!] Scanning IP: ",ip," from port: ", lowport, "to port: ", highport)
            for port in range(lowport, highport):
                #Establishes socket and checks for satus code 0 is open 1 is closed
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                state = s.connect_ex((ip,port))
                if(state == 0):
                    print('[+]*** Port: ', port, ' is Open ***')
                    openports += 1
            
            print("[!] Scanning complete! ", openports, " ports open!")
            sys.exit()
​
        #Catches single port scan
        except Exception:
            print("[!] Scanning IP: ",ip, "Port ", lowport)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            state = s.connect_ex((ip,lowport))
            if(state == 0):
                print("[+] Scan Complete! Port ", lowport, " is open!")
            else:
                print("[-] Scan Complete! Port ", lowport, " is closed!")
                    
        #Who doesn't like a clean exit
        except KeyboardInterrupt:
            sys.exit("\nBye!")
​
    else:
        sys.exit("[-] Please use a proper IP address!")
