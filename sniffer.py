#!/usr/bin/python

from scapy.all import *
import requests

def stationFound(packet):
    if (len(sys.argv) > 1):
        if (packet.addr2 == sys.argv[1]):
            print("The client with MAC address given ("+ sys.argv[1] +") has been found: ")
            print(packet.info)
            packet.show()
                        
    else:
        if (packet.haslayer(Dot11) and packet.type == 0):
            print("we find this")
            print packet.addr2
    

if __name__ == '__main__':

    print("Start the script to sniff devices...")
    
    # Sniff devices in the area
    sniff(iface="wlan0mon", prn=stationFound, count=10,)
    
    print("End of sniffing...")
