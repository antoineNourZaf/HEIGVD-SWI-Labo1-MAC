#!/usr/bin/python

import sys
import requests
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.sendrecv import sniff

clientSearched = []

# Function to execute when a packet was found
def stationFound(packet):

    # Looking for probe requests which is given by station
    if (packet.haslayer(Dot11ProbeReq)):

        # Use the mac address provided
        if (len(sys.argv) > 1):

            # The client searched has been found. We print him once.
            if (packet.addr2 == sys.argv[1] and packet.addr2 not in clientSearched):

                print("The client with MAC address given (" + sys.argv[1] + ") has been found: ")
                clientSearched.append(packet.addr2)
                print(packet.addr2 + " | " + packet.info)

if __name__ == '__main__':

    print("Start the script to sniff devices...")

    # Sniff devices in the area
    sniff(iface="wlan0mon", prn=stationFound)

    print("End of sniffing...")
