#!/usr/bin/python

import sys
import requests
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.sendrecv import sniff

# Function to execute when a packet was found
def stationFound(packet):

    # Looking for probe requests which is given by station
    if (packet.haslayer(Dot11ProbeReq)):

        # Use the mac address provided
        if (len(sys.argv) > 1):
            if (packet.addr2 == sys.argv[1]):
                print("The client with MAC address given (" + sys.argv[1] + ") has been found: ")
                r = requests.get("http://macvendors.co/api/" + packet.addr2 + "/pipe")
                print(packet.addr2 + " | " + packet.info + " | " + r.content)

        # No mac address given
        else:
            # We get informations from API to get manufacturer
            r = requests.get("http://macvendors.co/api/vendorname/" + packet.addr2 + "/pipe")
            print(packet.addr2 + " | " + packet.info + " | " + r.content)

if __name__ == '__main__':

    print("Start the script to sniff devices...")

    # Sniff devices in the area
    sniff(iface="wlan0mon", prn=stationFound)

    print("End of sniffing...")
