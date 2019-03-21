#!/usr/bin/python

import sys
import requests
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.sendrecv import sniff

clients = [][]

# Function to execute when a packet was found
def stationFound(packet):

    # Looking for probe requests which is given by stations
    if (packet.haslayer(Dot11ProbeReq)):

        # If it's the first time we see the device, it will be put in the array
        if (packet.addr2 not in clients):
            clients.append(packet.addr2)
        else :
            clients[clients.index(packet.addr2)].append(packet.info)
        # We get informations from API to get manufacturer
        r = requests.get("http://macvendors.co/api/vendorname/" + packet.addr2 + "/pipe")
        print(packet.addr2 + " (" + r.content + ") " + clients[clients.index(packet.addr2)])

if __name__ == '__main__':

    print("Start the script to sniff devices...")

    # Sniff devices in the area
    sniff(iface="wlan0mon", prn=stationFound)

    print("End of sniffing...")