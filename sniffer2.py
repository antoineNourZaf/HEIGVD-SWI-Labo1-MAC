#!/usr/bin/python

import sys
import requests
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.sendrecv import sniff

# a Client class to simplify printing
class Client:

    macId = ""
    manufacturer = ""
    ssid = []

    def __init__(self, macId, manufacturer):
        self.macId = macId
        self.manufacturer = manufacturer

    def getId():
        return self.macId

    def addSSID(self, ssidFound):
        if (ssidFound not in self.ssid):
            self.ssid.append(ssidFound)

    def __str__(self):
        return (self.macId + " (" + self.manufacturer + ") - " + ', '.join(self.ssid))

# dictionnary to contain our clients and to get a (key, value) tuple
clients = dict()

# Function to execute when a packet was found
def stationFound(packet):

    # Looking for probe requests which is given by stations
    if (packet.haslayer(Dot11ProbeReq)):

        # Get manufacturer
        ## This request can rise an exception because of the limited requests number decided by the api
        r = requests.get("http://macvendors.co/api/vendorname/" + packet.addr2 + "/pipe")

        # If it's the first time we see the device, it will be put in the array
        if (packet.addr2 not in clients):

            # Create a client from info we get
            client = Client(packet.addr2, r.content)
            ssid = packet.info
            # Add Ssid to the list of previous ssid
            client.addSSID(ssid)
            clients[packet.addr2] = client
            print(client)
        else :
            ssid = packet.info
            clients[packet.addr2].addSSID(ssid)


if __name__ == '__main__':

    print("Start the script to sniff devices...")

    # Sniff devices in the area
    sniff(iface="wlan0mon", prn=stationFound)

    # Print every clients found
    for client in clients:
        print(client)

    print("End of sniffing...")
