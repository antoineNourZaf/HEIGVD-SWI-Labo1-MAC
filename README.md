[Livrables](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#livrables)

[Échéance](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#échéance)

[Quelques pistes importantes](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#quelques-pistes-importantes-avant-de-commencer-revenez-les-voir-vous-en-aurez-besoin-)

[Travail à réaliser](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#travail-à-réaliser)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 MAC

__A faire en équipes de deux personnes__

### Pour cette partie pratique, vous devez être capable de :

*	Détecter si un certain client WiFi se trouve à proximité
*	Obtenir une liste des SSIDs annoncés par les clients WiFi présents

## Travail à réaliser

### 1. Détecter si un ou plusieurs clients 802.11 spécifiques sont à portée

Il peut être utile de détecter si certains utilisateurs se trouve dans les parages. Pensez, par exemple, au cas d'un incendie dans un bâtiment. On pourrait dresser une liste des dispositifs et la contraster avec les personnes qui ont déjà quitté le lieu.

La détection de client s'utilise également à des fins de recherche de marketing. Aux Etats Unis, par exemple, on sniffe dans les couloirs de centres commerciaux pour détecter, par exemple, quelles vitrines attirent plus de visiteurs, et quelle marque de téléphone ils utilisent. Ce service, interconnecté en réseau, peut aussi déterminer si un client visite plusieurs centres commerciaux un même jour ou sur un certain intervalle de temps.

__ATTENTION__ : Le suivi de clients iPhone n'est plus possible que dans certaines conditions depuis la version 8 d'iOS.
 
* Développer un script en Python/Scapy capable de capturer les trames nécessaires pour la détection de clients 802.11. Le script se lance en ligne de commandes avec comme argument une adresse MAC d'un certain client. Le script surveille ensuite les messages capturés et imprime une confirmation quand l'adresse est détectée.

__Question__ : quel type de trames sont nécessaires pour détecter les clients de manière passive ?

*Il faut des trames "Probe request" pour pouvoir ecouter les clients de manière passive. Ils envoient ces trames a tout access points, et il y a juste besoin d'ecouter*

__Question__ : pourquoi le suivi n'est-il plus possible sur iPhone depuis iOS 8 ?

*Depuis iOs 8, l'adresse MAC des iPhones peut changer ce qui rend impossible de suivre l'appareil entre deux détections*

### 2. Clients WiFi bavards
a)	Utilisant le script que vous venez de développer comme base, faire les modifications nécessaires pour capturer les noms de réseau annoncés par les différents clients se trouvant à portée de votre scanner. 

Vous pouvez afficher les noms des réseaux avec les adresses MAC correspondantes au fur et à mesure qu'ils sont capturés mais vous devez garder une trace de quels noms correspondent à quel client. 

b)	Utiliser une ressource online pour déterminer automatiquement la marque du constructeur de l'interface WiFi pour chaque message capturé. Afficher aussi cette information avec chaque ligne imprimée.

Ainsi, à chaque fois que votre client imprime des résultats, il affiche quelque chose comme ceci :

```
00:1B:63:21:10:33 (Apple Inc.) – HEIG-VD, GVA, Lausanne, MonWiFi
00:09:18:10:23:01 (Samsung) – HEIG-VD, Marathon, europa, eduroam
```

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

- Script de détection de clients 802.11 __abondamment commenté/documenté__

```
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
```

- Script de détection et affichage de SSID __abondamment commenté/documenté__

-	Réponses aux éventuelles questions posées dans la donnée. Vous répondez aux questions dans votre ```README.md```

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 20 mars 2019 à 18h00
