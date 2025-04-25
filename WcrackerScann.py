from scapy.all import ARP, Ether, srp
import netifaces
import requests


def get_vendor(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
    except requests.exceptions.RequestException:
        pass
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

    for i, (sent, received) in enumerate(result):
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

def main():
    gateway_ip, gateway_mac, iface = get_gateway_info()
    scan_ip = '.'.join(gateway_ip.split('.')[:3]) + '.0/24'

    print(f"[INFO] Gateway IP: {gateway_ip}")
    print(f"[INFO] Gateway MAC: {gateway_mac}")
    print(f"[INFO] Interface: {iface}")
    print(f"[INFO] Scanning subnet: {scan_ip}")

    devices = scan_network(scan_ip, iface)
    print_device_info(devices)

if __name__ == "__main__":
    main()