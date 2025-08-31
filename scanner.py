# scanner.py
import nmap
import argparse
import sys

def scan_network(network_range: str):
    """
    Skenira podan omrežni rang z Nmap-om in izpiše podrobne informacije
    o najdenih napravah.
    """
    print(f"[*] Začenjam podrobno skeniranje omrežja: {network_range}")
    print("[*] To lahko traja nekaj minut, odvisno od velikosti omrežja...")

    try:
        nm = nmap.PortScanner()
        # Argument '-A' za agresivno skeniranje (OS, verzije), '-T4' za hitrost.
        # Zahteva sudo/administratorske pravice za najboljše rezultate.
        nm.scan(hosts=network_range, arguments='-A -T4')
    except nmap.PortScannerError:
        print("\n[!] Napaka: Nmap ni najden. Ali je nameščen in v vaši sistemski poti (PATH)?")
        print("[!] Na Ubuntuju ga namestite z: sudo apt install nmap")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Prišlo je do nepričakovane napake: {e}")
        sys.exit(1)

    if not nm.all_hosts():
        print("\n[*] Skeniranje končano. V podanem rangu ni bilo najdenih aktivnih naprav.")
        return

    print("\n[+] Skeniranje končano. Najdene naprave:")
    for host in sorted(nm.all_hosts()):
        print("----------------------------------------------------")
        hostname = f"({nm[host].hostname()})" if nm[host].hostname() else ""
        print(f"  Gostitelj: {host} {hostname}")
        print(f"  Stanje:    {nm[host].state()}")

        if 'mac' in nm[host]['addresses']:
            vendor = nm[host]['vendor'][nm[host]['addresses']['mac']] if nm[host]['addresses']['mac'] in nm[host]['vendor'] else ""
            print(f"  MAC Naslov: {nm[host]['addresses']['mac']} ({vendor})")

        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            os_match = nm[host]['osmatch'][0]
            print(f"  OS:        {os_match['name']} (Natančnost: {os_match['accuracy']}%)")

        for proto in nm[host].all_protocols():
            print(f"  Protokol:  {proto.upper()}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_info = nm[host][proto][port]
                service = f"{port_info['name']} ({port_info.get('version', '')} {port_info.get('product', '')})".strip()
                print(f"    - Vrata {port:<5}: {port_info['state']:<10} {service}")
    print("----------------------------------------------------")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Orodje za skeniranje lokalnega omrežja z uporabo Nmap.",
        epilog="Primer uporabe: sudo python3 scanner.py 192.168.1.0/24"
    )
    parser.add_argument("network_range", help="Omrežni rang za skeniranje (npr. '192.168.1.0/24' ali '10.0.0.1-50').")
    args = parser.parse_args()

    scan_network(args.network_range)