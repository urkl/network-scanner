#!/usr/bin/env python3
"""
Network Scanner Application
By Urosk.NET - ZEN vibe coding
"""
import nmap
import json
import threading
import time
import os
import requests
import sqlite3
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
import netifaces
import socket
import subprocess
import re

app = Flask(__name__)

# Nastavi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Globalne spremenljivke za shranjuvanje rezultatov
scan_results = []
last_scan_time = None
scan_in_progress = False
stop_scan_requested = False
current_scan_status = {
    'scanning': False,
    'scan_type': '',
    'progress': 0,
    'current_host': '',
    'total_hosts': 0,
    'completed_hosts': 0,
    'start_time': ''
}

def preserve_custom_names():
    """Ohrani custom imena iz obstoječih rezultatov"""
    custom_names = {}
    for device in scan_results:
        if device.get('custom_name'):
            custom_names[device['ip']] = device['custom_name']
    return custom_names

def restore_custom_names(custom_names):
    """Obnovi custom imena v novih rezultatih"""
    for device in scan_results:
        if device['ip'] in custom_names:
            device['custom_name'] = custom_names[device['ip']]

def scan_network_background(network_range, force_full_scan=False):
    """Pametno skeniranje omrežja v ozadju"""
    global scan_results, last_scan_time, scan_in_progress, current_scan_status, stop_scan_requested
    
    # Reset stop flag
    stop_scan_requested = False
    scan_in_progress = True
    current_scan_status['scanning'] = True
    current_scan_status['scan_type'] = 'Polno skeniranje' if force_full_scan else 'Hitro skeniranje'
    current_scan_status['progress'] = 0
    current_scan_status['start_time'] = datetime.now().isoformat()
    
    print(f"[*] Začenjam pametno skeniranje omrežja: {network_range}")
    
    try:
        # Preveri če je zahtevano zaustavitev
        if stop_scan_requested:
            raise KeyboardInterrupt("Skeniranje prekinjeno po zahtevi")
            
        # Če ni force_full_scan in imamo cache, naredi samo hitro skeniranje
        if not force_full_scan and scan_results:
            print("[*] Izvajam hitro posodabljanje obstoječih naprav...")
            current_scan_status['scan_type'] = 'Hitro posodabljanje'
            
            # Hitro preveri status obstoječih naprav
            known_ips = set(device['ip'] for device in scan_results)
            active_ips = quick_ping_scan(network_range)
            
            # Posodobi status naprav
            update_device_status(active_ips)
            
            # Poišči nove naprave
            current_scan_status['current_host'] = 'Iščem nove naprave...'
            current_scan_status['progress'] = 50
            new_devices = detailed_scan_new_devices(network_range, known_ips)
            
            # Dodaj nove naprave
            scan_results.extend(new_devices)
            
            print(f"[*] Hitro posodobitev končano. Najdenih {len(new_devices)} novih naprav.")
            
        else:
            # Polno skeniranje
            print("[*] Izvajam polno skeniranje...")
            current_scan_status['scan_type'] = 'Polno skeniranje'
            
            # Ohrani custom imena pred brisanjem rezultatov
            custom_names = preserve_custom_names()
            scan_results = []
            
            # Najprej hitro skeniranje za žive naprave
            current_scan_status['current_host'] = 'Ping skeniranje...'
            current_scan_status['progress'] = 10
            active_ips = quick_ping_scan(network_range)
            
            if not active_ips:
                print("[*] Ni najdenih aktivnih naprav")
                current_scan_status['progress'] = 100
                current_scan_status['current_host'] = 'Končano - ni naprav'
                scan_in_progress = False
                current_scan_status['scanning'] = False
                return
                
            print(f"[*] Najdenih {len(active_ips)} aktivnih naprav, začenjam podrobno skeniranje...")
            current_scan_status['total_hosts'] = len(active_ips)
            current_scan_status['completed_hosts'] = 0
            
            # Podrobno skeniranje vsake aktivne naprave
            for i, host in enumerate(active_ips, 1):
                # Preveri če je zahtevano zaustavitev
                if stop_scan_requested:
                    print("[*] Skeniranje prekinjeno po zahtevi")
                    raise KeyboardInterrupt("Skeniranje prekinjeno")
                    
                try:
                    current_scan_status['current_host'] = f'Skeniram {host}'
                    current_scan_status['completed_hosts'] = i - 1
                    current_scan_status['progress'] = int(10 + (80 * i / len(active_ips)))
                    
                    print(f"[*] Skeniram napravo {i}/{len(active_ips)}: {host}")
                    
                    detailed_nm = nmap.PortScanner()
                    # Hitrejše skeniranje - samo top 200 ports
                    detailed_nm.scan(hosts=host, arguments='-A -T4 --top-ports 200')
                    
                    if host in detailed_nm.all_hosts():
                        host_info = extract_host_info(detailed_nm, host)
                        scan_results.append(host_info)
                    else:
                        # Dodaj osnovne informacije tudi če podrobno skeniranje ni uspelo
                        basic_info = {
                            'ip': host,
                            'hostname': '',
                            'custom_name': '',
                            'mac': '',
                            'vendor': '',
                            'os': '',
                            'state': 'up',
                            'ports': [],
                            'scan_time': datetime.now().isoformat(),
                            'last_seen': datetime.now().isoformat()
                        }
                        scan_results.append(basic_info)
                        
                except Exception as e:
                    print(f"[!] Napaka pri skeniranju {host}: {e}")
                    # Dodaj osnovne informacije kljub napaki
                    basic_info = {
                        'ip': host,
                        'hostname': '',
                        'custom_name': '',
                        'mac': '',
                        'vendor': '',
                        'os': '',
                        'state': 'up',
                        'ports': [],
                        'scan_time': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat()
                    }
                    scan_results.append(basic_info)
                    
    except Exception as e:
        print(f"[!] Napaka pri skeniranju: {e}")
    
    # Obnovi custom imena če so bila shranjena
    if 'custom_names' in locals():
        restore_custom_names(custom_names)
    
    last_scan_time = datetime.now().isoformat()
    scan_in_progress = False
    current_scan_status['scanning'] = False
    current_scan_status['progress'] = 100
    current_scan_status['current_host'] = 'Končano'
    current_scan_status['completed_hosts'] = current_scan_status.get('total_hosts', 0)
    
    # Shrani v cache
    save_cache()
    
    print(f"[*] Skeniranje končano. Skupno {len(scan_results)} naprav.")

# Cache in DB nastavitve
CACHE_FILE = 'devices.json'
CONFIG_FILE = 'config.json'
DB_FILE = 'network_scanner.db'
CACHE_DURATION = timedelta(hours=24)  # Koliko časa so podatki veljavni
QUICK_SCAN_INTERVAL = timedelta(minutes=5)  # Kako pogosto hitro skeniranje

# Inicializiraj bazo
def init_database():
    """Ustvari tabele v bazi če ne obstajajo"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Tabela za naprave
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (ip TEXT PRIMARY KEY,
                  hostname TEXT,
                  custom_name TEXT,
                  mac TEXT,
                  vendor TEXT,
                  os TEXT,
                  state TEXT,
                  first_seen TIMESTAMP,
                  last_seen TIMESTAMP,
                  last_scan TIMESTAMP)''')
    
    # Tabela za zgodovino vrat
    c.execute('''CREATE TABLE IF NOT EXISTS port_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  device_ip TEXT,
                  port INTEGER,
                  protocol TEXT,
                  service TEXT,
                  state TEXT,
                  timestamp TIMESTAMP,
                  FOREIGN KEY(device_ip) REFERENCES devices(ip))''')
    
    # Tabela za scan zgodovino
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  device_ip TEXT,
                  scan_type TEXT,
                  timestamp TIMESTAMP,
                  details TEXT,
                  FOREIGN KEY(device_ip) REFERENCES devices(ip))''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

# Inicializiraj bazo ob zagonu
init_database()

# Default config
default_config = {
    'preferred_interface': '',
    'last_network': '',
    'auto_refresh_enabled': True,  # Privzeto vklopljeno
    'view_mode': 'table',
    'last_search': '',
    'scan_settings': {
        'timeout': 300,
        'top_ports': 200
    }
}

def load_config():
    """Naloži konfiguracijo"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Napaka pri nalaganju config: {e}")
    
    return default_config.copy()

def save_config(config):
    """Shrani konfiguracijo"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Napaka pri shranjevanju config: {e}")

def load_cache():
    """Naloži cache iz JSON datoteke"""
    global scan_results, last_scan_time
    
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
                
            # Preveri ali je cache še veljaven
            cache_time = datetime.fromisoformat(cache_data.get('timestamp', '1970-01-01'))
            if datetime.now() - cache_time < CACHE_DURATION:
                scan_results = cache_data.get('devices', [])
                last_scan_time = cache_data.get('timestamp')
                print(f"[*] Naložen cache z {len(scan_results)} napravami")
                return True
            else:
                print("[*] Cache je zastarel, bom naredil novo skeniranje")
                
        except Exception as e:
            print(f"[!] Napaka pri nalaganju cache: {e}")
    
    return False

def save_cache():
    """Shrani cache v JSON datoteko"""
    try:
        cache_data = {
            'devices': scan_results,
            'timestamp': last_scan_time or datetime.now().isoformat(),
            'version': '2.0'
        }
        
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
        print(f"[*] Cache shranjen z {len(scan_results)} napravami")
        
    except Exception as e:
        print(f"[!] Napaka pri shranjevanju cache: {e}")

def get_enhanced_device_info(ip):
    """Dobi dodatne informacije o napravi preko različnih metod"""
    info = {}
    
    try:
        # Poskusi dobit hostname preko DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            info['dns_hostname'] = hostname
        except:
            pass
        
        # Poskusi SNMP če je na voljo
        try:
            result = subprocess.run(
                ['snmpget', '-v', '2c', '-c', 'public', ip, 'sysDescr.0'],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                info['snmp_info'] = result.stdout.strip()
        except:
            pass
        
        # Poskusi HTTP/HTTPS header
        for port in [80, 443, 8080, 8443]:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                response = requests.get(f'{protocol}://{ip}:{port}/', timeout=1, verify=False)
                if 'Server' in response.headers:
                    info['web_server'] = response.headers['Server']
                break
            except:
                continue
        
        # NetBIOS ime (Windows)
        try:
            result = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '<00>' in line and 'GROUP' not in line:
                        netbios_name = line.split()[0].strip()
                        if netbios_name:
                            info['netbios_name'] = netbios_name
                        break
        except:
            pass
            
    except Exception as e:
        logger.error(f"Error getting enhanced info for {ip}: {e}")
    
    return info

def get_vendor_info(mac_address):
    """Dobi informacije o proizvajalcu iz MAC naslova"""
    if not mac_address:
        return ''
        
    try:
        # Uporabi IEEE MAC lookup API
        mac_clean = mac_address.replace(':', '').replace('-', '').upper()
        oui = mac_clean[:6]
        
        # Lokalni MAC vendor lookup - dodamo znane proizvajalce
        mac_vendors = {
            '001122': 'Cisco Systems',
            '0050C2': 'IEEE Registration Authority',
            '001D7E': 'Cisco-Linksys',
            '000423': 'Intel Corporate',
            '00156D': 'Apple',
            'AC87A3': 'Apple',
            'A4C361': 'Apple',
            'B025AA': 'Apple',
            'DC9B9C': 'Apple',
            'E81132': 'Apple',
            '3C15C2': 'Apple',
            '5C95AE': 'Apple',
            '70CD60': 'Apple',
            'C06394': 'Apple',
            'D89695': 'Apple',
            'F40F24': 'Apple',
            'F8E079': 'Apple',
            '001B63': 'Samsung Electronics',
            '0002E3': 'Samsung Electronics',
            '000E8F': 'Samsung Electronics',
            '001377': 'Samsung Electronics',
            '0015B9': 'Samsung Electronics',
            '001632': 'Samsung Electronics',
            '001D25': 'Samsung Electronics',
            '001E7D': 'Samsung Electronics',
            '002454': 'Samsung Electronics',
            'D85D4C': 'Raspberry Pi Foundation',
            'B827EB': 'Raspberry Pi Foundation',
            'DCA632': 'Raspberry Pi Foundation',
            'E45F01': 'Raspberry Pi Foundation',
            '000C29': 'VMware',
            '005056': 'VMware',
            '001C14': 'VMware',
            '00155D': 'Microsoft',
            '001DD8': 'Microsoft',
            '7CB27D': 'Microsoft',
            '002248': 'NETGEAR',
            '001E2A': 'NETGEAR',
            '002722': 'NETGEAR',
            '003048': 'NETGEAR',
            '0024B2': 'NETGEAR',
            '001FDF': 'Dell',
            '002219': 'Dell',
            '0007E9': 'Dell',
            '001560': 'Dell',
            '001EC9': 'Dell',
            '002564': 'Dell',
            'D067E5': 'Xiaomi',
            '28E14C': 'Xiaomi',
            '64B473': 'Xiaomi',
            'F8A45F': 'Xiaomi',
            '68DFDD': 'Xiaomi',
            '7C1DD9': 'Xiaomi',
            '98FA9B': 'Xiaomi',
            'A0C589': 'Xiaomi',
            'C46AB7': 'Xiaomi',
            'E8DE27': 'Xiaomi',
            'F0B429': 'Xiaomi',
            'F49F54': 'Xiaomi',
            'FC64BA': 'Xiaomi',
            '001DE9': 'UBNT/Ubiquiti Networks',
            '0418D6': 'Ubiquiti Networks',
            '041E64': 'Ubiquiti Networks',
            '24A43C': 'Ubiquiti Networks',
            '44D9E7': 'Ubiquiti Networks',
            '68D79A': 'Ubiquiti Networks',
            '74AC B9': 'Ubiquiti Networks',
            '78045E': 'Ubiquiti Networks',
            '788A20': 'Ubiquiti Networks',
            'B4FBE4': 'Ubiquiti Networks',
            'DC9FDB': 'Ubiquiti Networks',
            'E063DA': 'Ubiquiti Networks',
            'F09FC2': 'Ubiquiti Networks',
            'FC21B4': 'Ubiquiti Networks',
        }
        
        if oui in mac_vendors:
            return mac_vendors[oui]
            
        # Fallback na online lookup (opcijsko)
        try:
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and vendor != "Not found":
                    return vendor
        except:
            pass
            
        return 'Neznano'
        
    except Exception as e:
        print(f"[!] Napaka pri lookup vendor: {e}")
        return 'Neznano'

def get_network_interfaces():
    """Dobi seznam mrežnih vmesnikov"""
    try:
        interfaces = []
        for interface in netifaces.interfaces():
            if interface == 'lo':  # Preskoči loopback
                continue
                
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')
                    if ip and netmask and not ip.startswith('127.'):
                        network = calculate_network(ip, netmask)
                        if network:
                            interfaces.append({
                                'name': interface,
                                'ip': ip,
                                'network': network,
                                'description': f"{interface} ({ip} - {network})"
                            })
        return interfaces
    except Exception as e:
        print(f"[!] Napaka pri iskanju vmesnikov: {e}")
        return []

def quick_ping_scan(network_range):
    """Hitro ping skeniranje za preverjanje aktivnih naprav"""
    try:
        nm = nmap.PortScanner()
        # Samo ping scan (-sn) - zelo hiter
        nm.scan(hosts=network_range, arguments='-sn -T5')
        return set(nm.all_hosts())
    except Exception as e:
        print(f"[!] Napaka pri ping skeniranju: {e}")
        return set()

def update_device_status(active_ips):
    """Posodobi status naprav glede na ping rezultate"""
    global scan_results
    
    current_time = datetime.now().isoformat()
    
    for device in scan_results:
        if device['ip'] in active_ips:
            device['state'] = 'up'
            device['last_seen'] = current_time
        else:
            device['state'] = 'down'
            # Ohrani zadnji čas ko smo napravo videli
            if 'last_seen' not in device:
                device['last_seen'] = device.get('scan_time', current_time)

def detailed_scan_new_devices(network_range, known_ips):
    """Podrobno skeniraj samo nove naprave"""
    try:
        nm = nmap.PortScanner()
        # Skeniraj vse žive naprave
        nm.scan(hosts=network_range, arguments='-sn -T5')
        live_hosts = set(nm.all_hosts())
        
        # Najdi nove naprave
        new_devices = live_hosts - known_ips
        
        if not new_devices:
            print("[*] Ni novih naprav za skeniranje")
            return []
            
        print(f"[*] Našel {len(new_devices)} novih naprav za podrobno skeniranje")
        
        new_device_info = []
        for host in new_devices:
            # Preveri če je zahtevano zaustavitev
            if stop_scan_requested:
                print("[*] Skeniranje novih naprav prekinjeno")
                break
                
            try:
                print(f"[*] Podrobno skeniram novo napravo: {host}")
                detailed_nm = nmap.PortScanner()
                # Hitrejše podrobno skeniranje - samo top 100 ports
                detailed_nm.scan(hosts=host, arguments='-A -T4 --top-ports 100')
                
                if host in detailed_nm.all_hosts():
                    host_info = extract_host_info(detailed_nm, host)
                    new_device_info.append(host_info)
                    
            except Exception as e:
                print(f"[!] Napaka pri skeniranju {host}: {e}")
                # Dodaj osnovno informacijo
                # Dodaj osnovno informacijo
                basic_info = {
                    'ip': host,
                    'hostname': '',
                    'custom_name': '',  # Novo polje za custom ime
                    'mac': '',
                    'vendor': '',
                    'os': '',
                    'state': 'up',
                    'ports': [],
                    'scan_time': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat()
                }
                new_device_info.append(basic_info)
                
        return new_device_info
        
    except Exception as e:
        print(f"[!] Napaka pri skeniranju novih naprav: {e}")
        return []

def get_local_network():
    """Zazna lokalno omrežje"""
    try:
        # Poskusi dobiti privzeti gateway
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        
        # Dobi vse mrežne vmesnike
        interfaces = netifaces.interfaces()
        
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    netmask = addr['netmask']
                    
                    # Preveri ali je to lokalno omrežje
                    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                        # Izračunaj omrežni naslov
                        network = calculate_network(ip, netmask)
                        if network:
                            return network
                            
        return "192.168.1.0/24"  # Privzeto
    except:
        return "192.168.1.0/24"

def calculate_network(ip, netmask):
    """Izračuna omrežni naslov iz IP-ja in maske"""
    try:
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        
        # Izračunaj CIDR
        cidr = sum(bin(x).count('1') for x in mask_parts)
        
        return f"{'.'.join(map(str, network_parts))}/{cidr}"
    except:
        return None

# Funkcije za ohranitev custom imen se nahajajo zgoraj
# scan_network_background funkcija se nahaja zgoraj

def extract_host_info(nm, host):
    """Izvleče informacije o gostitelju"""
    host_data = nm[host]
    
    # Osnovne informacije
    hostname = host_data.hostname() if host_data.hostname() else ''
    state = host_data.state()
    
    # MAC naslov in proizvajalec
    mac = ''
    vendor = ''
    if 'mac' in host_data['addresses']:
        mac = host_data['addresses']['mac']
        # Uporabi naš izboljšan vendor lookup
        vendor = get_vendor_info(mac)
        # Fallback na nmap vendor če naš ne najde ničesar
        if vendor == 'Neznano' and mac in host_data['vendor']:
            vendor = host_data['vendor'][mac]
    
    # Operacijski sistem
    os_info = ''
    if 'osmatch' in host_data and host_data['osmatch']:
        os_match = host_data['osmatch'][0]
        os_info = f"{os_match['name']} ({os_match['accuracy']}%)"
    
    # Odprte vrata
    ports = []
    for proto in host_data.all_protocols():
        port_list = host_data[proto].keys()
        for port in sorted(port_list):
            port_info = host_data[proto][port]
            if port_info['state'] == 'open':
                service = port_info.get('name', '')
                version = port_info.get('version', '')
                product = port_info.get('product', '')
                
                service_detail = service
                if product:
                    service_detail += f" ({product}"
                    if version:
                        service_detail += f" {version}"
                    service_detail += ")"
                elif version:
                    service_detail += f" ({version})"
                
                ports.append({
                    'port': port,
                    'protocol': proto,
                    'service': service_detail,
                    'state': port_info['state']
                })
    
    # Shrani v bazo
    save_device_to_db(host, hostname, mac, vendor, os_info, state, ports)
    
    return {
        'ip': host,
        'hostname': hostname,
        'custom_name': get_custom_name_from_db(host),  # Dobi custom ime iz baze
        'mac': mac,
        'vendor': vendor,
        'os': os_info,
        'state': state,
        'ports': ports,
        'scan_time': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat()
    }

def save_device_to_db(ip, hostname, mac, vendor, os_info, state, ports):
    """Shrani napravo v bazo"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    now = datetime.now()
    
    # Preveri če naprava že obstaja
    c.execute('SELECT ip FROM devices WHERE ip = ?', (ip,))
    exists = c.fetchone()
    
    if exists:
        # Posodobi obstoječo napravo
        c.execute('''UPDATE devices SET hostname=?, mac=?, vendor=?, os=?, state=?, 
                     last_seen=?, last_scan=? WHERE ip=?''',
                  (hostname, mac, vendor, os_info, state, now, now, ip))
    else:
        # Vstavi novo napravo
        c.execute('''INSERT INTO devices (ip, hostname, custom_name, mac, vendor, os, state, 
                     first_seen, last_seen, last_scan)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (ip, hostname, '', mac, vendor, os_info, state, now, now, now))
    
    # Shrani zgodovino vrat
    for port in ports:
        c.execute('''INSERT INTO port_history (device_ip, port, protocol, service, state, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (ip, port['port'], port['protocol'], port['service'], port['state'], now))
    
    conn.commit()
    conn.close()

def get_custom_name_from_db(ip):
    """Dobi custom ime iz baze"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT custom_name FROM devices WHERE ip = ?', (ip,))
    result = c.fetchone()
    conn.close()
    return result[0] if result and result[0] else ''

@app.route('/')
def index():
    """Glavna stran"""
    return render_template('index.html')

@app.route('/api/update-device-name', methods=['POST'])
def api_update_device_name():
    """Posodobi custom ime naprave"""
    global scan_results
    
    data = request.get_json()
    if not data or 'ip' not in data or 'custom_name' not in data:
        return jsonify({'status': 'error', 'message': 'Manjkajo podatki'})
    
    ip = data['ip']
    custom_name = data['custom_name'].strip()
    
    # Posodobi v bazi
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE devices SET custom_name = ? WHERE ip = ?', (custom_name, ip))
    conn.commit()
    conn.close()
    
    # Posodobi v trenutnih rezultatih
    for device in scan_results:
        if device['ip'] == ip:
            device['custom_name'] = custom_name
            save_cache()  # Shrani spremembe
            return jsonify({'status': 'success', 'message': 'Ime posodobljeno'})
    
    return jsonify({'status': 'error', 'message': 'Naprava ni najdena'})

@app.route('/api/rescan-device', methods=['POST'])
def api_rescan_device():
    """Ponovno skeniraj specifično napravo"""
    global scan_results
    
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'status': 'error', 'message': 'Manjka IP naslov'})
    
    ip = data['ip']
    
    # Najdi napravo v trenutnih rezultatih
    for device in scan_results:
        if device['ip'] == ip:
            # Označi kot da skeniranje poteka
            device['detailed_scan_pending'] = True
            
            # Sproži novo podrobno skeniranje
            detail_thread = threading.Thread(
                target=detailed_device_scan,
                args=(ip,)
            )
            detail_thread.daemon = True
            detail_thread.start()
            
            logger.info(f"Manual rescan started for {ip}")
            return jsonify({'status': 'success', 'message': 'Skeniranje zagnano'})
    
    return jsonify({'status': 'error', 'message': 'Naprava ni najdena'})

@app.route('/api/confirm-ai-suggestion', methods=['POST'])
def api_confirm_ai_suggestion():
    """Potrdi AI predlog za napravo"""
    global scan_results
    
    data = request.get_json()
    if not data or 'ip' not in data or 'confirmed' not in data:
        return jsonify({'status': 'error', 'message': 'Manjkajo podatki'})
    
    ip = data['ip']
    confirmed = data['confirmed']
    
    # Najdi napravo
    for device in scan_results:
        if device['ip'] == ip:
            device['ai_confirmed'] = confirmed
            if confirmed and device.get('ai_suggestion'):
                # Shrani AI predlog kot user opis
                device['ai_description'] = device['ai_suggestion']
                # Odstrani predlog ker je sprejet
                device.pop('ai_suggestion', None)
            elif not confirmed:
                # Ko zavrnemo predlog, ga popolnoma odstranimo
                device.pop('ai_suggestion', None)
                device.pop('ai_description', None)
            save_cache()
            return jsonify({'status': 'success', 'message': 'AI predlog posodobljen'})
    
    return jsonify({'status': 'error', 'message': 'Naprava ni najdena'})

@app.route('/api/interfaces')
def api_interfaces():
    """Vrne seznam mrežnih vmesnikov"""
    interfaces = get_network_interfaces()
    return jsonify({'interfaces': interfaces})

@app.route('/api/config')
def api_get_config():
    """Vrne trenutno konfiguracijo"""
    config = load_config()
    return jsonify(config)

@app.route('/api/config', methods=['POST'])
def api_save_config():
    """Shrani konfiguracijo"""
    data = request.get_json()
    if data:
        save_config(data)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Ni podatkov'})

@app.route('/api/auto-refresh', methods=['POST'])
def api_toggle_auto_refresh():
    """Shrani stanje auto refresh"""
    data = request.get_json()
    if data and 'enabled' in data:
        config = load_config()
        config['auto_refresh_enabled'] = data['enabled']
        save_config(config)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Manjkajo podatki'})

@app.route('/api/view-mode', methods=['POST'])
def api_save_view_mode():
    """Shrani view mode (table/cards)"""
    data = request.get_json()
    if data and 'mode' in data:
        config = load_config()
        config['view_mode'] = data['mode']
        save_config(config)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Manjkajo podatki'})

@app.route('/api/search', methods=['POST'])
def api_save_search():
    """Shrani zadnji iskalni niz"""
    data = request.get_json()
    if data and 'search' in data:
        config = load_config()
        config['last_search'] = data['search']
        save_config(config)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Manjkajo podatki'})

@app.route('/api/scan')
def api_scan():
    """Sproži novo skeniranje"""
    global scan_in_progress, stop_scan_requested
    
    # Če skeniranje že poteka, ga prekini in začni novo
    if scan_in_progress:
        print("[*] Prekinjam obstoječe skeniranje...")
        stop_scan_requested = True
        # Počakaj malo, da se obstoječe skeniranje ustavi
        import time
        time.sleep(1)
    
    network = request.args.get('network')
    interface = request.args.get('interface', '')
    force_full = request.args.get('full', 'false').lower() == 'true'
    
    # Če ni podano omrežje, uporabi iz interface ali default
    if not network:
        if interface:
            # Najdi omrežje za izbrani interface
            interfaces = get_network_interfaces()
            for iface in interfaces:
                if iface['name'] == interface:
                    network = iface['network']
                    break
        if not network:
            network = get_local_network()
    
    # Shrani interface v config
    config = load_config()
    if interface:
        config['preferred_interface'] = interface
    config['last_network'] = network
    save_config(config)
    
    # Zaženi skeniranje v ločeni niti
    thread = threading.Thread(target=scan_network_background, args=(network, force_full))
    thread.daemon = True
    thread.start()
    
    scan_type = "polno" if force_full else "hitro"
    return jsonify({'status': 'success', 'message': f'{scan_type.title()} skeniranje zagnano'})

@app.route('/api/quick-scan')
def api_quick_scan():
    """Sproži hitro skeniranje (samo ping + nove naprave)"""
    global scan_in_progress, stop_scan_requested
    
    # Če skeniranje že poteka, ga prekini in začni novo
    if scan_in_progress:
        print("[*] Prekinjam obstoječe skeniranje za hitro skeniranje...")
        stop_scan_requested = True
        import time
        time.sleep(1)
    
    network = request.args.get('network', get_local_network())
    
    # Zaženi hitro skeniranje
    thread = threading.Thread(target=scan_network_background, args=(network, False))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'success', 'message': 'Hitro skeniranje zagnano'})

@app.route('/api/scan-status')
def api_scan_status():
    """Vrne podroben status trenutnega skeniranja"""
    global current_scan_status
    
    # Izračunaj čas skeniranja
    elapsed_time = None
    if current_scan_status.get('start_time'):
        start = datetime.fromisoformat(current_scan_status['start_time'])
        elapsed_time = str(datetime.now() - start).split('.')[0]  # Remove microseconds
    
    return jsonify({
        **current_scan_status,
        'elapsed_time': elapsed_time
    })

@app.route('/api/results')
def api_results():
    """Vrne trenutne rezultate skeniranja"""
    online_devices = [d for d in scan_results if d['state'] == 'up']
    
    # Dobi statistike iz baze
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM devices')
    total_in_db = c.fetchone()[0]
    c.execute('SELECT COUNT(DISTINCT device_ip) FROM port_history WHERE timestamp > datetime("now", "-24 hours")')
    active_24h = c.fetchone()[0]
    conn.close()
    
    return jsonify({
        'results': scan_results,
        'last_scan': last_scan_time,
        'scanning': scan_in_progress,
        'total_devices': len(scan_results),
        'online_devices': len(online_devices),
        'total_in_database': total_in_db,
        'active_last_24h': active_24h,
        'cache_info': {
            'has_cache': os.path.exists(CACHE_FILE),
            'cache_age_hours': get_cache_age_hours() if os.path.exists(CACHE_FILE) else 0
        }
    })

@app.route('/api/device-history/<ip>')
def api_device_history(ip):
    """Vrne zgodovino naprave"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Dobi osnovne podatke o napravi
    c.execute('SELECT * FROM devices WHERE ip = ?', (ip,))
    device = c.fetchone()
    
    if not device:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Naprava ni najdena'})
    
    # Dobi zgodovino vrat
    c.execute('''SELECT port, protocol, service, state, timestamp 
                 FROM port_history 
                 WHERE device_ip = ? 
                 ORDER BY timestamp DESC 
                 LIMIT 100''', (ip,))
    port_history = c.fetchall()
    
    # Dobi scan zgodovino
    c.execute('''SELECT scan_type, timestamp, details 
                 FROM scan_history 
                 WHERE device_ip = ? 
                 ORDER BY timestamp DESC 
                 LIMIT 50''', (ip,))
    scan_history = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'device': {
            'ip': device[0],
            'hostname': device[1],
            'custom_name': device[2],
            'mac': device[3],
            'vendor': device[4],
            'os': device[5],
            'state': device[6],
            'first_seen': device[7],
            'last_seen': device[8],
            'last_scan': device[9]
        },
        'port_history': [{
            'port': p[0],
            'protocol': p[1],
            'service': p[2],
            'state': p[3],
            'timestamp': p[4]
        } for p in port_history],
        'scan_history': [{
            'scan_type': s[0],
            'timestamp': s[1],
            'details': s[2]
        } for s in scan_history]
    })

@app.route('/api/export')
def api_export():
    """Izvozi podatke v različnih formatih"""
    format_type = request.args.get('format', 'json')
    
    if format_type == 'json':
        return jsonify({
            'devices': scan_results,
            'export_time': datetime.now().isoformat()
        })
    elif format_type == 'csv':
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['IP', 'Hostname', 'Custom Name', 'MAC', 'Vendor', 'OS', 'State', 'Open Ports', 'Last Seen'])
        
        # Data
        for device in scan_results:
            ports_str = ', '.join([f"{p['port']}/{p['protocol']}" for p in device.get('ports', [])])
            writer.writerow([
                device['ip'],
                device.get('hostname', ''),
                device.get('custom_name', ''),
                device.get('mac', ''),
                device.get('vendor', ''),
                device.get('os', ''),
                device.get('state', ''),
                ports_str,
                device.get('last_seen', '')
            ])
        
        output.seek(0)
        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=network_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    else:
        return jsonify({'status': 'error', 'message': 'Unsupported format'})

def get_cache_age_hours():
    """Vrne starost cache v urah"""
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            cache_time = datetime.fromisoformat(cache_data.get('timestamp', '1970-01-01'))
            age = datetime.now() - cache_time
            return round(age.total_seconds() / 3600, 1)
    except:
        pass
    return 0

@app.route('/api/network')
def api_network():
    """Vrne zaznano lokalno omrežje"""
    return jsonify({'network': get_local_network()})

def continuous_background_scanner():
    """Hitro kontinuirano skeniranje za real-time detekcijo naprav"""
    global scan_results, last_scan_time
    
    config = load_config()
    network = config.get('last_network') or get_local_network()
    
    logger.info(f"Starting continuous background scanner for network: {network}")
    
    while True:
        try:
            # Agresivnejše ping skeniranje za boljše odkrivanje naprav
            nm = nmap.PortScanner()
            try:
                nm.scan(hosts=network, arguments='-sn -T4 --min-parallelism 50')
                active_hosts = nm.all_hosts()
                logger.debug(f"Found {len(active_hosts)} hosts in ping scan")
                
                # Dodatno ARP skeniranje za lokalne naprave (če smo root)
                if os.getuid() == 0:
                    try:
                        nm_arp = nmap.PortScanner()
                        nm_arp.scan(hosts=network, arguments='-sn -PR')
                        arp_hosts = nm_arp.all_hosts()
                        logger.debug(f"Found {len(arp_hosts)} hosts in ARP scan")
                        # Dodaj ARP zaznane naprave
                        for host in arp_hosts:
                            if host not in active_hosts:
                                active_hosts.append(host)
                    except Exception as e:
                        logger.warning(f"ARP scan failed: {e}")
            except Exception as e:
                logger.error(f"Main scan failed: {e}")
                active_hosts = []
            
            current_time = datetime.now()
            known_ips = {device['ip'] for device in scan_results}
            
            # Najdi nove naprave
            new_hosts = set(active_hosts) - known_ips
            
            if new_hosts:
                logger.info(f"Found {len(new_hosts)} new devices")
                
                for host in new_hosts:
                    # Takoj dodaj osnovne informacije za prikaz
                    basic_info = {
                        'ip': host,
                        'hostname': '',
                        'custom_name': get_custom_name_from_db(host),
                        'mac': '',
                        'vendor': '',
                        'os': '',
                        'state': 'up',
                        'ports': [],
                        'scan_time': current_time.isoformat(),
                        'last_seen': current_time.isoformat(),
                        'scan_pending': True  # Označimo da čaka na podroben sken
                    }
                    
                    # Poskusi dobit hostname preko DNS
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                        basic_info['hostname'] = hostname
                    except:
                        pass
                    
                    scan_results.append(basic_info)
                    logger.info(f"Added new device: {host} (waiting for detailed scan)")
                    
                    # Sprozi podrobno skeniranje v novi niti
                    detail_thread = threading.Thread(
                        target=detailed_device_scan,
                        args=(host,)
                    )
                    detail_thread.daemon = True
                    detail_thread.start()
            
            # Posodobi status vseh naprav in sproži podrobno skeniranje če potrebno
            for device in scan_results:
                if device['ip'] in active_hosts:
                    device['state'] = 'up'
                    device['last_seen'] = current_time.isoformat()
                    
                    # Sproži podrobno skeniranje za naprave brez MAC naslova ali OS info
                    if (not device.get('mac') or device.get('mac') == '') and device.get('detailed_scan_pending') != True:
                        device['detailed_scan_pending'] = True
                        detail_thread = threading.Thread(
                            target=detailed_device_scan,
                            args=(device['ip'],)
                        )
                        detail_thread.daemon = True
                        detail_thread.start()
                        logger.info(f"Started detailed scan for existing device: {device['ip']}")
                else:
                    # Če naprava ni videna 30 sekund, označi kot offline
                    if 'last_seen' in device:
                        last_seen = datetime.fromisoformat(device['last_seen'])
                        if (current_time - last_seen).seconds > 30:
                            device['state'] = 'down'
            
            # Shrani če so spremembe
            if new_hosts or len(scan_results) > 0:
                last_scan_time = current_time.isoformat()
                save_cache()
                
        except Exception as e:
            logger.error(f"Error in continuous scanner: {e}")
        
        # Počakaj samo 3 sekunde za naslednji ping scan
        time.sleep(3)

def detailed_device_scan(host):
    """Podrobno skeniranje posamezne naprave v ozadju"""
    global scan_results
    
    try:
        logger.info(f"Starting detailed scan for {host}")
        
        # Podrobno skeniranje z dodatnimi technikami
        detailed_nm = nmap.PortScanner()
        
        # Poenostavljeno podrobno skeniranje
        try:
            scan_args = '-A -T4 --top-ports 500'
            if os.getuid() == 0:
                # Root dodatne možnosti
                scan_args += ' -O --osscan-guess'
            
            detailed_nm.scan(hosts=host, arguments=scan_args)
        except Exception as e:
            logger.error(f"Detailed scan failed for {host}: {e}")
            # Fallback - osnovni TCP scan
            try:
                detailed_nm.scan(hosts=host, arguments='-sS -T4 --top-ports 100')
            except Exception as e2:
                logger.error(f"Fallback scan also failed for {host}: {e2}")
                return
        
        if host in detailed_nm.all_hosts():
            host_data = detailed_nm[host]
            
            # Najdi napravo v scan_results
            for i, device in enumerate(scan_results):
                if device['ip'] == host:
                    # Posodobi z podrobnimi informacijami
                    hostname = host_data.hostname() if host_data.hostname() else device.get('hostname', '')
                    
                    # MAC naslov in vendor
                    mac = ''
                    vendor = ''
                    if 'mac' in host_data['addresses']:
                        mac = host_data['addresses']['mac']
                        vendor = get_vendor_info(mac)
                        if vendor == 'Neznano' and mac in host_data['vendor']:
                            vendor = host_data['vendor'][mac]
                    else:
                        # Poskusi dobiti MAC iz sistemske ARP tabele
                        mac = get_mac_from_arp(host)
                        if mac:
                            vendor = get_vendor_info(mac)
                    
                    # OS detekcija
                    os_info = ''
                    if 'osmatch' in host_data and host_data['osmatch']:
                        os_match = host_data['osmatch'][0]
                        os_info = f"{os_match['name']} ({os_match['accuracy']}%)"
                    
                    # Odprte vrate
                    ports = []
                    for proto in host_data.all_protocols():
                        port_list = host_data[proto].keys()
                        for port in sorted(port_list):
                            port_info = host_data[proto][port]
                            if port_info['state'] == 'open':
                                service = port_info.get('name', '')
                                version = port_info.get('version', '')
                                product = port_info.get('product', '')
                                
                                service_detail = service
                                if product:
                                    service_detail += f" ({product}"
                                    if version:
                                        service_detail += f" {version}"
                                    service_detail += ")"
                                elif version:
                                    service_detail += f" ({version})"
                                
                                ports.append({
                                    'port': port,
                                    'protocol': proto,
                                    'service': service_detail,
                                    'state': port_info['state']
                                })
                    
                    # Analiziraj tip naprave
                    device_type = detect_device_type(hostname, vendor, os_info, ports)
                    device_description = generate_device_description(hostname, vendor, os_info, ports, device_type)
                    
                    # AI analiza naprave
                    ai_suggestion = analyze_device_with_ai(hostname, mac, vendor, os_info, ports)
                    
                    # Posodobi podatke
                    scan_results[i].update({
                        'hostname': hostname,
                        'mac': mac,
                        'vendor': vendor,
                        'os': os_info,
                        'ports': ports,
                        'device_type': device_type,
                        'description': device_description,
                        'ai_suggestion': ai_suggestion,
                        'ai_confirmed': False,  # Ali je uporabnik potrdil AI predlog
                        'scan_pending': False,  # Skeniranje končano
                        'detailed_scan_pending': False,  # Podrobno skeniranje končano
                        'detailed_scan_time': datetime.now().isoformat()
                    })
                    
                    # Shrani v bazo
                    save_device_to_db(host, hostname, mac, vendor, os_info, device['state'], ports)
                    
                    # Shrani v cache
                    save_cache()
                    
                    logger.info(f"Completed detailed scan for {host}")
                    break
                    
    except Exception as e:
        logger.error(f"Error in detailed scan for {host}: {e}")
        # Označi da je skeniranje končano tudi če je bila napaka
        for device in scan_results:
            if device['ip'] == host:
                device['scan_pending'] = False
                break

if __name__ == '__main__':
    # Naloži cache in config ob zagonu
    cache_loaded = load_cache()
    config = load_config()
    
    # Zaznaj lokalno omrežje ali uporabi shranjeno
    network = config.get('last_network') or get_local_network()
    print(f"Zaznano/shranjeno omrežje: {network}")
    print(f"[*] By Urosk.NET - ZEN vibe coding")
    
    if config.get('preferred_interface'):
        print(f"Preferred interface: {config['preferred_interface']}")
    
    # Zaženi hitro kontinuirano skeniranje v ozadju
def get_mac_from_arp(ip):
    """Pridobi MAC naslov iz sistemske ARP tabele"""
    try:
        import subprocess
        # Preberi ARP tabelo
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ip in line and 'ether' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if ':' in part and len(part) == 17:  # MAC format xx:xx:xx:xx:xx:xx
                            return part.upper()
        
        # Alternativa z /proc/net/arp (Linux)
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != '00:00:00:00:00:00' and ':' in mac:
                            return mac.upper()
        except:
            pass
            
    except Exception as e:
        logger.debug(f"Failed to get MAC from ARP for {ip}: {e}")
    
    return None

def analyze_device_with_ai(hostname, mac, vendor, os_info, ports):
    """Analiziraj napravo z AI in vrni predlog"""
    config = load_config()
    ai_settings = config.get('ai_settings', {})
    
    if not ai_settings.get('enabled') or not ai_settings.get('api_key'):
        return None
    
    # Pripravi podatke za AI
    device_info = {
        'hostname': hostname or 'Unknown',
        'mac_address': mac or 'Unknown',
        'vendor': vendor or 'Unknown', 
        'os': os_info or 'Unknown',
        'open_ports': [f"{p['port']}/{p['protocol']} ({p['service']})" for p in (ports or [])]
    }
    
    prompt = f"""Analiziraj to omrežno napravo in povej kaj verjetno je:

Podatki o napravi:
- Hostname: {device_info['hostname']}
- MAC naslov: {device_info['mac_address']}
- Vendor: {device_info['vendor']}
- OS: {device_info['os']}
- Odprte vrate: {', '.join(device_info['open_ports']) if device_info['open_ports'] else 'Ni podatkov'}

Odgovori SAMO s kratkim opisom naprave (npr. "Samsung pametni televizor", "Raspberry Pi server", "iPhone telefon", "HP tiskalnik", "Xiaomi router", "Windows računalnik") brez dodatnih razlag."""

    try:
        if ai_settings.get('provider') == 'openai':
            headers = {
                'Authorization': f"Bearer {ai_settings['api_key']}",
                'Content-Type': 'application/json'
            }
            
            data = {
                'model': 'gpt-3.5-turbo',
                'messages': [
                    {'role': 'system', 'content': 'Si strokovnjak za analizo omrežnih naprav. Odgovarjaš kratko in natančno.'},
                    {'role': 'user', 'content': prompt}
                ],
                'max_tokens': 50,
                'temperature': 0.3
            }
            
            response = requests.post(
                'https://api.openai.com/v1/chat/completions',
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_description = result['choices'][0]['message']['content'].strip()
                return ai_description
            else:
                logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return None
    
    return None

def detect_device_type(hostname, vendor, os_info, ports):
    """Zaznaj tip naprave na podlagi dostopnih informacij"""
    hostname = (hostname or '').lower()
    vendor = (vendor or '').lower()
    os_info = (os_info or '').lower()
    port_numbers = [p['port'] for p in ports] if ports else []
    
    # Router/Gateway detection
    if any(word in hostname for word in ['router', 'gateway', 'fritz', 'tp-link', 'netgear']):
        return 'router'
    if any(word in vendor for word in ['cisco', 'netgear', 'tp-link', 'd-link', 'linksys']):
        return 'router'
    if any(port in port_numbers for port in [23, 80, 443, 161]) and hostname.endswith(('.1', '.254')):
        return 'router'
        
    # Mobile devices
    if any(word in hostname for word in ['iphone', 'android', 'mobile', 'phone']):
        return 'mobile'
    if any(word in vendor for word in ['apple']) and any(word in hostname for word in ['iphone', 'ios']):
        return 'mobile'
        
    # Tablets
    if any(word in hostname for word in ['ipad', 'tablet']):
        return 'tablet'
        
    # Smart TV
    if any(word in hostname for word in ['tv', 'samsung-tv', 'lg-tv', 'sony-tv']):
        return 'smart_tv'
        
    # Printer
    if any(word in hostname for word in ['printer', 'canon', 'epson', 'brother', 'hp-printer']):
        return 'printer'
    if 631 in port_numbers or 9100 in port_numbers:  # IPP, HP JetDirect
        return 'printer'
        
    # NAS/Storage
    if any(word in hostname for word in ['nas', 'synology', 'qnap', 'storage']):
        return 'nas'
    if 445 in port_numbers or 2049 in port_numbers:  # SMB, NFS
        return 'nas'
        
    # IP Camera
    if any(word in hostname for word in ['camera', 'cam', 'hikvision', 'dahua']):
        return 'camera'
    if 554 in port_numbers:  # RTSP
        return 'camera'
        
    # Server detection
    web_ports = [80, 443, 8080, 8443]
    if any(port in port_numbers for port in web_ports):
        if 22 in port_numbers:  # SSH + Web = Server
            return 'server'
        return 'web_device'
        
    # Database server
    if any(port in port_numbers for port in [3306, 5432, 27017, 1433]):
        return 'database'
        
    # IoT devices
    if any(word in hostname for word in ['esp', 'arduino', 'iot', 'sensor']):
        return 'iot'
    if any(word in vendor for word in ['raspberry', 'pi foundation']):
        return 'iot'
        
    # Gaming console
    if any(word in hostname for word in ['playstation', 'xbox', 'nintendo']):
        return 'gaming'
        
    # Computer/Laptop
    if any(word in os_info for word in ['windows', 'linux', 'mac', 'ubuntu']):
        if any(word in hostname for word in ['laptop', 'macbook']):
            return 'laptop'
        return 'computer'
        
    # Apple devices
    if 'apple' in vendor:
        if any(word in hostname for word in ['macbook', 'imac']):
            return 'computer'
        if any(word in hostname for word in ['iphone']):
            return 'mobile'
        if any(word in hostname for word in ['ipad']):
            return 'tablet'
            
    # Default
    return 'unknown'

def generate_device_description(hostname, vendor, os_info, ports, device_type):
    """Generiraj opis naprave"""
    descriptions = {
        'router': 'Omrežni usmerjevalnik',
        'mobile': 'Pametni telefon',
        'tablet': 'Tablica',
        'smart_tv': 'Pametna televizija',
        'printer': 'Omrežni tiskalnik',
        'nas': 'Omrežna shramba (NAS)',
        'camera': 'IP kamera',
        'server': 'Strežnik',
        'web_device': 'Spletna naprava',
        'database': 'Podatkovni strežnik',
        'iot': 'IoT naprava',
        'gaming': 'Igralna konzola',
        'computer': 'Računalnik',
        'laptop': 'Prenosnik',
        'unknown': 'Neznana naprava'
    }
    
    base_desc = descriptions.get(device_type, 'Neznana naprava')
    
    # Add vendor info
    if vendor:
        base_desc += f' ({vendor.title()})'
        
    # Add OS info if available
    if os_info:
        base_desc += f' - {os_info}'
        
    # Add service count
    if ports:
        service_count = len(ports)
        base_desc += f' - {service_count} storitev'
        
    return base_desc

if __name__ == '__main__':
    print("[*] Zaganjam real-time network scanner...")
    scanner_thread = threading.Thread(target=continuous_background_scanner)
    scanner_thread.daemon = True
    scanner_thread.start()
    
    print("[*] Naprave se bodo prikazale v nekaj sekundah...")
    print(f"[*] Odprite http://localhost:5000 v brskalniku")
    
    app.run(host='0.0.0.0', port=5000, debug=False)  # Debug=False da se ne restartira
