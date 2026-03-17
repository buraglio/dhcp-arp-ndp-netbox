# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import re
import csv
import ipaddress
import argparse
from pathlib import Path

def parse_leases(file_path):
    leases = {}
    mac_re = re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
    
    if not Path(file_path).exists():
        return leases

    with open(file_path, 'r', encoding='utf-8') as f:
        last_comment = ""
        for line in f:
            line = line.strip()
            if line.startswith(';;;'):
                last_comment = line[3:].strip()
                continue
            
            match = mac_re.search(line)
            if match:
                mac = match.group(0).upper()
                parts = line.split()
                
                try:
                    mac_idx = parts.index(match.group(0))
                    ip_str = parts[mac_idx - 1]
                    
                    # Validate IP
                    ip = ipaddress.ip_address(ip_str)
                    
                    status_idx = -1
                    if 'bound' in parts:
                        status_idx = parts.index('bound')
                    elif 'waiting' in parts:
                        status_idx = parts.index('waiting')
                        
                    hostname = ""
                    server = ""
                    
                    if status_idx != -1 and status_idx > mac_idx:
                        server = parts[status_idx - 1]
                        hostname_parts = parts[mac_idx + 1 : status_idx - 1]
                        if hostname_parts:
                            hostname = " ".join(hostname_parts)
                    
                    if not hostname and last_comment:
                        hostname = last_comment

                    leases[str(ip)] = {
                        'mac': mac,
                        'hostname': hostname,
                        'server': server,
                        'source': 'lease'
                    }
                except ValueError:
                    pass # Ignore if not valid IP or IP not found correctly
            
            # Reset comment if this isn't a comment line
            if not line.startswith(';;;'):
                last_comment = ""
                
    return leases

def parse_arp_ndp(file_path, source_type):
    entries = {}
    mac_re = re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
    
    if not Path(file_path).exists():
        return entries

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            match = mac_re.search(line)
            if match:
                mac = match.group(0).upper()
                parts = line.split()
                
                try:
                    mac_idx = parts.index(match.group(0))
                    ip_str = parts[mac_idx - 1]
                    
                    # Validate IP
                    ip = ipaddress.ip_address(ip_str)
                    
                    interface = ""
                    if len(parts) > mac_idx + 1:
                        interface = parts[mac_idx + 1]

                    entries[str(ip)] = {
                        'mac': mac,
                        'interface': interface,
                        'source': source_type
                    }
                except ValueError:
                    pass
    return entries

def extract_vlan_id(interface):
    if interface and interface.startswith('vlan.'):
        try:
            return int(interface.split('.')[1])
        except (IndexError, ValueError):
            return None
    return None

def is_slaac_eui64(ip_obj, mac_str):
    if not mac_str:
        return False
    packed = ip_obj.packed
    # Quick check for FF:FE in the middle of the IID
    if packed[11] == 0xff and packed[12] == 0xfe:
        mac_parts = mac_str.split(':')
        if len(mac_parts) == 6:
            try:
                b0 = int(mac_parts[0], 16) ^ 0x02
                expected_iid = [
                    b0, int(mac_parts[1], 16), int(mac_parts[2], 16),
                    0xff, 0xfe,
                    int(mac_parts[3], 16), int(mac_parts[4], 16), int(mac_parts[5], 16)
                ]
                if list(packed[8:]) == expected_iid:
                    return True
            except ValueError:
                pass
    return False

def main():
    parser = argparse.ArgumentParser(description="Convert Mikrotik ARP/NDP and DHCP leases to Netbox CSV.")
    parser.add_argument('--leases', default='leases.txt', help='Path to initial DHCP leases file.')
    parser.add_argument('--arp', default='arp.txt', help='Path to ARP file.')
    parser.add_argument('--ndp', default='ipv6-neighbors.txt', help='Path to IPv6 Neighbors file.')
    parser.add_argument('--output', default='netbox_import.csv', help='Output CSV file.')
    parser.add_argument('--ipv4', action='store_true', help='Only include IPv4 addresses.')
    parser.add_argument('--ipv6', action='store_true', help='Only include IPv6 addresses.')
    parser.add_argument('--no-slaac', action='store_true', help='Exclude IPv6 SLAAC (EUI-64 derived) addresses.')
    args = parser.parse_args()

    # Data collection
    ip_records = {} # Combine everything here by IP address
    
    print(f"Parsing leases from {args.leases}...")
    leases = parse_leases(args.leases)
    
    print(f"Parsing ARP from {args.arp}...")
    arp = parse_arp_ndp(args.arp, 'arp')
    
    print(f"Parsing NDP (IPv6) from {args.ndp}...")
    ndp = parse_arp_ndp(args.ndp, 'ndp')
    
    # Merge strategy: Leases form base for IPv4, ARP adds missing IPv4 / provides interfaces.
    # NDP provides base for IPv6.
    
    all_ips = set(list(leases.keys()) + list(arp.keys()) + list(ndp.keys()))
    
    results = []
    
    for ip_str in all_ips:
        ip_obj = ipaddress.ip_address(ip_str)
        
        if args.ipv4 and ip_obj.version != 4:
            continue
        if args.ipv6 and ip_obj.version != 6:
            continue
            
        entry = {
            'address': '',
            'status': 'active',
            'dns_name': '',
            'description': '',
            'tags': ''
        }
        
        # Determine CIDR format for import
        if ip_obj.version == 4:
            entry['address'] = f"{ip_str}/32"
        else:
            entry['address'] = f"{ip_str}/128"
            
        # Collect merged info
        mac = ""
        hostname = ""
        interface = ""
        sources = []
        
        if ip_str in leases:
            mac = leases[ip_str]['mac']
            hostname = leases[ip_str]['hostname']
            sources.append('lease')
            
        if ip_str in arp:
            if not mac:
                mac = arp[ip_str]['mac']
            interface = arp[ip_str]['interface']
            sources.append('arp')
            
        if ip_str in ndp:
            if not mac:
                mac = ndp[ip_str]['mac']
            interface = ndp[ip_str]['interface']
            sources.append('ndp')
            
        if args.no_slaac and ip_obj.version == 6 and mac:
            if is_slaac_eui64(ip_obj, mac):
                continue
            
        entry['mac_address'] = mac
        if hostname:
            entry['dns_name'] = hostname
            
        vlan_id = extract_vlan_id(interface)
        if vlan_id is not None:
            entry['tags'] = f"vlan-{vlan_id}"
            
        desc_parts = []
        if mac:
            desc_parts.append(f"MAC: {mac}")
        if interface:
            desc_parts.append(f"Intf: {interface}")
        if hostname:
            desc_parts.append(f"Host: {hostname}")
        if sources:
            desc_parts.append(f"Src: {','.join(sources)}")
            
        entry['description'] = " | ".join(desc_parts)
        results.append(entry)

    # Sort results properly
    def sort_key(x):
        ip = ipaddress.ip_address(x['address'].split('/')[0])
        return (ip.version, int(ip))
        
    results.sort(key=sort_key)
    
    # Write to CSV
    headers = ['address', 'status', 'dns_name', 'description', 'tags']
    
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)
        
    print(f"Exported {len(results)} records to {args.output}")

if __name__ == '__main__':
    main()
