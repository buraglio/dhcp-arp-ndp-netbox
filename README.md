# dhcp-arp-2-netbox

Convert ARP and DHCP leases to Netbox entries.

This script takes the output from a Mikrotik router's ARP table, IPv6 neighbor table, and DHCP leases, then correlates and creates a structured CSV file suitable for importing directly into Netbox as IP Addresses. 

The script dynamically matches IP addresses to MAC Addresses, Hostnames, and maps any `vlan.$ID` interface structure into a strict `$ID` format so it correctly links to your VLAN definitions inside Netbox.

## Usage

This project uses Python. The easiest way to run it is with `uv`, which reads standard inline dependency declarations and runs it directly, aoiding the venv nonsense. 

```bash
uv run convert_to_netbox.py
```

### Options

The script provides the following argument flags to let you limit execution appropriately:

*   `--leases` /path/to/leases.txt : Custom path to leases file (Default: `leases.txt`)
*   `--arp` /path/to/arp.txt : Custom path to IPv4 ARP table (Default: `arp.txt`)
*   `--ndp` /path/to/ndp.txt : Custom path to IPv6 Neighbors table (Default: `ipv6-neighbors.txt`)
*   `--output` /path/to/output.csv : Destination for processed Netbox CSV (Default: `netbox_import.csv`)
*   `--ipv4` : **Only export IPv4 addresses.**
*   `--ipv6` : **Only export IPv6 addresses.**
*   `--no-slaac` : **Exclude SLAAC (EUI-64 derived) IPv6 addresses.**

#### Examples:

Export **everything** to `custom_output.csv`:
```bash
uv run convert_to_netbox.py --output custom_output.csv
```

Export **only IPv4** entries:
```bash
uv run convert_to_netbox.py --ipv4
```

Export **only IPv6** entries:
```bash
uv run convert_to_netbox.py --ipv6
```

Export **only IPv6**, but exclude any SLAAC generated interfaces (EUI-64):
```bash
uv run convert_to_netbox.py --ipv6 --no-slaac
```
