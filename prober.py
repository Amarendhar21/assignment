#!/usr/bin/env python3
import argparse
import re
from collections import defaultdict
from easysnmp import Session

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'
BASE_PORT_IFINDEX_OID = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR_OID = '1.3.6.1.2.1.2.2.1.2'
IFNAME_OID = '1.3.6.1.2.1.31.1.1.1.1'  # NEW: Fallback for human-readable names
IFPHYSADDRESS_OID = '1.3.6.1.2.1.2.2.1.6'


def classify_port(interface_name, mac_count, uplink_pattern):
    name = interface_name.lower()
    if re.search(uplink_pattern, interface_name, re.IGNORECASE):
        return "uplink"
    if "gigabitethernet" in name or "fastethernet" in name or "access" in name:
        return "edge"
    if mac_count > 1:
        return "uplink"
    return "edge"


def main():
    parser = argparse.ArgumentParser(description="SNMP Switch Prober")
    parser.add_argument('--host', required=True, help='Switch IP address')
    parser.add_argument('--community', required=True, help='SNMP community string')
    parser.add_argument('--version', default='2c', choices=['2c', '3'], help='SNMP version')
    parser.add_argument('--port', type=int, default=161, help='SNMP port (default: 161)')
    parser.add_argument('--timeout', type=int, default=5, help='SNMP timeout in seconds')
    parser.add_argument('--retries', type=int, default=2, help='SNMP retries')
    parser.add_argument('--uplink-pattern', default='TenGig|Port-channel|Uplink', help='Regex pattern for uplink interfaces')
    
    args = parser.parse_args()
    print(f"Probing switch: {args.host} (SNMP Port: {args.port})")
    print("=" * 120)

    try:
        session = Session(
            hostname=args.host, community=args.community, version=2 if args.version == '2c' else 3,
            remote_port=args.port, timeout=args.timeout, retries=args.retries
        )
    except Exception as e:
        print(f"Failed to create SNMP session: {e}")
        return

    # 1. Get Switch's own MAC addresses
    switch_macs = set()
    try:
        for entry in session.bulkwalk(IFPHYSADDRESS_OID):
            try:
                mac_val = entry.value.replace(':', '').replace('-', '').lower()
                if len(mac_val) == 12:
                    switch_macs.add(':'.join(mac_val[i:i+2] for i in range(0, 12, 2)))
            except (ValueError, AttributeError):
                continue
    except Exception:
        pass

    # 2. Walk FDB Table
    mac_table = {}
    try:
        for entry in session.bulkwalk(FDB_PORT_OID):
            try:
                mac_parts = entry.oid.split('.')[-6:] if entry.oid_index == '' else [p for p in entry.oid_index.split('.') if p != '']
                if len(mac_parts) == 6 and entry.value and entry.value != '0':
                    mac_table[':'.join(f"{int(p):02x}" for p in mac_parts)] = int(entry.value)
            except (ValueError, AttributeError):
                continue
    except Exception as e:
        print(f"Error walking FDB table: {e}")
        return

    # 3. Walk Bridge Port to ifIndex
    bridge_to_ifindex = {}
    try:
        for entry in session.bulkwalk(BASE_PORT_IFINDEX_OID):
            try:
                bp_str = entry.oid.split('.')[-1] if entry.oid_index == '' else entry.oid_index.replace('.', '')
                bridge_to_ifindex[int(bp_str)] = int(entry.value)
            except (ValueError, AttributeError):
                continue
    except Exception:
        pass

    # 4. Walk ifDescr AND ifName (with smart fallback)
    ifindex_to_name = {}
    try:
        for entry in session.bulkwalk(IFDESCR_OID):
            try:
                idx_str = entry.oid.split('.')[-1] if entry.oid_index == '' else entry.oid_index.replace('.', '')
                ifindex_to_name[int(idx_str)] = entry.value
            except (ValueError, AttributeError):
                continue
        
        # SMART FALLBACK: Override numeric ifDescr with ifName
        for entry in session.bulkwalk(IFNAME_OID):
            try:
                idx_str = entry.oid.split('.')[-1] if entry.oid_index == '' else entry.oid_index.replace('.', '')
                ifindex = int(idx_str)
                current_name = ifindex_to_name.get(ifindex, "")
                if current_name.isdigit() and not entry.value.isdigit():
                    ifindex_to_name[ifindex] = entry.value
            except (ValueError, AttributeError):
                continue
    except Exception:
        pass

    # 5. Group MACs by Bridge Port
    port_macs = defaultdict(list)
    for mac, bp in mac_table.items():
        port_macs[bp].append(mac)

    # 6. Generate Validation Report
    print(f"\n{'Bridge Port':<12} | {'ifIndex':<8} | {'Interface Name':<25} | {'Type':<8} | {'MAC Count':<10} | {'MAC Addresses'}")
    print("-" * 120)

    for bp in sorted(port_macs.keys()):
        macs = port_macs[bp]
        ifindex = bridge_to_ifindex.get(bp, "N/A")
        iface_name = ifindex_to_name.get(ifindex, "UNKNOWN") if ifindex != "N/A" else "UNKNOWN"
        port_type = classify_port(iface_name, len(macs), args.uplink_pattern)

        macs_display = ", ".join(macs[:4])
        if len(macs) > 4:
            macs_display += f" ... (+{len(macs) - 4} more)"

        print(f"{bp:<12} | {str(ifindex):<8} | {iface_name:<25} | {port_type:<8} | {len(macs):<10} | {macs_display}")

    print("=" * 120)
    print(f"Probing complete. Total unique MACs found on switch: {len(mac_table)}")


if __name__ == "__main__":
    main()
else:
    print("example: python3 snmp_prober.py --host 192.168.184.191 --community public")