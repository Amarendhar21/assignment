import argparse
import re
from easysnmp import Session

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'
BASE_PORT_IFINDEX_OID = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR_OID = '1.3.6.1.2.1.2.2.1.2'
SYSUPTIME_OID = '1.3.6.1.2.1.1.3.0'
IFPHYSADDRESS_OID = '1.3.6.1.2.1.2.2.1.6'

def normalize_mac(mac_str):
    clean = mac_str.replace(':', '').replace('-', '').replace('.', '').lower()
    if len(clean) != 12 or not all(c in '0123456789abcdef' for c in clean):
        raise ValueError(f"Invalid MAC address format: {mac_str}")
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def parse_arguments():
    parser = argparse.ArgumentParser(description="SNMP MAC Finder")
    parser.add_argument('--macs', nargs='+', required=True, help='MAC addresses to search for')
    parser.add_argument('--agents', nargs='+', required=True, help='SNMP agents in ip:port:community format')
    parser.add_argument('--version', default='2c', choices=['2c', '3'])
    parser.add_argument('--timeout', type=int, default=5)
    parser.add_argument('--retries', type=int, default=2)
    parser.add_argument('--uplink-pattern', default='TenGig|Port-channel|Uplink')
    return parser.parse_args()

def parse_agent(agent_string):
    ip, port, community = agent_string.split(':')
    return {'ip': ip, 'port': int(port), 'community': community}


def get_sysuptime(agent):
    session = Session(hostname=agent['ip'], community=agent['community'], version=2, remote_port=agent['port'])
    try:
        result = session.get(SYSUPTIME_OID)
        return int(result.value)
    except Exception as e:
        print(f"TIMEOUT: agent {agent['ip']} did not respond")
        return None


def retrieve_switch_macs(agent):
    switch_macs = set()
    session = Session(hostname=agent['ip'], community=agent['community'], version=2, remote_port=agent['port'])
    try:
        entries = session.bulkwalk(IFPHYSADDRESS_OID)
        for entry in entries:
            try:
                mac_val = entry.value.replace(':', '').replace('-', '').lower()
                if len(mac_val) == 12:
                    normalized = ':'.join(mac_val[i:i+2] for i in range(0, 12, 2))
                    switch_macs.add(normalized)
            except (ValueError, AttributeError):
                continue
        return switch_macs
    except Exception:
        return set()

def classify_port(interface_name, mac_count, uplink_pattern):
    name = interface_name.lower()
    if re.search(uplink_pattern, interface_name, re.IGNORECASE):
        return "uplink"
    if "gigabitethernet" in name or "fastethernet" in name or "access" in name:
        return "edge"
    if mac_count > 1:
        return "uplink"
    return "edge"


def retrieve_ifindex_mapping(agent):
    bridge_to_ifindex = {}
    session = Session(hostname=agent['ip'], community=agent['community'], version=2, remote_port=agent['port'])
    try:
        entries = session.bulkwalk(BASE_PORT_IFINDEX_OID)
        for entry in entries:
            try:
                if entry.oid_index == '':
                    bridge_port_str = entry.oid.split('.')[-1]
                else:
                    bridge_port_str = entry.oid_index.replace('.', '')
                
                bridge_port = int(bridge_port_str)
                ifindex = int(entry.value)
                bridge_to_ifindex[bridge_port] = ifindex
            except (ValueError, AttributeError):
                continue
        return bridge_to_ifindex
    except Exception:
        return {}






        
if __name__ == "__main__":
    main()