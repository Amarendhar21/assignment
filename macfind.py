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

def retrieve_ifdescr_mapping(agent):
    ifindex_to_name = {}
    session = Session(hostname=agent['ip'], community=agent['community'], version=2, remote_port=agent['port'])
    try:
        entries = session.bulkwalk(IFDESCR_OID)
        for entry in entries:
            try:
                if entry.oid_index == '':
                    ifindex_str = entry.oid.split('.')[-1]
                else:
                    ifindex_str = entry.oid_index.replace('.', '')

                ifindex = int(ifindex_str)
                ifindex_to_name[ifindex] = entry.value
            except (ValueError, AttributeError):
                continue
        return ifindex_to_name
    except Exception:
        return {}


def retrieve_mac_addresses(agent):
    mac_table = {}
    session = Session(hostname=agent['ip'], community=agent['community'], version=2, remote_port=agent['port'])
    try:
        entries = session.bulkwalk(FDB_PORT_OID)
        for entry in entries:
            try:
                if entry.oid_index == '':
                    mac_parts = entry.oid.split('.')[-6:]
                else:
                    mac_parts = [p for p in entry.oid_index.split('.') if p != '']

                if len(mac_parts) != 6:
                    continue

                mac_address = ':'.join(f"{int(part):02x}" for part in mac_parts)

                if not entry.value or entry.value == '0':
                    continue

                bridge_port = int(entry.value)
                mac_table[mac_address] = bridge_port
            except (ValueError, AttributeError):
                continue
        return mac_table
    except Exception:
        return {}

def main():
    args = parse_arguments()
    agents = [parse_agent(agent) for agent in args.agents]
    requested_macs = set()
    for mac in args.macs:
        try:
            requested_macs.add(normalize_mac(mac))
        except ValueError as e:
            print(f"Warning: {e}")

    results = {mac: [] for mac in requested_macs}
    all_switch_macs = {}
    global_switch_macs = set()
    for agent in agents:
        all_switch_macs[agent['ip']] = retrieve_switch_macs(agent)
        global_switch_macs.update(all_switch_macs[agent['ip']])

    for agent in agents:
        start_uptime = get_sysuptime(agent)
        if start_uptime is None:
            continue

        mac_table = retrieve_mac_addresses(agent)
        if not mac_table:
            continue

 # Build reverse mapping: bridge_port -> list of MACs
        port_macs = {}
        for mac, bp in mac_table.items():
            port_macs.setdefault(bp, []).append(mac)
        port_mac_count = {bp: len(macs) for bp, macs in port_macs.items()}

        bridge_mapping = retrieve_ifindex_mapping(agent)
        ifdescr_mapping = retrieve_ifdescr_mapping(agent)

        end_uptime = get_sysuptime(agent)
        if end_uptime is None:
            continue

        if end_uptime < start_uptime:
            print(f"Agent {agent['ip']} has RESET — results from this agent may be stale")
            continue

        # MATCHING LOGIC: Iterate ONLY over requested MACs to prevent console spam
        for req_mac in requested_macs:
            if req_mac not in mac_table:
                continue # Will be reported as NOT FOUND at the end

            bridge_port = mac_table[req_mac]
            if bridge_port not in bridge_mapping:
                continue

            ifindex = bridge_mapping[bridge_port]
            interface_name = ifdescr_mapping.get(ifindex, "UNKNOWN")
            mac_count = port_mac_count.get(bridge_port, 0)

   # Cross-reference to detect uplinks
            is_uplink = False
            for mac_on_port in port_macs.get(bridge_port, []):
                if mac_on_port in global_switch_macs and mac_on_port not in all_switch_macs[agent['ip']]:
                    is_uplink = True
                    break

            port_type = "uplink" if is_uplink else classify_port(interface_name, mac_count, args.uplink_pattern)

            results[req_mac].append({
                "agent": agent["ip"],
                "port": interface_name,
                "type": port_type
            })

    # Final Reporting (Exact spacing per assignment spec: two spaces around pipes)
    print("\n==============================")
    print("FINAL REPORT")
    print("==============================")

    for mac in requested_macs:
        if len(results[mac]) == 0:
            print(f"{mac}  |  NOT FOUND")
        else:
            for entry in results[mac]:
                print(f"{mac}  |  {entry['agent']}  |  {entry['port']}  |  {entry['type']}")


                
if __name__ == "__main__":
    main()