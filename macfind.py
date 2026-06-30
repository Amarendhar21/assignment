#!/usr/bin/python3
import argparse
import re
import logging
from easysnmp import Session


logging.basicConfig(
    filename='Nsologs.txt',
    filemode='a',
    level=logging.DEBUG,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'
BASE_PORT_IFINDEX_OID = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR_OID = '1.3.6.1.2.1.2.2.1.2'
IFNAME_OID = '1.3.6.1.2.1.31.1.1.1.1'
IFALIAS_OID = '1.3.6.1.2.1.31.1.1.1.18'  # NEW: For operator-assigned labels
SYSUPTIME_OID = '1.3.6.1.2.1.1.3.0'
IFPHYSADDRESS_OID = '1.3.6.1.2.1.2.2.1.6'
SYSDESCR_OID = '1.3.6.1.2.1.1.1.0'


def normalize_mac(mac_str):
    clean = mac_str.replace(':', '').replace('-', '').replace('.', '').lower()
    if len(clean) != 12 or not all(c in '0123456789abcdef' for c in clean):
        raise ValueError(f"Invalid MAC address format: {mac_str}")
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def parse_arguments():
    parser = argparse.ArgumentParser(description="SNMP MAC Finder")
    parser.add_argument('--macs', nargs='+', required=True, help='MAC addresses to search for')
    parser.add_argument('--agents', nargs='+', required=True, help='SNMP agents in ip:port:community format')
    parser.add_argument('--timeout', type=int, default=5)
    parser.add_argument('--retries', type=int, default=2)
    parser.add_argument('--uplink-pattern', default='TenGig|Port-channel|Uplink')
    return parser.parse_args()


def parse_agent(agent_string):
    ip, port, community = agent_string.split(':')
    return {'ip': ip, 'port': int(port), 'community': community}

# detect snmp version of an agent
def detect_snmp_capabilities(agent):
    # Uses the agent's configured timeout default 5 seconds but forces only 1 retry for fast-fail detection.                                            
    probe_timeout = agent.get('timeout', 5)
    probe_retries = 1

    for version_str, easysnmp_ver in [('2c', 2), ('1', 1)]:
        logger.debug(f"Probing SNMPv{version_str} for {agent['ip']}...") # prober snmpversion2 for ip 
        try:
            session = Session(
                hostname=agent['ip'],
                community=agent['community'],
                version=easysnmp_ver,
                remote_port=agent['port'],
                timeout=probe_timeout,
                retries=probe_retries
            )
            result = session.get(SYSDESCR_OID)
            if result and result.value:
                logger.debug(f"SNMPv{version_str} probe successful for {agent['ip']}.")
                return version_str, result.value.strip()
        # Log the exact exception type e.g., EasySNMPTimeoutError, ConnectionRefusedError.
        # continue jumps to the next iteration (try the other SNMP version).             
        except Exception as e:
            logger.debug(f"SNMPv{version_str} probe failed for {agent['ip']}: {type(e).__name__}")
            continue
            
    return None, "UNKNOWN"

# Defines a function that takes one agent dictionary containing IP, community, version.
def get_sysuptime(agent):
    try:
        session = Session(
            hostname=agent['ip'], 
            community=agent['community'], 
            version=agent.get('version', 2), 
            remote_port=agent['port'],
            timeout=agent.get('timeout', 5),
            retries=agent.get('retries', 2)
        )
        result = session.get(SYSUPTIME_OID)
        return int(result.value)
    except Exception:
        print(f"TIMEOUT: agent {agent['ip']} did not respond")
        return None


def retrieve_switch_macs(agent):
    switch_macs = set()
    try:
        session = Session(
            hostname=agent['ip'], 
            community=agent['community'], 
            version=agent.get('version', 2), 
            remote_port=agent['port'],
            timeout=agent.get('timeout', 5),
            retries=agent.get('retries', 2)
        )
        entries = session.bulkwalk(IFPHYSADDRESS_OID)
        for entry in entries:
            try:
                mac_val = entry.value.replace(':', '').replace('-', '').lower()
                if len(mac_val) == 12:
                    normalized = ':'.join(mac_val[i:i+2] for i in range(0, 12, 2))
                    switch_macs.add(normalized)
            except (ValueError, AttributeError):
                continue
    except Exception as e:
        logger.debug(f"Failed to retrieve switch MACs from {agent['ip']}: {e}")
    return switch_macs

    
def classify_port(interface_name, mac_count, uplink_pattern):
    name = interface_name.lower()
    if re.search(uplink_pattern, interface_name, re.IGNORECASE):
        return "uplink"
    if "gigabitethernet" in name or "fastethernet" in name or "access" in name:
        return "edge"
    if mac_count > 1:
        return "uplink"
    return "edge"

# in bridge port initialise the empty dictionary to store the mapping
def retrieve_ifindex_mapping(agent):
    bridge_to_ifindex = {}
    try:
        # snmp session to target switch using dynamically passed credentials all this sessions 
        session = Session(
            hostname=agent['ip'], 
            community=agent['community'], 
            version=agent.get('version', 2), 
            remote_port=agent['port'],
            timeout=agent.get('timeout', 5),
            retries=agent.get('retries', 2)
        )
        entries = session.bulkwalk(BASE_PORT_IFINDEX_OID) # performs an snmp Getbulk walk on OID 
        # using the for loop, ifindex from the snmp value 
        # converts the both to integers, if parsing fails skips to the next row (continue)
        for entry in entries:
            try:
                # OID index is stored in the entry.oid.index and it's empty must be extracted from the full entry.oid string.
                if entry.oid_index == '':
                    bridge_port_str = entry.oid.split('.')[-1]
                else:
                    bridge_port_str = entry.oid_index.replace('.', '')
                # Converts both the bridge port number from the OID suffix and the ifIndex from the SNMP value into Python integers.
                bridge_port = int(bridge_port_str) #integer 
                ifindex = int(entry.value)
                bridge_to_ifindex[bridge_port] = ifindex # store the mappingin the dictionary
            except (ValueError, AttributeError):
                continue
    except Exception as e:
        logger.debug(f"Failed to retrieve ifIndex mapping from {agent['ip']}: {e}")
    return bridge_to_ifindex


def retrieve_ifdescr_mapping(agent):
    ifindex_to_name = {} # in ifindex it queries two snmp table ifdescr and ifname 
    try:
        session = Session(
            hostname=agent['ip'], 
            community=agent['community'], 
            version=agent.get('version', 2), 
            remote_port=agent['port'],
            timeout=agent.get('timeout', 5),
            retries=agent.get('retries', 2)
        )
        
        # 1. Walk ifDescr 
        descr_entries = session.bulkwalk(IFDESCR_OID)
        for entry in descr_entries:
            try:
                # ifIndex from the OID suffix same logic as before handles entry.oid_index being empty by splitting entry.oid and taking the last piece.
                if entry.oid_index == '':
                    ifindex_str = entry.oid.split('.')[-1]
                else:
                    ifindex_str = entry.oid_index.replace('.', '')
                ifindex_to_name[int(ifindex_str)] = entry.value 
            except (ValueError, AttributeError):
                continue

        # 2. SMART FALLBACK: Walk ifName
        name_entries = session.bulkwalk(IFNAME_OID)
        for entry in name_entries:
            try:
                if entry.oid_index == '':
                    ifindex_str = entry.oid.split('.')[-1]
                else:
                    ifindex_str = entry.oid_index.replace('.', '')
                
                ifindex = int(ifindex_str)
                current_name = ifindex_to_name.get(ifindex, "")
                
                if current_name.isdigit() and not entry.value.isdigit():
                    ifindex_to_name[ifindex] = entry.value
            except (ValueError, AttributeError):
                continue

        # 3. Walk ifAlias (operator-assigned labels take highest priority)
        alias_entries = session.bulkwalk(IFALIAS_OID)
        for entry in alias_entries:
            try:
                if entry.oid_index == '':
                    ifindex_str = entry.oid.split('.')[-1]
                else:
                    ifindex_str = entry.oid_index.replace('.', '')
                
                ifindex = int(ifindex_str)
                alias = entry.value.strip() if entry.value else ""
                if alias:  # Only overwrite if alias is actually set
                    ifindex_to_name[ifindex] = alias
            except (ValueError, AttributeError):
                continue

    except Exception as e:
        logger.debug(f"Failed to retrieve interface names from {agent['ip']}: {e}")
        
    return ifindex_to_name

# MAC addresses to the Bridge port numbers.
def retrieve_mac_addresses(agent):
    mac_table = {} 
    try:
        session = Session(
            hostname=agent['ip'], 
            community=agent['community'], 
            version=agent.get('version', 2), 
            remote_port=agent['port'],
            timeout=agent.get('timeout', 5),
            retries=agent.get('retries', 2)
        )
        # for loop entries the easy snmp objects returned by session.bulkwalk().
        entries = session.bulkwalk(FDB_PORT_OID)
    
        for entry in entries:
            try:
                # Extracts the MAC from the OID. SNMP doesn't store the MAC in the value field. It encodes it as 6 decimal numbers at the end of the OID. This handles the easysnmp quirk where the index might be empty or already split.
                if entry.oid_index == '':
                    mac_parts = entry.oid.split('.')[-6:]
                else:
                    mac_parts = [p for p in entry.oid_index.split('.') if p != '']
                # MAC address always has exactly 6 octets. If the OID suffix has more or fewer parts, it's not a valid MAC → skip it.
                if len(mac_parts) != 6:
                    continue
                # Converts Decimal → Hex. SNMP returns MAC octets as decimal (e.g., 0, 17, 34, 51, 68, 85). This line converts each to 2-digit lowercase hex (00, 11, 22, 33, 44, 55) and joins them with colons.
                mac_address = ':'.join(f"{int(part):02x}" for part in mac_parts)
                # Bridge port 0 means learned but not assigned to a physical port. We ignore it.
                if not entry.value or entry.value == '0':
                    continue
                # actual SNMP value for this table is the bridge port number.
                bridge_port = int(entry.value)
                mac_table[mac_address] = bridge_port # save to dictionary Maps the clean MAC string to its port.
            except (ValueError, AttributeError):
                continue
        # If a row is malformed (bad hex, missing value, etc.), skip it and move to the next row without crashing.
    except Exception as e:
        logger.debug(f"Failed to retrieve MAC table from {agent['ip']}: {e}")
    return mac_table


def main():
    args = parse_arguments()
    agents = [parse_agent(agent) for agent in args.agents]
    
    # 1 Apply timeout/retries to ALL agents & Purpose: Ensures every switch uses the same timeout/retry settings from the CLI.
    for agent in agents:
        agent['timeout'] = args.timeout
        agent['retries'] = args.retries

    requested_macs = set()
    # 2 normalize Requested MACs & Converts user input like aabb.ccdd.eeff into a clean aa:bb:cc:dd:ee:ff.
    for mac in args.macs:
        try:
            requested_macs.add(normalize_mac(mac))
        except ValueError as e:
            print(f"Warning: {e}")
            logger.warning(f"Invalid MAC skipped: {e}")

    results = {mac: [] for mac in requested_macs}
    all_switch_macs = {}
    global_switch_macs = set()

    for agent in agents:
        # 3 Robust SNMP Version & Model Detection 
        detected_version, sys_descr = detect_snmp_capabilities(agent)
        
        if detected_version is None:
            # REQUIRED BY SPEC: Must print to stdout
            print(f"TIMEOUT: agent {agent['ip']} did not respond")
            continue
            
        # RESTORED: High-value status visible to user
        logger.info(f"Agent {agent['ip']} -> {sys_descr} (SNMP {detected_version})")
        
        # Update agent dict for subsequent walks
        agent['version'] = 2 if detected_version == '2c' else 1
        agent['sys_descr'] = sys_descr
        
        all_switch_macs[agent['ip']] = retrieve_switch_macs(agent)
        global_switch_macs.update(all_switch_macs[agent['ip']])

        start_uptime = get_sysuptime(agent)
        if start_uptime is None:
            continue

        mac_table = retrieve_mac_addresses(agent) # get mac: bridge port 
        logger.info(f"{agent['ip']} retrieved {len(mac_table)} MAC entries")
        if not mac_table:
            continue

        port_macs = {}
        for mac, bp in mac_table.items():
            port_macs.setdefault(bp, []).append(mac)
        port_mac_count = {bp: len(macs) for bp, macs in port_macs.items()} # for the edge/uplink 

        bridge_mapping = retrieve_ifindex_mapping(agent) # walk bridge port to ifindex
        ifdescr_mapping = retrieve_ifdescr_mapping(agent) # walk ifindex to interface name

        # Layer 4: Synthesize Port-<N> for any remaining numeric/empty names
        for ifindex, name in ifdescr_mapping.items():
            if not name or name.isdigit():
                ifdescr_mapping[ifindex] = f"Port-{ifindex}"

        end_uptime = get_sysuptime(agent)
        if end_uptime is None:
            continue

        if end_uptime < start_uptime:
            print(f"Agent {agent['ip']} has RESET — results from this agent may be stale")
            continue
        # 4 translate bridge port to ifIndex to interface name, classify as edge/uplink.
        for req_mac in requested_macs:
            if req_mac not in mac_table:
                continue

            bridge_port = mac_table[req_mac]
            if bridge_port not in bridge_mapping:
                continue

            ifindex = bridge_mapping[bridge_port]
            interface_name = ifdescr_mapping.get(ifindex, "UNKNOWN")
            mac_count = port_mac_count.get(bridge_port, 0)

            is_uplink = False
            # 5 mac learn on this port belong to another switch 
            # this port is connected to another switch to label as uplink
            for mac_on_port in port_macs.get(bridge_port, []):
                if mac_on_port in global_switch_macs and mac_on_port not in all_switch_macs[agent['ip']]:
                    is_uplink = True
                    break
            # break: Stop checking once we find one matching switch MAC (efficient).
            port_type = "uplink" if is_uplink else classify_port(interface_name, mac_count, args.uplink_pattern)

            results[req_mac].append({
                "agent": agent["ip"],
                "port": interface_name,
                "type": port_type
            })
    # 6 Print the final output.
    for mac in requested_macs:
        if len(results[mac]) == 0:
            print(f"{mac}  |  NOT FOUND")
        else:
            for entry in results[mac]:
                print(f"{mac}  |  {entry['agent']}  |  {entry['port']}  |  {entry['type']}")


if __name__ == "__main__":
    main()