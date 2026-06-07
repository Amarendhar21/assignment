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

    return {
        'ip': ip,
        'port': int(port),
        'community': community
    }

def get_sysuptime(agent):
    """
    Fetches the system uptime. Must be at the module level.
    """
    session = Session(
        hostname=agent['ip'],
        community=agent['community'],
        version=2,
        remote_port=agent['port']
    )

    try:
        result = session.get(SYSUPTIME_OID)
        return int(result.value)
    except Exception as e:
        print(f"{agent['ip']} | SYSUPTIME ERROR | {e}")
        return None


def classify_port(interface_name, mac_count, uplink_pattern):
    name = interface_name.lower()
    
    # Properly aligned regex check
    if re.search(uplink_pattern, interface_name, re.IGNORECASE):
        return "UPLINK"

    if (
        "gigabitethernet" in name or
        "fastethernet" in name or
        "access" in name
    ):
        return "EDGE"

    # Fallback: MAC count heuristic
    if mac_count > 1:
        return "UPLINK"

    return "EDGE"


def retrieve_ifindex_mapping(agent):
    bridge_to_ifindex = {}
    session = Session(
        hostname=agent['ip'],
        community=agent['community'],
        version=2,
        remote_port=agent['port']
    )

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
                
            except ValueError as ve:
                print(f"  -> Skipping due to conversion error: {ve}")

        return bridge_to_ifindex
    except Exception as e:
        print(f"{agent['ip']} | IFINDEX ERROR | {e}")
        return {}


def retrieve_ifdescr_mapping(agent):
    ifindex_to_name = {}
    session = Session(
        hostname=agent['ip'],
        community=agent['community'],
        version=2,
        remote_port=agent['port']
    )

    try:
        entries = session.bulkwalk(IFDESCR_OID)
        for entry in entries:
            try:
                # OID suffix = ifIndex
                if entry.oid_index == '':
                    ifindex_str = entry.oid.split('.')[-1]
                else:
                    ifindex_str = entry.oid_index.replace('.', '')

                ifindex = int(ifindex_str)
                interface_name = entry.value
                ifindex_to_name[ifindex] = interface_name

            except ValueError as ve:
                print(f"Skipping ifDescr entry (OID={entry.oid}) because: {ve}")

        return ifindex_to_name

    except Exception as e:
        print(f"{agent['ip']} | IFDESCR ERROR | {e}")
        return {}


def retrieve_mac_addresses(agent):
    mac_table = {}
    session = Session(
        hostname=agent['ip'],
        community=agent['community'],
        version=2,
        remote_port=agent['port']
    )

    try:
        entries = session.bulkwalk(FDB_PORT_OID)
        for entry in entries:
            try:
                if entry.oid_index == '':
                    mac_parts = entry.oid.split('.')[-6:]
                else:
                    mac_parts = [p for p in entry.oid_index.split('.') if p != '']

                if len(mac_parts) != 6:
                    print(f"  -> Skipping: Not enough parts for a MAC address: {mac_parts}")
                    continue

                mac_address = ':'.join(f"{int(part):02x}" for part in mac_parts)

                if entry.value == '':
                    continue

                bridge_port = int(entry.value)
                mac_table[mac_address] = bridge_port

            except ValueError as ve:
                print(f"  -> Skipping due to conversion error: {ve}")

        return mac_table
    except Exception as e:
        print(f"{agent['ip']} | MAC ERROR | {e}")
        return {}


def main():

    args = parse_arguments()

    agents = [
        parse_agent(agent)
        for agent in args.agents
    ]

    requested_macs = {
        mac.lower().replace('-', ':')
        for mac in args.macs
    }

    print("\nRequested MACs:")
    for mac in requested_macs:
        print(f"  {mac}")

    results = {}

    for mac in requested_macs:
        results[mac] = []

    for agent in agents:

        print(
            f"\n=============================="
        )
        print(
            f"Processing agent {agent['ip']}"
        )
        print(
            f"=============================="
        )

        #
        # Step 0 - sysUpTime BEFORE collection
        #
        start_uptime = get_sysuptime(agent)

        if start_uptime is None:

            print(
                f"TIMEOUT: agent "
                f"{agent['ip']} did not respond"
            )

            continue

        print(
            f"Start sysUpTime: "
            f"{start_uptime}"
        )

        #
        # Step 1 - MAC Table
        #
        mac_table = retrieve_mac_addresses(agent)

        print(
            f"{agent['ip']} returned "
            f"{len(mac_table)} MAC entries"
        )

        #
        # Print first few MACs discovered
        #
        count = 0

        for mac, bridge_port in mac_table.items():

            print(
                f"DEBUG MAC: "
                f"{mac} -> bridge port "
                f"{bridge_port}"
            )

            count += 1

            if count >= 10:
                break

        #
        # Count MACs per bridge port
        #
        port_mac_count = {}

        for mac, bridge_port in mac_table.items():

            if bridge_port not in port_mac_count:
                port_mac_count[bridge_port] = 0

            port_mac_count[bridge_port] += 1

        #
        # Step 2
        #
        bridge_mapping = retrieve_ifindex_mapping(agent)

        print(
            f"{agent['ip']} returned "
            f"{len(bridge_mapping)} "
            f"bridge-port mappings"
        )

        #
        # Step 3
        #
        ifdescr_mapping = retrieve_ifdescr_mapping(agent)

        print(
            f"{agent['ip']} returned "
            f"{len(ifdescr_mapping)} "
            f"interface descriptions"
        )

        #
        # sysUpTime AFTER collection
        #
        end_uptime = get_sysuptime(agent)

        if end_uptime is None:

            print(
                f"TIMEOUT: agent "
                f"{agent['ip']} did not respond"
            )

            continue

        print(
            f"End sysUpTime: "
            f"{end_uptime}"
        )

        #
        # Reboot detection
        #
        if end_uptime < start_uptime:

            print(
                f"Agent {agent['ip']} "
                f"has RESET — results from "
                f"this agent may be stale"
            )

            continue

        #
        # Build final results
        #
        for mac, bridge_port in mac_table.items():

            #
            # DEBUG
            #
            if mac.lower() not in requested_macs:

                print(
                    f"Skipping {mac} "
                    f"(not requested)"
                )

                continue

            if bridge_port not in bridge_mapping:

                print(
                    f"Skipping {mac} "
                    f"(bridge port "
                    f"{bridge_port} "
                    f"not mapped)"
                )

                continue

            ifindex = bridge_mapping[bridge_port]

            interface_name = ifdescr_mapping.get(
                ifindex,
                "UNKNOWN"
            )

            mac_count = port_mac_count.get(
                bridge_port,
                0
            )

            port_type = classify_port(
                interface_name,
                mac_count,
                args.uplink_pattern
            )

            print(
                f"MATCH FOUND: "
                f"{mac} -> "
                f"{interface_name}"
            )

            results[mac.lower()].append(
                {
                    "agent": agent["ip"],
                    "port": interface_name,
                    "type": port_type.lower()
                }
            )

    #
    # Final Reporting
    #
    print(
        "\n=============================="
    )
    print(
        "FINAL REPORT"
    )
    print(
        "=============================="
    )

    for mac in requested_macs:

        if len(results[mac]) == 0:

            print(
                f"{mac} | NOT FOUND"
            )

            continue

        for entry in results[mac]:

            print(
                f"{mac} | "
                f"{entry['agent']} | "
                f"{entry['port']} | "
                f"{entry['type']}"
            )
    for mac in requested_macs:
        print("Checking", mac)
if __name__ == "__main__":
    main()