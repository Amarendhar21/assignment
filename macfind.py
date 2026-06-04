import sys
from easysnmp import Session
import argparse
import re

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'
BASE_PORT_IFINDEX_OID = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR_OID = '1.3.6.1.2.1.2.2.1.2'
SYSUPTIME_OID = '1.3.6.1.2.1.1.3.0'


def parse_arguments():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--host',
        required=True
    )

    parser.add_argument(
        '--community',
        required=True
    )

    parser.add_argument(
        '--version',
        default='2c'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=161
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=5
    )

    parser.add_argument(
        '--retries',
        type=int,
        default=2
    )

    parser.add_argument(
        '--uplink-pattern',
        default='TenGig|Port-channel|Uplink'
    )

    return parser.parse_args()


def get_sysuptime(agent):

    session = Session(
        hostname=agent['ip'],
        community=agent['community'],
        version=2,
        remote_port=agent['port']
    )

    result = session.get(SYSUPTIME_OID)

    return int(result.value)


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
                print(
                    f"Skipping ifDescr entry "
                    f"(OID={entry.oid}) "
                    f"because: {ve}"
                )

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
    agents = parse_agents()

    for agent in agents:
        print(f"\n--- Fetching MAC table for {agent['ip']} ---")
        mac_table = retrieve_mac_addresses(agent)
        
       
        port_mac_count = {}
        for mac, bridge_port in mac_table.items():
            if bridge_port not in port_mac_count:
                port_mac_count[bridge_port] = 0
            port_mac_count[bridge_port] += 1

        print(f"\n--- Fetching ifIndex mapping for {agent['ip']} ---")
        bridge_mapping = retrieve_ifindex_mapping(agent)
        
        print(f"\n--- Fetching ifDescr mapping for {agent['ip']} ---")
        ifdescr_mapping = retrieve_ifdescr_mapping(agent)

        print(f"\n--- Combined Results for {agent['ip']} ---")
        for mac, bridge_port in mac_table.items():
            
            if bridge_port not in bridge_mapping:
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
                mac_count
            )

            # Properly indented inside the combination loop
            print(
                f"{agent['ip']} | "
                f"{mac} | "
                f"bridge port {bridge_port} | "
                f"ifIndex {ifindex} | "
                f"{interface_name} | "
                f"{port_type}"
            )


if __name__ == "__main__":
    main()