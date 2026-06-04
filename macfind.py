import sys
from easysnmp import Session

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'
BASE_PORT_IFINDEX_OID = '1.3.6.1.2.1.17.1.4.1.2'


def parse_agents():
    agents = []

    for arg in sys.argv[1:]:
        try:
            ip, port, community = arg.split(':')
            agents.append({
                'ip': ip,
                'port': int(port),
                'community': community
            })
        except ValueError:
            print(f"Invalid format: {arg}")
            print("Expected: ip:port:community")
            sys.exit(1)

    return agents


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
            # --- DEBUG PRINT ---
            print(f"RAW IFINDEX DATA -> OID: {entry.oid} | INDEX: '{entry.oid_index}' | VALUE: '{entry.value}'")
            
            try:
                # If oid_index is empty, fallback to taking the last number from the full OID
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
            # --- DEBUG PRINT ---
            print(f"RAW MAC DATA -> OID: {entry.oid} | INDEX: '{entry.oid_index}' | VALUE: '{entry.value}'")
            
            try:
                # If oid_index is missing, extract MAC from the end of the full OID
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

        print(f"\n--- Fetching ifIndex mapping for {agent['ip']} ---")
        bridge_mapping = retrieve_ifindex_mapping(agent)

        print(f"\n--- Combined Results for {agent['ip']} ---")
        for mac, bridge_port in mac_table.items():
            if bridge_port in bridge_mapping:
                ifindex = bridge_mapping[bridge_port]
                print(
                    f"{agent['ip']} | "
                    f"{mac} | "
                    f"bridge port {bridge_port} | "
                    f"ifIndex {ifindex}"
                )


if __name__ == "__main__":
    main()