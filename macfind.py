import sys
from easysnmp import Session

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'
BASE_PORT_IFINDEX_OID = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR_OID = '1.3.6.1.2.1.2.2.1.2'


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


def classify_port(interface_name, mac_count):

    name = interface_name.lower()

    # Name-based heuristic
    if (
        "tengig" in name or
        "port-channel" in name or
        "uplink" in name or
        "trunk" in name
    ):
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
        
        print(f"\n--- Fetching ifDescr mapping for {agent['ip']} ---")
        ifdescr_mapping = retrieve_ifdescr_mapping(agent)

        print(f"\n--- Combined Results for {agent['ip']} ---")
        for mac, bridge_port in mac_table.items():
            
            # Properly indented inside the loop
            if bridge_port not in bridge_mapping:
                continue

            ifindex = bridge_mapping[bridge_port]

            interface_name = ifdescr_mapping.get(
                ifindex,
                "UNKNOWN"
            )

            # Print statement is now properly inside the loop
            print(
                f"{agent['ip']} | "
                f"{mac} | "
                f"bridge port {bridge_port} | "
                f"ifIndex {ifindex} | "
                f"{interface_name}"
            )


if __name__ == "__main__":
    main()