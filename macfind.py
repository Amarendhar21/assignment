import sys
from easysnmp import Session

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'


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
            # Properly indented inside the loop
            mac_parts = [
                part for part in entry.oid_index.split('.')
                if part != ''
            ]

            mac_address = ':'.join(
                f"{int(part):02x}"
                for part in mac_parts
            )

            if entry.value == '':
                continue

            bridge_port = int(entry.value)
            mac_table[mac_address] = bridge_port

            print(
                f"{agent['ip']} | "
                f"{mac_address} | "
                f"bridge port {bridge_port}"
            )
            
        # Return the populated dictionary AFTER the loop finishes
        return mac_table

    except Exception as e:
        print(f"{agent['ip']} | ERROR | {e}")
        return {}


def main():
    agents = parse_agents()

    for agent in agents:
        retrieve_mac_addresses(agent)


if __name__ == "__main__":
    main()