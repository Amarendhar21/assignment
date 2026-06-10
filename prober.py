#!/usr/bin/env python3
import argparse
import re
from collections import defaultdict
from easysnmp import Session

try:
    from easysnmp.exceptions import EasySNMPTimeoutError
except ImportError:
    EasySNMPTimeoutError = Exception

FDB_PORT_OID = '1.3.6.1.2.1.17.4.3.1.2'
BASE_PORT_IFINDEX_OID = '1.3.6.1.2.1.17.1.4.1.2'
IFDESCR_OID = '1.3.6.1.2.1.2.2.1.2'
IFNAME_OID = '1.3.6.1.2.1.31.1.1.1.1'
IFPHYSADDRESS_OID = '1.3.6.1.2.1.2.2.1.6'
IFALIAS_OID = '1.3.6.1.2.1.31.1.1.1.18'
SYSDESCR_OID = '1.3.6.1.2.1.1.1.0'


def detect_snmp_capabilities(host, community, port):
   
    probe_timeout = 5
    probe_retries = 1

    # (oid, is_walk, label)
    probes = [
        (SYSDESCR_OID,        False, 'sysDescr'),
        (IFDESCR_OID,         True,  'ifDescr'),
        (FDB_PORT_OID,        True,  'FDB'),
    ]

    # Collect what each version can actually return
    version_results = {}   # version_name -> {label: bool}

    for version_code, version_name in [(2, '2c'), (1, '1')]:
        version_results[version_name] = {}
        print(f"\n   🔍 Probing SNMPv{version_name}...")
        try:
            session = Session(
                hostname=host, community=community, version=version_code,
                remote_port=port, timeout=probe_timeout, retries=probe_retries
            )
            for oid, is_walk, label in probes:
                try:
                    if is_walk:
                    
                        result = session.walk(oid)
                        success = len(list(result)) > 0
                    else:
                        result = session.get(oid)
                        success = bool(result and result.value)
                    version_results[version_name][label] = success
                    status = "✅" if success else "❌"
                    print(f"      {status} {label}: {'accessible' if success else 'empty/blocked'}")
                except Exception as e:
                    version_results[version_name][label] = False
                    print(f"      ❌ {label}: {type(e).__name__}")
        except Exception as e:
            print(f"   ❌ SNMPv{version_name} session failed: {type(e).__name__}: {e}")
            version_results[version_name] = {}

    caps = {}
    for label in ['sysDescr', 'ifDescr', 'FDB']:
        v2_ok = version_results.get('2c', {}).get(label, False)
        v1_ok = version_results.get('1',  {}).get(label, False)

        if v2_ok:
            caps[label] = '2c'    # prefer v2c when both work (bulkwalk is faster)
        elif v1_ok:
            caps[label] = '1'
        else:
            caps[label] = None    # table inaccessible under either version
            print(f"   ⚠️ '{label}' inaccessible under both versions.")

    caps['reachable'] = any(v is not None for v in caps.values())
    return caps


def snmp_walk_table(session, oid, is_v1, host, table_name):
    
    try:
        if is_v1:
            return list(session.walk(oid))
        else:
            # Controlled repetitions prevent oversized PDUs on legacy/flaky switches
            return list(session.bulkwalk(oid, max_repetitions=15))
    except EasySNMPTimeoutError as e:
        print(f"   ⚠️ Timeout walking '{table_name}' on {host}. Partial data may be preserved.")
        return []
    except Exception as e:
        print(f"   ⚠️ Failed to walk '{table_name}' on {host}: {type(e).__name__}: {e}")
        return []


def classify_port(interface_name, mac_count, uplink_pattern):
    name = interface_name.lower()
    if re.search(uplink_pattern, interface_name, re.IGNORECASE):
        return "uplink"
    if "gigabitethernet" in name or "fastethernet" in name or "access" in name:
        return "edge"
    return "uplink" if mac_count > 1 else "edge"


def probe_switch(host, args):
    
    print(f"\nProbing switch: {host} (SNMP Port: {args.port})")
    print("-" * 120)

    # 1. Capability detection — replaces single-version detect_snmp_version()
    caps = detect_snmp_capabilities(host, args.community, args.port)

    if not caps['reachable']:
        print("❌ Cannot establish SNMP session under any version. Skipping.\n")
        return

    print(f"\n   Capability map:")
    print(f"      sysDescr : SNMPv{caps['sysDescr']  or 'none'}")
    print(f"      ifDescr  : SNMPv{caps['ifDescr']   or 'none'}")
    print(f"      FDB      : SNMPv{caps['FDB']        or 'none'}")

    # 2. Session factory — opens a correctly versioned session per capability entry
    def make_session(version_name):
        if version_name is None:
            return None
        try:
            return Session(
                hostname=host,
                community=args.community,
                version=1 if version_name == '1' else 2,
                remote_port=args.port,
                timeout=args.timeout,
                retries=args.retries
            )
        except Exception as e:
            print(f"   ❌ Session creation failed for SNMPv{version_name}: {type(e).__name__}: {e}")
            return None

    # Each table gets its own session using the version that proved accessible
    fdb_session  = make_session(caps['FDB'])
    name_session = make_session(caps['ifDescr'])
    base_session = make_session(caps['sysDescr'])  # used for bridge port map + switch MACs

    is_v1_fdb  = (caps['FDB']      == '1')
    is_v1_name = (caps['ifDescr']  == '1')
    is_v1_base = (caps['sysDescr'] == '1')

    # 3. Optional: Switch MACs (non-fatal, uses base session)
    switch_macs = set()
    if base_session:
        for entry in snmp_walk_table(base_session, IFPHYSADDRESS_OID, is_v1_base, host, "ifPhysAddress"):
            try:
                clean = entry.value.replace(':', '').replace('-', '').lower()
                if len(clean) == 12:
                    switch_macs.add(':'.join(clean[i:i+2] for i in range(0, 12, 2)))
            except Exception:
                continue

    # 4. FDB Table (critical — skip entirely if no version could access it)
    if fdb_session is None:
        print("   ⚠️ FDB table inaccessible under all versions. Skipping port report.\n")
        return

    mac_table = {}
    for entry in snmp_walk_table(fdb_session, FDB_PORT_OID, is_v1_fdb, host, "FDB Table"):
        try:
            parts = entry.oid.split('.')[-6:] if entry.oid_index == '' else [p for p in entry.oid_index.split('.') if p != '']
            if len(parts) == 6 and entry.value and entry.value != '0':
                mac_table[':'.join(f"{int(p):02x}" for p in parts)] = int(entry.value)
        except Exception:
            continue

    if not mac_table:
        print("   ⚠️ FDB table returned no rows. Skipping port report.\n")
        return

    # 5. Bridge Port -> ifIndex Mapping (MISSING STEP - CAUSES NameError)
    bridge_to_ifindex = {}
    if base_session:
        for entry in snmp_walk_table(base_session, BASE_PORT_IFINDEX_OID, is_v1_base, host, "BasePortIfIndex"):
            try:
                bp = entry.oid.split('.')[-1] if entry.oid_index == '' else entry.oid_index.replace('.', '')
                bridge_to_ifindex[int(bp)] = int(entry.value)
            except Exception:
                continue

    # 6. ifIndex -> Name (Consolidated Layer 1-4 Logic)
    ifindex_to_name = {}
    if name_session:
        #1: ifDescr as baseline
        for entry in snmp_walk_table(name_session, IFDESCR_OID, is_v1_name, host, "ifDescr"):
            try:
                idx = entry.oid.split('.')[-1] if entry.oid_index == '' else entry.oid_index.replace('.', '')
                if entry.value:
                    ifindex_to_name[int(idx)] = entry.value
            except Exception:
                continue

        #2: ifName — overwrite only when it gives something more readable than a bare number
        for entry in snmp_walk_table(name_session, IFNAME_OID, is_v1_name, host, "ifName"):
            try:
                idx = entry.oid.split('.')[-1] if entry.oid_index == '' else entry.oid_index.replace('.', '')
                ifindex = int(idx)
                current = ifindex_to_name.get(ifindex, "")
                new_val = entry.value.strip() if entry.value else ""
                if new_val and (not current or current.isdigit()) and not new_val.isdigit():
                    ifindex_to_name[ifindex] = new_val
            except Exception:
                continue

        #3: ifAlias — overwrite when non-empty (operator-assigned labels)
        for entry in snmp_walk_table(name_session, IFALIAS_OID, is_v1_name, host, "ifAlias"):
            try:
                idx = entry.oid.split('.')[-1] if entry.oid_index == '' else entry.oid_index.replace('.', '')
                ifindex = int(idx)
                alias = entry.value.strip() if entry.value else ""
                if alias:
                    ifindex_to_name[ifindex] = alias
            except Exception:
                continue
    else:
        print("   ⚠️ Interface name table inaccessible. Names will show as UNKNOWN.")

    #4: Synthesize Port-<N> for numeric/empty names (Aruba physical ports fallback)
    for bp, ifindex in bridge_to_ifindex.items():
        current = ifindex_to_name.get(ifindex, "")
        if not current or current.isdigit():
            ifindex_to_name[ifindex] = f"Port-{ifindex}"

   
    port_macs = defaultdict(list)
    for mac, bp in mac_table.items():
        port_macs[bp].append(mac)

    print(f"\n{'Bridge Port':<12} | {'ifIndex':<8} | {'Interface Name':<25} | {'Type':<8} | {'MAC Count':<10} | {'MAC Addresses'}")
    print("-" * 120)

    for bp in sorted(port_macs.keys()):
        macs = port_macs[bp]
        ifindex = bridge_to_ifindex.get(bp)
        name = ifindex_to_name.get(ifindex, "UNKNOWN") if ifindex else "UNKNOWN"
        ptype = classify_port(name, len(macs), args.uplink_pattern)

        mac_display = ", ".join(macs[:4])
        if len(macs) > 4:
            mac_display += f" ... (+{len(macs)-4} more)"

        print(f"{bp:<12} | {str(ifindex or 'N/A'):<8} | {name:<25} | {ptype:<8} | {len(macs):<10} | {mac_display}")

    print("=" * 120)
    print(f"✅ Probing complete. {len(mac_table)} unique MACs mapped.")


def main():
    parser = argparse.ArgumentParser(description="SNMP Switch Prober (Seconds-Corrected)")
    parser.add_argument('--hosts', nargs='+', required=True, help='Switch IP addresses')
    parser.add_argument('--community', required=True, help='SNMP community string')
    parser.add_argument('--version', default='2c', choices=['1', '2c', '3'])
    parser.add_argument('--port', type=int, default=161)
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in SECONDS')
    parser.add_argument('--retries', type=int, default=2)
    parser.add_argument('--uplink-pattern', default='TenGig|Port-channel|Uplink')
    
    args = parser.parse_args()
    

    for host in args.hosts:
        probe_switch(host, args)


if __name__ == "__main__":
    main()