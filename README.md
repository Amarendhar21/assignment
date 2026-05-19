# Assignment 3A — Student One

## Environment

| Item | Value |
|------|-------|
| Python virtualenv | `/home/ubuntu/venv` |
| Assignment | 3A |
| SNMP port | 161 |

The virtualenv is activated automatically when you open a shell.
To activate manually: `source /home/ubuntu/venv/bin/activate`

The SNMP community string is available as the environment variable `$SNMP_COMMUNITY`.
**Do not hard-code it in your source code, and do not commit it.**

## Quick SNMP test

A test script is available at `~/tools/test_snmp.sh`. Run it to verify
connectivity to the lab switches before starting development:

```bash
~/tools/test_snmp.sh <switch-ip>
```

Two shell aliases are also available for manual exploration:

```bash
# Walk an OID tree
swalk <switch-ip> <oid>

# Get a single OID
sget <switch-ip> <oid>
```

## Git requirements

Your submission is your Git history. Please read these requirements carefully:

- **Push to a remote repository** at https://github.com/your-institution regularly.
  If this VM is reset, any commits not pushed are lost.
- Commit after each logical piece of work — not just at the end.
- Write meaningful commit messages. Examples of **bad** messages:
  - `wip`, `stuff`, `changes`, `final`, `done`
- Examples of **good** messages:
  - `Implement SNMP table walker for dot1dTpFdbTable`
  - `Add two-step port translation (bridge port -> ifIndex -> ifDescr)`
  - `Handle agent timeout without flushing state`
- The marker will read your git log. A single commit will score zero
  for version control regardless of code quality.

## Useful OIDs for reference

| OID | Description |
|-----|-------------|

## Installing additional packages

If you need a package not already in the virtualenv:

```bash
pip install <package-name>
```

Do not use `sudo pip` — always install into the virtualenv.
