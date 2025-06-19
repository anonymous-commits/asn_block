# asn_block
Small python script to block all traffic from an ASN

This script automates the process of blocking or unblocking IP ranges associated with specific Autonomous System Numbers (ASNs).

It works by downloading and parsing the latest ASN-to-IP prefix mappings from iptoasn.com, converting these IP ranges to CIDR format,
loading them into `ipset`, and applying or removing rules using one of several supported firewall systems: `firewalld`, `ufw`, or plain `iptables`/`ip6tables`.

Supported actions include:
- `update`: Download and cache the latest IP-to-ASN datasets (IPv4 and IPv6).
- `block <ASN>`: Create or update ipsets for the given ASN and apply firewall rules using the active system (`firewalld`, `ufw`, or `iptables`/`ip6tables`).
- `unblock <ASN>`: Remove previously created ipsets and their associated rules according to the firewall system in use.

The script supports a `--dry-run` mode to simulate changes without applying them, logs operations to syslog.

This is really only tested for the firewalld case.
iptables/ipset use-case does not handle persistence.. save/restore?
ufw is only implemented as a theoretical exercise.
