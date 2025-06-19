# iptables_asn_block
Small python script to block all traffic from an ASN

This script automates the process of blocking or unblocking IP ranges associated with specific Autonomous System Numbers (ASNs).

It works by downloading and parsing the latest ASN-to-IP prefix mappings from iptoasn.com, converting these IP ranges to CIDR format,
loading them into `ipset`, and applying or removing `iptables`/`ip6tables` rules accordingly.

Supported actions include:
- `update`: Download and cache the latest IP-to-ASN datasets (IPv4 and IPv6).
- `block <ASN>`: Create or update ipsets for the given ASN and apply iptables/ip6tables rules to block traffic from those networks.
- `unblock <ASN>`: Remove previously created ipsets and firewall rules for the given ASN.

The script supports a `--dry-run` mode to simulate changes without applying them, logs operations to syslog, and uses explicit binary paths for security.
