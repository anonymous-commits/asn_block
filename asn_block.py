#!/usr/bin/env python3
"""
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
"""

import os
import re
import gzip
import shutil
import ipaddress
import argparse
import logging
import requests
import logging.handlers
import subprocess
from pathlib import Path
from typing import Generator, Tuple

# Configure syslog logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("asn_ipblocker")
handler = logging.handlers.SysLogHandler(address='/dev/log')
logger.addHandler(handler)

# Full paths to system binaries
BIN_SYSTEMCTL = "/bin/systemctl"
BIN_FIREWALL_CMD = "/usr/bin/firewall-cmd"
BIN_UFW = "/usr/sbin/ufw"
BIN_IPSET = "/sbin/ipset"
BIN_IPTABLES = "/sbin/iptables"
BIN_IP6TABLES = "/sbin/ip6tables"

# URLs and paths
IPTOASN_V4_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
IPTOASN_V6_URL = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
DATA_DIR = Path("/var/tmp/iptoasn_cache")
FILES = {
    "v4": DATA_DIR / "ip2asn-v4.tsv",
    "v6": DATA_DIR / "ip2asn-v6.tsv"
}

def is_service_active(service: str) -> bool:
    return subprocess.run([BIN_SYSTEMCTL, "is-active", "--quiet", service]).returncode == 0

def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

def validate_asn(asn: int) -> bool:
    return isinstance(asn, int) and 0 < asn < 4294967295

def download_file(url: str, out_path: Path) -> None:
    gz_path = out_path.with_suffix(".tsv.gz")
    with requests.get(url, stream=True, timeout=10) as r:
        r.raise_for_status()
        with open(gz_path, "wb") as f:
            shutil.copyfileobj(r.raw, f)
    with gzip.open(gz_path, "rt") as f_in, open(out_path, "w") as f_out:
        for line in f_in:
            if re.match(r"^\S+\t\S+\t\d+(?:\t.+)?$", line.strip()):
                f_out.write(line)
    os.remove(gz_path)

def update_datasets() -> None:
    ensure_data_dir()
    logger.info("Downloading IPv4 dataset...")
    download_file(IPTOASN_V4_URL, FILES["v4"])
    logger.info("Downloading IPv6 dataset...")
    download_file(IPTOASN_V6_URL, FILES["v6"])
    logger.info("Datasets updated.")

def ensure_datasets() -> None:
    if not FILES["v4"].exists() or not FILES["v6"].exists():
        logger.warning("Datasets missing, downloading now...")
        update_datasets()

def parse_dataset(file_path: Path, asn: int) -> Generator[Tuple[str, str], None, None]:
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#") or line.strip() == "":
                continue
            parts = line.strip().split("\t")
            start, end, record_asn = parts[0], parts[1], parts[2]
            if record_asn == str(asn):
                yield (start, end)

def iprange_to_cidr(start_ip: str, end_ip: str) -> ipaddress._BaseNetwork:
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    return ipaddress.summarize_address_range(start, end)

def detect_firewall_backend() -> str:
    firewalld = is_service_active("firewalld")
    ufw = is_service_active("ufw")
    ipt = is_service_active("iptables") or is_service_active("ip6tables")
    if sum([firewalld, ufw, ipt]) > 1:
        logger.error("Multiple conflicting firewall systems detected. Please ensure only one is active.")
        return "conflict"
    if firewalld:
        return "firewalld"
    if ufw:
        return "ufw"
    if ipt:
        return "iptables"
    return "unknown"

def create_or_reset_ipset(ipset_name: str, version: str, dry_run: bool) -> None:
    result = subprocess.run([BIN_IPSET, "list", ipset_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        if dry_run:
            print(f"[DRY-RUN] Would run: {BIN_IPSET} destroy {ipset_name}")
        else:
            subprocess.run([BIN_IPSET, "destroy", ipset_name], stderr=subprocess.DEVNULL)
    cmd = [BIN_IPSET, "create", ipset_name, "hash:net", "family", "inet6" if version == "v6" else "inet"]
    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(cmd)}")
    else:
        subprocess.run(cmd, stderr=subprocess.DEVNULL)

def add_ip_to_ipset(ipset_name: str, cidr: str, dry_run: bool = False) -> None:
    cmd = [BIN_IPSET, "add", ipset_name, cidr]
    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(cmd)}")
    else:
        subprocess.run(cmd, stderr=subprocess.DEVNULL)

def apply_firewalld_rule(ipset_name: str, dry_run: bool = False) -> None:
    zone = "block"
    cmd_add = [BIN_FIREWALL_CMD, "--permanent", f"--zone={zone}", "--add-source=ipset:" + ipset_name]
    cmd_reload = [BIN_FIREWALL_CMD, "--reload"]
    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(cmd_add)}")
        print(f"[DRY-RUN] Would run: {' '.join(cmd_reload)}")
    else:
        subprocess.run(cmd_add)
        subprocess.run(cmd_reload)

def remove_firewalld_rule(ipset_name: str, dry_run: bool = False) -> None:
    zone = "block"
    cmd_del = [BIN_FIREWALL_CMD, "--permanent", f"--zone={zone}", "--remove-source=ipset:" + ipset_name]
    cmd_reload = [BIN_FIREWALL_CMD, "--reload"]
    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(cmd_del)}")
        print(f"[DRY-RUN] Would run: {' '.join(cmd_reload)}")
    else:
        subprocess.run(cmd_del)
        subprocess.run(cmd_reload)

def apply_ufw_rule(cidr_list: list[str], dry_run: bool = False) -> None:
    for cidr in cidr_list:
        rule = [BIN_UFW, "deny", "from", cidr]
        if dry_run:
            print(f"[DRY-RUN] Would run: {' '.join(rule)}")
        else:
            subprocess.run(rule)

def remove_ufw_rule(cidr_list: list[str], dry_run: bool = False) -> None:
    for cidr in cidr_list:
        rule = [BIN_UFW, "delete", "deny", "from", cidr]
        if dry_run:
            print(f"[DRY-RUN] Would run: {' '.join(rule)}")
        else:
            subprocess.run(rule)

def apply_iptables_rule(cmd_path: str, ipset_name: str, dry_run: bool = False) -> None:
    rule = [cmd_path, "-I", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"]
    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(rule)}")
    else:
        subprocess.run(rule, stderr=subprocess.DEVNULL)

def remove_iptables_rule(cmd_path: str, ipset_name: str, dry_run: bool = False) -> None:
    rule = [cmd_path, "-D", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"]
    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(rule)}")
    else:
        subprocess.run(rule, stderr=subprocess.DEVNULL)

def create_ipset_and_rules(asn: int, dry_run: bool = False) -> None:
    print("--- Creating block rules ---")
    if not validate_asn(asn):
        logger.error("Invalid ASN.")
        return

    firewall = detect_firewall_backend()
    if firewall == "conflict":
        return
    print(f"Firewall system detected: {firewall}")

    ensure_data_dir()
    ensure_datasets()
    sets = {"v4": f"ASN{asn}_v4", "v6": f"ASN{asn}_v6"}

    for version in ["v4", "v6"]:
        ipset_name = sets[version]
        ip_version = "inet6" if version == "v6" else "inet"
        create_or_reset_ipset(ipset_name, version, dry_run)

        cidr_list = []
        for start, end in parse_dataset(FILES[version], asn):
            for net in iprange_to_cidr(start, end):
                cidr = str(net)
                add_ip_to_ipset(ipset_name, cidr, dry_run=dry_run)
                cidr_list.append(cidr)

        if firewall == "iptables":
            cmd = BIN_IPTABLES if version == "v4" else BIN_IP6TABLES
            apply_iptables_rule(cmd, ipset_name, dry_run=dry_run)
        elif firewall == "firewalld":
            apply_firewalld_rule(ipset_name, dry_run=dry_run)
        elif firewall == "ufw":
            apply_ufw_rule(cidr_list, dry_run=dry_run)

def cleanup_ipsets(asn: int, dry_run: bool = False) -> None:
    print("--- Cleaning up block rules ---")
    if not validate_asn(asn):
        logger.error("Invalid ASN.")
        return

    firewall = detect_firewall_backend()
    if firewall == "conflict":
        return
    print(f"Firewall system detected: {firewall}")

    for version in ["v4", "v6"]:
        ipset_name = f"ASN{asn}_{version}"
        cidr_list = []

        for start, end in parse_dataset(FILES[version], asn):
            for net in iprange_to_cidr(start, end):
                cidr_list.append(str(net))

        if firewall == "iptables":
            cmd = BIN_IPTABLES if version == "v4" else BIN_IP6TABLES
            remove_iptables_rule(cmd, ipset_name, dry_run=dry_run)
        elif firewall == "firewalld":
            remove_firewalld_rule(ipset_name, dry_run=dry_run)
        elif firewall == "ufw":
            remove_ufw_rule(cidr_list, dry_run=dry_run)

        if dry_run:
            print(f"[DRY-RUN] Would run: {BIN_IPSET} destroy {ipset_name}")
        else:
            subprocess.run([BIN_IPSET, "destroy", ipset_name], stderr=subprocess.DEVNULL)
            logger.info(f"Removed ipset and rules for {ipset_name}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Manage ASN-based ipset blocking using iptoasn.com")
    parser.add_argument("action", choices=["update", "block", "unblock"], help="Action to perform")
    parser.add_argument("asn", nargs="?", type=int, help="ASN to block/unblock")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying them")
    args = parser.parse_args()

    if args.action == "update":
        update_datasets()
    elif args.action == "block":
        if not args.asn:
            logger.error("ASN argument required.")
            return
        create_ipset_and_rules(args.asn, dry_run=args.dry_run)
    elif args.action == "unblock":
        if not args.asn:
            logger.error("ASN argument required.")
            return
        cleanup_ipsets(args.asn, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
