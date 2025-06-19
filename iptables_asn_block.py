#!/usr/bin/env python3

import os
import requests
import gzip
import shutil
import ipaddress
import argparse
import logging
from pathlib import Path
import subprocess
import re
from typing import Generator, Tuple

# Configure syslog logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("asn_ipblocker")
handler = logging.handlers.SysLogHandler(address='/dev/log')
logger.addHandler(handler)

# Full paths to system binaries
BIN_IPSET = "/sbin/ipset"
BIN_IPTABLES = "/sbin/iptables"
BIN_IP6TABLES = "/sbin/ip6tables"

# URLs to download the iptoasn database
IPTOASN_V4_URL: str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
IPTOASN_V6_URL: str = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
DATA_DIR: Path = Path("/var/tmp/iptoasn_cache")
FILES: dict = {
    "v4": DATA_DIR / "ip2asn-v4.tsv",
    "v6": DATA_DIR / "ip2asn-v6.tsv"
}

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
            if re.match(r"^\d+\t\d+\t\d+$", line.strip()):
                f_out.write(line)
    os.remove(gz_path)

def update_datasets() -> None:
    ensure_data_dir()
    logger.info("🔄 Downloading IPv4 dataset...")
    download_file(IPTOASN_V4_URL, FILES["v4"])
    logger.info("🔄 Downloading IPv6 dataset...")
    download_file(IPTOASN_V6_URL, FILES["v6"])
    logger.info("✅ Datasets updated!")

def parse_dataset(file_path: Path, asn: int) -> Generator[Tuple[str, str], None, None]:
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#") or line.strip() == "":
                continue
            start, end, record_asn = line.strip().split("\t")
            if record_asn == str(asn):
                yield (start, end)

def iprange_to_cidr(start_ip: str, end_ip: str) -> ipaddress._BaseNetwork:
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    return ipaddress.summarize_address_range(start, end)

def ensure_datasets() -> None:
    if not FILES["v4"].exists() or not FILES["v6"].exists():
        logger.warning("⚠️  Datasets missing, downloading now...")
        update_datasets()

def create_ipset_and_rules(asn: int, dry_run: bool = False) -> None:
    if not validate_asn(asn):
        logger.error("❌ Invalid ASN.")
        return

    ensure_data_dir()
    ensure_datasets()
    sets = {"v4": f"ASN{asn}_v4", "v6": f"ASN{asn}_v6"}

    for version in ["v4", "v6"]:
        ipset_name = sets[version]
        ip_version = "inet" if version == "v4" else "inet6"

        if not dry_run:
            subprocess.run([BIN_IPSET, "create", ipset_name, "hash:net", "family", ip_version], stderr=subprocess.DEVNULL)
            subprocess.run([BIN_IPSET, "flush", ipset_name])

        count = 0
        for start, end in parse_dataset(FILES[version], asn):
            for cidr in iprange_to_cidr(start, end):
                if dry_run:
                    print(f"[DRY-RUN] Would add {cidr} to ipset '{ipset_name}'")
                else:
                    subprocess.run([BIN_IPSET, "add", ipset_name, str(cidr)])
                count += 1
        logger.info(f"✅ {count} CIDRs {'would be' if dry_run else 'added to'} ipset '{ipset_name}'")

        if not dry_run:
            chain = "INPUT"
            cmd = BIN_IPTABLES if version == "v4" else BIN_IP6TABLES
            rule_exists = subprocess.call([
                cmd, "-C", chain, "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

            if not rule_exists:
                subprocess.run([
                    cmd, "-I", chain, "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"
                ])
                logger.info(f"🛡️  Rule added to {chain} chain for ipset '{ipset_name}'")

def cleanup_ipsets(asn: int) -> None:
    if not validate_asn(asn):
        logger.error("❌ Invalid ASN.")
        return

    for version in ["v4", "v6"]:
        ipset_name = f"ASN{asn}_{version}"
        cmd = BIN_IPTABLES if version == "v4" else BIN_IP6TABLES
        subprocess.run([cmd, "-D", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"], stderr=subprocess.DEVNULL)
        subprocess.run([BIN_IPSET, "destroy", ipset_name], stderr=subprocess.DEVNULL)
        logger.info(f"🧹 Removed ipset and rules for {ipset_name}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Manage ASN-based ipset blocking using iptoasn.com")
    parser.add_argument("action", choices=["update", "block", "unblock"], help="Action to perform")
    parser.add_argument("asn", nargs="?", type=int, help="ASN to block/unblock")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying them")
    args = parser.parse_args()

    if args.action == "update":
        update_datasets()
    elif args.action in ["block", "unblock"]:
        if not args.asn:
            logger.error("❌ ASN argument required.")
            return
        if args.action == "block":
            create_ipset_and_rules(args.asn, dry_run=args.dry_run)
        else:
            cleanup_ipsets(args.asn)

if __name__ == "__main__":
    main()
