"""Offline manufacturer lookup for directly connected Linux neighbors."""

import csv
import ipaddress
import json
import logging
import re
import subprocess
from functools import lru_cache
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)
VENDOR_NAMES = (
    ("Cisco", r"\b(cisco|meraki|linksys)\b"),
    ("Juniper", r"\bjuniper\b"),
    ("HP / HPE / Aruba", r"\b(hewlett|hp|hpe|aruba|procurve|3com|h3c)\b"),
    ("SMC", r"\b(smc networks|standard microsystems)\b"),
    ("Extreme Networks", r"\b(extreme networks|enterasys|avaya|nortel)\b"),
    ("Brocade / Ruckus", r"\b(brocade|ruckus|foundry)\b"),
    ("D-Link", r"\bd-link\b"),
    ("NETGEAR", r"\bnetgear\b"),
    ("TP-Link", r"\btp-link\b"),
    ("MikroTik", r"\bmikrotik\b"),
    ("Ubiquiti", r"\bubiquiti\b"),
    ("Dell", r"\b(dell|force10)\b"),
    ("Huawei", r"\bhuawei\b"),
    ("Allied Telesis", r"\ballied teles"),
    ("Zyxel", r"\bzyxel\b"),
    ("Edgecore / Accton", r"\b(edgecore|accton)\b"),
    ("Arista", r"\barista\b"),
    ("Fortinet", r"\bfortinet\b"),
    ("Alcatel-Lucent", r"\b(alcatel|nokia)\b"),
)


def network_vendor(organization):
    for name, pattern in VENDOR_NAMES:
        if re.search(pattern, organization, re.IGNORECASE):
            return name
    return None


@lru_cache(maxsize=4)
def load_oui(path, modified):
    with open(path, newline="", encoding="utf-8-sig") as source:
        rows = csv.DictReader(source)
        if not {"Assignment", "Organization Name"} <= set(rows.fieldnames or []):
            raise ValueError("Expected IEEE MA-L CSV headers.")
        return {
            row["Assignment"].upper(): row["Organization Name"]
            for row in rows
            if re.fullmatch(r"[0-9a-fA-F]{6}", row.get("Assignment") or "")
            and row.get("Organization Name")
        }


def lookup_oui(mac):
    compact = mac.replace(":", "").replace("-", "")
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact) or int(compact[:2], 16) & 3:
        return None
    path = Path(settings.DISCOVERY_OUI_FILE)
    try:
        return load_oui(str(path), path.stat().st_mtime_ns).get(compact[:6].upper())
    except (OSError, ValueError, csv.Error):
        logger.warning("OUI fallback database is unavailable or invalid at %s.", path)
        return None


def ip_json(*arguments):
    result = subprocess.run(
        ["ip", "-j", *arguments], capture_output=True, text=True,
        timeout=2, check=True,
    )
    return json.loads(result.stdout)


def neighbor_mac(address):
    address = str(ipaddress.ip_address(address))
    try:
        routes = ip_json("route", "get", address)
        if not routes or routes[0].get("gateway") or routes[0].get("type") in ("local", "unreachable"):
            return None
        interface = routes[0].get("dev")
        if not interface:
            return None
        for neighbor in ip_json("neigh", "show", "to", address, "dev", interface):
            if neighbor.get("dst") != address:
                continue
            if set(neighbor.get("state", [])) & {"FAILED", "INCOMPLETE"}:
                continue
            mac = neighbor.get("lladdr", "")
            if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                return mac
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
        logger.warning("Neighbor lookup failed for %s; OUI fallback unavailable.", address)
    return None
