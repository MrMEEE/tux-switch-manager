"""Bounded, unauthenticated probes; evidence is not proof of a switch."""

import re
import socket
import ssl
import time

from .oui import lookup_oui, neighbor_mac, network_vendor

VENDOR_MARKERS = (
    ("Juniper", r"\b(juniper|junos|j-web)\b"),
    ("Cisco", r"\b(cisco|catalyst|nx-os|meraki)\b"),
    ("HP / HPE / Aruba", r"\b(aruba|procurve|comware|h3c)\b|\bhp (?:switch|networking)\b"),
    ("SMC", r"\bsmc (?:networks|switch)\b|\bsmc[0-9]{3,}"),
    ("Extreme Networks", r"\b(extremexos|extreme networks|enterasys)\b"),
    ("Brocade / Ruckus", r"\b(brocade|ruckus|fastiron|foundry)\b"),
    ("D-Link", r"\bd-link\b"),
    ("NETGEAR", r"\bnetgear\b"),
    ("TP-Link", r"\btp-link\b"),
    ("MikroTik", r"\b(mikrotik|routeros|swos)\b"),
    ("Ubiquiti", r"\b(ubiquiti|edgeswitch|unifi)\b"),
    ("Dell", r"\b(force10|powerconnect|dell networking)\b"),
    ("Huawei", r"\b(huawei|vrp)\b"),
    ("Allied Telesis", r"\ballied telesis\b"),
    ("Zyxel", r"\bzyxel\b"),
    ("Edgecore", r"\bedgecore\b"),
    ("Arista", r"\barista\b"),
    ("Fortinet", r"\b(fortinet|fortiswitch)\b"),
    ("Alcatel-Lucent", r"\b(alcatel-lucent|omniswitch)\b"),
)


def classify_candidate(address, open_ports, banners):
    evidence = [f"TCP {port} open" for port in open_ports]
    vendor = None
    netconf_ssh = False
    for port, banner in banners.items():
        safe_banner = re.sub(r"[\x00-\x1f\x7f]", " ", banner)[:200]
        if port in (22, 830) and safe_banner.startswith("SSH-"):
            evidence.append(f"SSH banner on {port}: {safe_banner}")
            if port == 830:
                netconf_ssh = True
        for name, pattern in VENDOR_MARKERS:
            if re.search(pattern, banner, re.IGNORECASE):
                vendor = name
                evidence.append(f"{name} marker in service response on TCP {port}")
                break
    if not vendor and not netconf_ssh:
        return None
    return {
        "address": address, "status": "candidate", "open_ports": open_ports,
        "vendor": vendor or "Unknown (SSH on NETCONF port)",
        "confidence": "vendor service fingerprint" if vendor else "possible NETCONF device",
        "evidence": evidence,
    }


def read_response(connection, http=False):
    chunks = []
    size = 0
    deadline = time.monotonic() + 2
    while size < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        connection.settimeout(min(1, remaining))
        try:
            chunk = connection.recv(4096 - size)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if not http and b"\n" in chunk:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def probe_candidate(address, port=22):
    open_ports = []
    banners = {}
    for candidate_port in sorted({22, 80, 443, 830, port}):
        try:
            connection = socket.create_connection((address, candidate_port), timeout=1)
        except OSError:
            continue
        with connection:
            open_ports.append(candidate_port)
            try:
                if candidate_port == 443:
                    # Discovery collects public banners, not authenticated data.
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(connection, server_hostname=address) as tls:
                        host = f"[{address}]" if ":" in address else address
                        tls.sendall(
                            f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
                        )
                        banners[candidate_port] = read_response(tls, http=True)
                    continue
                if candidate_port == 80:
                    host = f"[{address}]" if ":" in address else address
                    connection.sendall(
                        f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
                    )
                banners[candidate_port] = read_response(connection, http=candidate_port == 80)
            except OSError:
                # An open port remains useful evidence even when no banner arrives.
                banners[candidate_port] = ""
    candidate = classify_candidate(address, open_ports, banners)
    if candidate and candidate["confidence"] == "vendor service fingerprint":
        return candidate
    mac = neighbor_mac(address)
    organization = lookup_oui(mac) if mac else None
    vendor = network_vendor(organization) if organization else None
    if not vendor:
        return candidate
    if candidate is None:
        candidate = {
            "address": address, "status": "candidate", "open_ports": open_ports,
            "evidence": [f"TCP {value} open" for value in open_ports],
        }
    candidate.update(
        vendor=vendor, mac=mac, organization=organization,
        confidence="manufacturer OUI fallback (unverified device type)",
    )
    candidate["evidence"].append(f"MAC {mac}: local IEEE OUI registered to {organization}")
    return candidate
