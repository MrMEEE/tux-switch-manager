"""Read operational link state without using staged administrative settings."""

import re


def port_link_states(driver, snapshot):
    states = {}
    if not isinstance(snapshot, dict) or snapshot.get("errors", {}).get("interfaces"):
        return states
    interfaces = snapshot.get("interfaces")
    if driver in {"netgear_gs108tv2", "netgear_plus"} and isinstance(interfaces, list):
        for port in interfaces:
            if not isinstance(port, dict) or not isinstance(port.get("name"), str):
                continue
            link = str(port.get("link", "")).strip().lower()
            states[port["name"]] = {"up": "up", "link up": "up", "down": "down", "link down": "down"}.get(link, "unknown")
    elif driver == "juniper_ex" and isinstance(interfaces, str):
        for name, admin, link in re.findall(
            r"(?m)^\s*((?:ge|xe|et|fe)-\d+/\d+/\d+)\s+(up|down)\s+(up|down)\b", interfaces,
        ):
            states[name] = link
    elif driver == "hp_comware" and isinstance(interfaces, str):
        for name, link in re.findall(
            r"(?m)^\s*((?:GigabitEthernet|Ten-GigabitEthernet|Ethernet|XGE|GE|FE)\d+/\d+/\d+)\s+(UP|DOWN|ADM)\b",
            interfaces,
        ):
            for short, full in (("XGE", "Ten-GigabitEthernet"), ("GE", "GigabitEthernet"), ("FE", "Ethernet")):
                if name.startswith(short):
                    name = full + name[len(short):]
                    break
            states[name] = "up" if link == "UP" else "down"
    return states
