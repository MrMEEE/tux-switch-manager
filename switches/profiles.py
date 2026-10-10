"""Conservative profile recommendations from public evidence, not authentication."""

import re

from django.conf import settings

from .drivers.base import DriverError
from .drivers.registry import driver_class

AUTO = "auto"


def choices(include_auto=True):
    options = [(AUTO, "Automatic matching (recommended)")] if include_auto else []
    for slug in settings.SWITCH_DRIVERS:
        options.append((slug, driver_class(slug).profile_label or slug.replace("_", " ").title()))
    return options


def annotate(candidate):
    candidate = dict(candidate)
    evidence = " ".join(str(value) for value in candidate.get("evidence", [])) + " " + str(candidate.get("fingerprint", ""))
    vendor = candidate.get("vendor", "")
    slug = ""
    known_model = False
    if candidate.get("verified") and candidate.get("profile") in settings.SWITCH_DRIVERS:
        slug, known_model = candidate["profile"], True
    elif vendor == "NETGEAR" or re.search(r"\bnetgear\b", evidence, re.I):
        if re.search(r"\bGS108Tv2\b", evidence, re.I):
            slug, known_model = "netgear_gs108tv2", True
        elif re.search(r"\bGS108T\b", evidence, re.I):
            slug = "netgear_gs108tv2"
    elif vendor == "Juniper" or re.search(r"\b(juniper|junos|j-web)\b", evidence, re.I):
        model = re.search(r"\bex\d+[-\w]*", evidence, re.I)
        if model is None or model.group().lower() in {"ex3300-24p", "ex3300-48p"}:
            slug = "juniper_ex"
            known_model = model is not None
    if slug not in settings.SWITCH_DRIVERS:
        slug = ""
    candidate["profile"] = slug
    candidate["support"] = (
        "Supported — model verified" if candidate.get("verified") and slug else
        "Supported profile — authentication will verify model" if known_model
        else "Possible supported profile — model verification required" if slug
        else "No matching supported profile"
    )
    candidate["supported"] = bool(slug)
    candidate["profile_label"] = driver_class(slug).profile_label if slug else ""
    ports = candidate.get("open_ports", [])
    candidate["profile_port"] = (80 if slug == "netgear_gs108tv2" else 830 if 830 in ports else 22)
    return candidate


def resolve(candidate):
    matched = annotate(candidate or {})
    if not matched["profile"]:
        raise DriverError("No supported profile could be matched. Choose a known compatible profile explicitly; an open port or vendor alone is not proof of support.")
    return matched["profile"], matched["profile_port"]


def discovery_runs(runs):
    for run in runs:
        run.results = [annotate(item) for item in run.results]
        for item in run.results:
            item["enrollment_port"] = item["profile_port"] if run.driver == AUTO else run.port
    return runs
