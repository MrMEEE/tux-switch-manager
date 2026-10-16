# Automatic profiles and supported features

[Back to supported switches](../README.md#supported-switches)

Discovery and manual inventory creation default to **Automatic matching**.
Public service fingerprints recommend a registered driver and transport port:
the legacy GS108T web page selects the GS108Tv2 adapter, and Junos/Juniper
evidence selects the EX3300 NETCONF adapter (preferring port 830 when detected).
GS110EMX web fingerprints recommend the NETGEAR Plus profile; V1910 model or
Comware 5.20 evidence can recommend the experimental HP V1910 SSH2 profile.
An explicit profile and custom port remain available. Manual matching probes
only the entered address, not a network; the existing inventory permission is
required. Discovery still requires the scanning permission.

Vendor evidence is not model verification. Discovery shows one of:
**supported profile / model verification pending**, **possible supported profile**,
**no matching supported profile**, or **supported / model verified** after
authenticated enrollment. Known incompatible models and NETGEAR OUI-only matches
are not automatically assigned the GS108Tv2 adapter. Unknown devices stay visible
but do not receive credentials in automatic authenticated discovery. Verify and
Add uses the selected/matched profile directly, without a new discovery run;
Juniper model validation and SSH key approval are unchanged. Manual inventory
records are verified when synchronized.

Drivers declare configuration sections, creatable sections, monitoring choices
and operation capabilities. The workspace only shows those supported by the
selected profile, and the server rejects forged requests for unsupported
operations. For example, the GS108Tv2 adapter shows Ports, VLAN membership and
System, not LAG/aggregation provisioning, routing or firewall editors. These are
adapter capabilities, not a claim that the physical device lacks every hidden
feature.

## Model-specific guides

- [Juniper EX3300-24P / EX3300-48P](juniper-ex.md)
- [NETGEAR GS108Tv2 legacy web GUI](netgear-gs108tv2.md)
- [NETGEAR Plus GS110EMX](netgear-gs110emx.md)
- [HP V1910 / Comware 5 (experimental)](hp-v1910.md)
