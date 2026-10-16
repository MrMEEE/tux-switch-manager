# NETGEAR Ethernet Plus / GS110EMX

[Back to supported switches](../README.md#supported-switches)

The `netgear_plus` web profile supports the **GS110EMX**, verified on firmware
**1.0.1.4** with read-only collection and an approved reversible switch-name
write/readback/restoration test. No live port, VLAN or management-address writes
were used for validation. Discovery and manual automatic matching recognize the
GS110EMX login page and use port 80 by default. Select a saved password-only
credential. Other Plus models are not advertised as compatible until their
page layouts and writes are verified.

The adapter uses [py-netgear-plus](https://github.com/foxey/py-netgear-plus)
0.6.4 (Apache-2.0) for its challenge-response login and system metadata parser.
Its GS110EMX library profile is monitoring-only; the staged configuration
adapter here uses the inspected native forms. HTTP requests remain bounded,
proxy-free and redirect-refusing, with per-operation sessions and no persisted
cookies or authentication tokens. HTTPS transport uses the existing strict
TLS implementation; this profile does not offer automatic HTTPS enabling.

Supported:

- Ten-port link state, negotiated speed, MTU, RX/TX byte and CRC counters.
- Prefilled switch name and port description, speed/admin state and flow
  control editors.
- Existing Advanced 802.1Q tagged/untagged/excluded membership and port PVID
  editors. LAG members must have matching membership; aggregated-port settings
  remain in the native LAG GUI.
- Staged review, local preview, fresh managed-baseline comparison and readback
  after applying. WebSocket updates use the normal switch synchronization flow.

Changing VLAN modes, creating/deleting VLANs, configuring LAGs, changing
management IP/DHCP, QoS, mirroring, firmware, reboot and startup-save operations
are not exposed. If Advanced 802.1Q mode is inactive, VLAN/PVID editors are
hidden without enabling or resetting anything. This is a managed-field
baseline, not a full configuration backup. HTTP is unencrypted; writes are
non-atomic, have no device lock or rollback, and a failed write/readback is
marked **uncertain**, never automatically retried. Startup persistence is not
verified. Management/uplink membership changes can disconnect access.
