# Web-only NETGEAR GS108Tv2

[Back to supported switches](../README.md#supported-switches)

## Validation scope

Live collection was tested against the legacy GUI on firmware **5.0.0.8**.
Automated fixtures cover managed writes and readback failure handling; they
do not certify all write operations against physical hardware.

## Setup, capabilities and safety

Choose **NETGEAR GS108Tv2 (legacy web GUI)** (`netgear_gs108tv2`) in inventory or discovery and
use management port **80** (blank uses the driver default). Create a saved
credential with the switch password; its username may be blank and is ignored
by this driver. Verify and Add authenticates directly without rescanning or
requesting SSH host-key approval.

This adapter targets the legacy GS108Tv2 interface observed on firmware 5.0.0.8,
not every NETGEAR model. It reads system metadata, eight ports and existing VLAN
membership, including four LAG membership slots. The preferred GUI prefills
system name/location/contact, port description/admin state/speed/power-saving/
link-trap/frame-size settings, and tagged/untagged VLAN membership. Changes stay
staged until explicitly committed. VLAN creation/deletion, PVID, LAG configuration,
CLI diagnostics, reboot and restore are not supported; use the device GUI.
Unrecognized model/page layouts fail closed instead of guessing.

**Safety differences from Junos:**

- HTTP sends passwords and configuration unencrypted. Use an isolated, trusted
  management network. The device workspace offers device administrators
  **Enable / inspect HTTPS**. This explicitly confirmed, asynchronous operation
  enables the device HTTPS service (disabling SSLv3 when enabling it), preserving
  its configured port and timeouts. It does not disable HTTP or save startup
  configuration. If HTTPS is already enabled, it only inspects the endpoint.
- Before using HTTPS, the client requires TLS 1.2 or newer and displays the
  certificate SHA-256 fingerprint for independent verification. Choose **Trust
  certificate and use HTTPS** to approve that exact certificate. The app
  authenticates and reads back over pinned HTTPS before changing its saved
  protocol/port. Pin mismatch blocks sending any credentials. No silent HTTP
  fallback, obsolete TLS, weak-cipher opt-in or blanket certificate bypass is
  provided. Firmware that only supports TLS 1.0 needs upgrading; the job explains
  that HTTPS may have been enabled but the app transport remains unchanged.
- HTTPS setup requires device-admin permission and rechecks it at job execution.
  Certificate approval is bound to the device address, port and inspected
  certificate, and is rechecked before use. Changing inventory endpoints clears
  the old approval/pin rather than reusing another device's trust.
- The adapter disables proxy use, refuses redirects and keeps session cookies in
  memory, never in a shared file or logs.
- Revisions contain only managed fields, not a full restorable configuration.
  Preview is a local planned diff, not a device candidate or commit-check.
- Writes take effect immediately, without a remote lock, atomic transaction or
  rollback. Commit-all is disabled. Commit one item, synchronize, then recreate
  remaining pending changes using the latest synchronized configuration.
- The adapter compares managed fields before writing and verifies readback
  afterward. A failed/uncertain write is marked **uncertain**, not automatically
  retried. Inspect actual state, synchronize, discard the uncertain change and
  save replacement changes only for settings still needed. Concurrent edits
  through the device GUI cannot be locked.
- Startup persistence is not verified. After checking the applied changes, use
  **Save Configuration** in the switch GUI. That device action can save *all*
  previously applied changes, including changes made by other administrators.
- VLAN/uplink/admin-state edits can disconnect management access. PVID is not
  changed by the membership editor. Avoid traffic-affecting writes outside a
  maintenance window.

No additional dependency is needed. PyNetgearSwitchController was evaluated as
a reference, but its GS108Ev3/GS105Ev2 CGI endpoints and authentication do not
match this GS108Tv2 legacy interface; its code is not incorporated.

## Legacy GS108Tv2 HTTPS troubleshooting

For the legacy GS108Tv2 HTTPS flow, an explicit device rejection is reported
separately from an uncertain network/readback failure. `Failed to set HTTPS
Admin Mode` is a switch-side rejection: inspect its HTTPS Certificate Download
setup and firmware support in the native GUI. Its old `TLS Version 1` label
means TLS 1.0, not a guarantee of TLS 1.2 support. The app never enables legacy
TLS or weak ciphers, and retains HTTP until modern TLS and certificate approval
are verified.
