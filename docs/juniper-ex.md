# Juniper EX3300

[Back to supported switches](../README.md#supported-switches)

## Models and validation

The `juniper_ex` profile accepts **EX3300-24P** and **EX3300-48P** only,
including older non-ELS Junos. Both models have live synchronization coverage.
Automated tests cover configuration builders, NETCONF transactions, conflict
checks and uncertain outcomes; this is not blanket live certification of every
editor field or firmware release.

## Connection setup

Enable NETCONF on each switch using a trusted local administration connection:

```text
set system services netconf ssh
commit
```

Use port **830** for the standard NETCONF listener. Port 22 may also support the
`netconf` SSH subsystem on the installed Junos release; the inventory port is
configurable. This driver requires NETCONF, not just an interactive CLI login.
Use a Junos account with permissions for the intended RPCs.

## Graphical configuration

The device workspace's **Current configuration** is the preferred editor.
Synchronize once after upgrading to collect committed NETCONF XML in addition
to the encrypted text baseline. Tables show current ports, VLANs, LAGs, system
settings, static routes, NTP/DNS servers, SNMP contact/location and community access, and simple IPv4
firewall terms. Choose **Edit** for a prefilled form; switching/LACP modes and
time zones use dropdowns, and VLAN/LAG membership uses checkbox selections from
the switch's current inventory. New physical ports are not invented: they are
taken from configuration and synchronized interface telemetry.

Saving generates only changed settings and creates a staged change. It does
not contact or commit to the switch. Use **Review and Commit**, preview the
remote diff in job output, then commit when ready. Changes are committed
individually or together with **Preview all pending / Commit all pending**.
Combined changes must share the current baseline and are processed in staging
order under one candidate lock. Discard-all affects pending changes only.
Stale editor baselines are rejected, and remote apply still checks the exact
committed baseline under the NETCONF configuration lock.

## Implicit default VLAN

The Junos VLAN editor supports the implicit `default` VLAN even when no
`vlan-id` is present. It displays ID 1 as implicit and prefills the routed
interface and addresses. Leaving ID blank preserves the implicit configuration;
metadata/address edits do not add an explicit VLAN ID. Rename/deletion of this
implicit VLAN remain unavailable, and management-address/membership changes
still require staging and an explicit commit.

## Transaction diagnostics and uncertain outcomes

NETCONF preview, commit and restore job outputs retain a bounded transaction
trace, including the rejected RPC stage, allowlisted error codes, safe error
categories, configuration line numbers when supplied, and candidate
discard/unlock outcomes. Raw device error messages, configuration values and
credentials are not logged. Existing failed jobs cannot recover details that
were not saved. On older Junos releases, whole-unit deletions for LAG member
attachment are expanded to explicit unit IDs under the candidate lock, including
all configured units rather than assuming unit 0.

Junos commit acknowledgements have a minimum 120-second reply deadline because
flash writes and daemon activation can exceed normal read-RPC timeouts. A lost
commit reply, failed post-commit unlock, or expired apply worker marks its change
as **uncertain**, never pending/retryable. Synchronize and reconcile the actual
device configuration before removing an uncertain record or creating replacement changes. The switch
may already have committed even when its job is failed; no automatic commit
retry is performed.

For shared staging terminology, newer revisions and read-only outcome
verification, see [pending changes](../README.md#pending-changes-and-newer-configuration-revisions).

## Graphical editor limitations

The GUI preserves unrelated settings. Complex items it cannot represent are
marked for the collapsed **Advanced · manual configuration** editor instead of
being approximated. Configurations using groups, interface ranges, or inactive
settings require Advanced. Firewall editing currently covers simple IPv4 terms,
not filter attachment or term reordering. SNMP communities are not displayed in
the graphical editor; existing community access/client restrictions can be edited
without revealing the secret. New communities use a configured
`SWITCH_CREDENTIAL_` reference, and unrestricted client lists require explicit
acknowledgement. New LAG member attachments require acknowledgement because
they remove existing unit configuration; unchanged members are not reattached.
VLAN deletion is blocked while configured port memberships reference it.
Current configuration tables update via WebSockets; an open edit form is kept
outside live replacement so unsaved input is preserved.

## Switchman configuration parity

The reference audit covers Switchman commit
`75e8e054399586289f489c12648411ca68468540`, including its forms, handlers,
templates, integrations, models and tests. The features below are independently
implemented using this project's NETCONF driver; reference SSH shell scripts,
unsafe input sanitization and destructive whole-subtree replacements are not
copied.

| Switchman capability | Tux Switch Manager equivalent |
| --- | --- |
| Port enable/disable, description, MTU, speed, duplex, flow control and auto-negotiation | Prefilled Ports editor; only changed leaves are staged |
| Access/trunk mode, VLAN membership and native VLAN | Dropdowns and membership selections in Ports and LAGs |
| IPv4/IPv6 interface addresses | Existing-address checkboxes plus validated address/prefix additions |
| LAG creation/deletion, member attachment/removal, LACP and minimum links | Link aggregation editor, with attachment-impact acknowledgement |
| Enable/disable aggregate provisioning and device count | Aggregate device provisioning editor; configured LAGs cannot be removed accidentally |
| VLAN ID/list/ranges, description and MAC aging | VLAN editor with validated ranges and overlapping-ID checks |
| VLAN rename and interface membership assignment/removal | VLAN editor updates references; access-port replacement requires acknowledgement |
| VLAN input/output filters and routed VLAN interface addresses | Filter selections and routed VLAN interface fields, supporting `vlan.N` and `irb.N` |
| Hostname, domain, timezone, DNS and NTP | System and Services editors |
| SNMP read-only/read-write communities and deletion | Services editor; secrets hidden, new communities use secret references |
| Static routes and deletion | Static routes editor, including IPv6 |
| Compare/commit/discard pending changes together | Review and Commit, including combined pending-change actions |
| Manual set/delete and operational show commands, with reason | Advanced configuration and diagnostics; reasons retained for audit |
| Ping/count, traceroute and reboot | Diagnostics and administrator-only reboot |
| Device notes, monitoring enablement, SNMP timeout/port and active state | Inventory settings; manual synchronization is available when automatic monitoring is disabled |
| Configuration/status synchronization and live SNMP interfaces | Background jobs and WebSocket state updates |
| Alarms, ARP, BGP, chassis, interfaces, LLDP, MAC, OSPF, PoE, routing, STP, IGMP, 802.1X, port security and syslog monitoring | Monitoring and diagnostics buttons plus synchronized snapshot/job output |
| LLDP configuration display; firewall, DHCP, 802.1X and port-security raw configuration | Current LLDP table and dedicated configuration-monitor actions; Advanced for manual edits |
| User management and permissions | In-app superuser account management, per-switch Viewer/Operator/Administrator grants and inventory/discovery/credential/access permissions |

Switchman's STP, IGMP, DHCP, 802.1X and port-security configuration pages have no
dedicated configuration handlers; their manual-command possibilities are retained,
not presented as newly working graphical editors. Its LAG logging checkbox is
unused by the backend and is not replicated as a misleading control. The optional
Ansible show helper has no distinct UI capability; validated read-only NETCONF
show commands provide the equivalent operation. Switchman's immediate-commit
preference is deliberately excluded: edits always stage for Review and Commit.
Its faceplate image, port-image mapping, image/layout editors and image-detection
API integration are excluded. There are no reference export or rollback actions;
this project's existing revision comparison/restoration remains available.

Junos syntax is device-dependent. This driver targets non-ELS EX3300 syntax
(including `link-mode full-duplex/half-duplex` rather than blindly copying an
unverified `duplex` CLI keyword); remote preview/commit-check validates actual
support. Interface units with unrepresented settings remain Advanced rather
than silently flattening or deleting those settings. Configuration secrets remain
encrypted at rest, and saved login credentials replace Switchman's device-password
fields.
