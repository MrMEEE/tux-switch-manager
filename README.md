# Tux Switch Manager

A multi-switch management application built with Python, Django, Celery/Beat and
Django Channels. [Switchman](https://github.com/MrMEEE/switchman) is the functional reference; there is intentionally
no switch image, faceplate mapping or image-detection integration. The initial
driver targets Juniper EX3300-24P and EX3300-48P, including older non-ELS Junos.

## Features

- Fleet inventory, per-device access and cached operational/configuration views.
- System, interface, VLAN, LAG, static-route, security and service configuration;
  validated manual `set`/`delete` commands for advanced settings.
- Stage changes, preview and commit or discard. Immediate apply is disabled.
  Junos provides a device-generated diff and commit-check; the legacy NETGEAR
  adapter provides a local planned diff and managed-field readback instead.
- Monitor chassis, health, interfaces, switching, routing, BGP, OSPF, ARP, MAC,
  LLDP, PoE and alarms. Optional SNMPv2c IF-MIB polling supplies interface names,
  administrative/operational status and 64-bit traffic counters.
- Background synchronization, command history, ping, traceroute and reboot.
- RBAC-controlled discovery without credentials lists management-service candidates
  with detection evidence. Assign credentials to verify and enroll supported switches.
- Reusable username/password credentials, encrypted at rest, with a permission-gated
  management page. Existing environment-variable credentials remain supported.
- Permission-filtered WebSocket notifications update cached data and job history
  without replacing configuration forms that users are editing.
- Authenticated WebSockets push live discovery progress/results, fleet inventory
  and status, switch telemetry/history, job output, credential lists and credential
  choices. No manual refresh is needed. Discovery history expansion and unsaved
  form values are preserved; updates to focused controls are deferred until blur.
  Disconnections reconnect automatically with backoff, and a 30-second WebSocket
  resynchronization rechecks sessions and permissions. Revoked access clears the
  affected live region instead of retaining sensitive data. The page shows the
  connection state; ordinary HTTP polling is not used.
- Encrypted configuration revisions, adjacent-revision diffs and restoration.
  Revisions are created when the configuration changes, including out-of-band
  changes detected by polling. Commits and restores record their initiating user.
- A vendor-independent driver contract and settings-based plugin registry.
- Web-only NETGEAR GS108Tv2 legacy GUI support, including encrypted password-only
  credentials, monitoring and staged graphical edits, with explicit HTTP and
  non-atomic-write warnings.
- A responsive dark workspace matching TuxCMDB's sidebar, blue accents and green
  Tux branding, with collapsible navigation and locally served theme assets.

## Web-only NETGEAR GS108Tv2

Choose **Netgear Gs108Tv2** (`netgear_gs108tv2`) in inventory or discovery and
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
  management network. The adapter disables proxy use, refuses redirects and
  keeps session cookies in memory, never in a shared file or logs.
- Revisions contain only managed fields, not a full restorable configuration.
  Preview is a local planned diff, not a device candidate or commit-check.
- Writes take effect immediately, without a remote lock, atomic transaction or
  rollback. Commit-all is disabled. Commit one item, synchronize and restage
  remaining edits against the new baseline.
- The adapter compares managed fields before writing and verifies readback
  afterward. A failed/uncertain write is marked **uncertain**, not automatically
  retried. Inspect actual state, synchronize, discard the uncertain change and
  restage deliberately. Concurrent edits through the device GUI cannot be locked.
- Startup persistence is not verified. After checking the applied changes, use
  **Save Configuration** in the switch GUI. That device action can save *all*
  previously applied changes, including changes made by other administrators.
- VLAN/uplink/admin-state edits can disconnect management access. PVID is not
  changed by the membership editor. Avoid traffic-affecting writes outside a
  maintenance window.

No additional dependency is needed. PyNetgearSwitchController was evaluated as
a reference, but its GS108Ev3/GS105Ev2 CGI endpoints and authentication do not
match this GS108Tv2 legacy interface; its code is not incorporated.

## Run locally

Requires Python 3.12+ and Redis. Install Redis using your operating system's
package manager. The launcher can start Redis as your own user without sudo;
for the manual terminal commands below, start Redis separately.
Run these commands from the repository root:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

export DJANGO_DEBUG=1
export DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
export CONFIG_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
export REDIS_URL=redis://127.0.0.1:6379/0
export SWITCH_KNOWN_HOSTS="$HOME/.ssh/known_hosts"

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

In two additional terminals, activate the virtual environment and supply the
**same** environment (including both keys and the switch credentials):

```sh
celery -A tux_switch worker --loglevel=INFO
celery -A tux_switch beat --loglevel=INFO
```

Alternatively, use `./tux-switch-manager` to manage the web server, worker and
Beat together. It loads its settings from `config/config.conf` (or the file
named by `TUX_SWITCH_CONFIG`); variables already exported in the shell are used
when no configuration file exists. Create the file from the sample, fill in the
keys and credentials, and keep it private:

```sh
cp config/config.conf.sample config/config.conf
chmod 600 config/config.conf
./tux-switch-manager manage migrate
./tux-switch-manager manage createsuperuser
./tux-switch-manager start
./tux-switch-manager status
./tux-switch-manager restart
./tux-switch-manager stop
```

On `start`, `restart` and `manage`, the script creates `.venv` with `python3` if it is
missing (override the interpreter with `TUX_SWITCH_PYTHON`) and runs
`pip install -r requirements.txt` when a pinned requirement is missing or has a
different version. It writes process IDs to `.run/` and service output to `logs/`.
`start` and `restart` automatically apply database
migrations with `migrate --noinput` and collect CSS/JavaScript with
`collectstatic --noinput` before launching services; if either step fails, startup
aborts. Back up the database before restarting after an application update.
For an initial installation, run `./tux-switch-manager manage migrate` before
creating the superuser, or create the superuser after the first successful start. Use
`./tux-switch-manager manage <command> [arguments...]` for any Django management
command with the configured environment and project virtual environment.
Activating `.venv` alone does not load `config/config.conf` for direct
`manage.py` commands. The web server binds to `127.0.0.1:8000` by
default; override this with `TUX_SWITCH_BIND_HOST` and `TUX_SWITCH_PORT` when
needed. For production, use the deployment guidance below and do not expose
the development setup to an untrusted network.

The launcher reuses a responding Redis at `REDIS_URL`. If a local unauthenticated
`redis://` endpoint is unavailable, it starts `redis-server` under your user,
bound only to loopback with protected mode enabled. No sudo or system service
is needed. Install the `redis-server` binary separately if it is missing.
Remote, authenticated and TLS endpoints must be provided externally; the script
does not substitute another Redis when those endpoints fail.

Redis data is persisted with append-only files in `.redis/` (private and
git-ignored), its PID is stored in `.run/redis.pid`, and its log is
`logs/redis.log`. `stop` shuts down the app services before its own Redis;
it never stops an externally managed Redis. `status` identifies the user-owned
instance or reports external Redis connectivity.

If discovery reports that it could not queue, check `REDIS_URL` and
`logs/redis.log` / `logs/worker.log`. Submit a new scan after Redis is available;
failed runs are not automatically retried.

Visit `http://127.0.0.1:8000/`. Add a switch, grant access, then synchronize it.
The Django admin at `/admin/` manages users, groups, inventory permissions and
per-switch access grants. Web mutations require authenticated sessions and CSRF
tokens; worker jobs recheck permissions before contacting devices.

Keep the generated keys stable between restarts. Store them in your deployment's
secret manager, not in source control. Losing `CONFIG_ENCRYPTION_KEY` makes stored
revisions, snapshots and job outputs unreadable. Back it up separately from the
database. Changing `DJANGO_SECRET_KEY` invalidates existing sessions.

### Connecting the Juniper test switches

Enable NETCONF on each switch using a trusted local administration connection:

```text
set system services netconf ssh
commit
```

Use port **830** for the standard NETCONF listener. Port 22 may also support the
`netconf` SSH subsystem on the installed Junos release; the inventory port is
configurable. This driver requires NETCONF, not just an interactive CLI login.
Use a Junos account with permissions for the intended RPCs.

### Graphical configuration

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
Configuration tabs sit above the panel and show only the selected section
without reloading the page. The active tab survives WebSocket updates.
Use Left/Right arrows or Home/End to navigate the tabs with a keyboard.
Review and Commit is available as a separate tab.

### Switchman configuration parity

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
| User management and permissions | Django administration plus per-switch Viewer/Operator/Administrator roles and inventory/discovery/credential/access permissions |

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

### Credentials and SSH trust

Verify each switch's host-key fingerprint independently and put its key in
`SWITCH_KNOWN_HOSTS`. Nonstandard ports use `[address]:port` known-host entries.
Do not blindly trust a key obtained by scanning the network. Unknown or changed
keys are rejected during discovery. Candidate verification can request explicit
approval for an unknown key, but never silently replaces a changed key.
Authenticated discovery displays safe per-address verification errors for missing
or changed host keys, rejected credentials, and unavailable NETCONF. A completed
scan does not mean every address was verified or enrolled.

Use **Credentials** in the sidebar to create a named username/password pair, then
select it on the switch inventory form. Credential creation/editing requires
`switches.manage_credentials` (superusers have it automatically). Passwords are
encrypted with `CONFIG_ENCRYPTION_KEY` and are never displayed or prefilled;
leaving the password blank when editing preserves it. These are shared credentials:
inventory managers and discovery users can select and use them without viewing
passwords. Restrict those permissions to trusted network administrators. Updating
a shared credential changes the login used by every assigned switch.

Alternatively, supply the SSH password through a variable named `SWITCH_CREDENTIAL_<NAME>` in
the **worker's** environment. The web inventory stores only that variable's
name, never the password. Saved credentials take precedence over these legacy
username/reference values when selected. The discovery and inventory forms expose
only the saved credential selector; existing legacy switch records retain their
environment credentials until a saved credential is assigned. Supply the variable to the web process too when using structured
configuration builders. Enter `SWITCH_CREDENTIAL_LAB`, for example, in the
credential-reference field; obtain its value securely from your secret manager.

For optional SNMP, enable a read-only community on the switch, enable SNMP in
inventory and supply its separate `SWITCH_CREDENTIAL_<NAME>` reference to the
worker. SNMPv2c communities travel unencrypted: use this only on an isolated,
trusted management network. SNMP failure does not discard valid SSH telemetry.

## Access and configuration safety

| Per-switch role | Access |
| --- | --- |
| Viewer | Operational telemetry, synchronization, ping and traceroute |
| Operator | Viewer access plus configuration, manual show commands, revisions and restore |
| Administrator | Operator access plus reboot and inventory editing when globally permitted |

An active superuser has access to every switch. Other users see only explicitly
granted devices. Global `manage_inventory` and `discover_switches` permissions
control onboarding/discovery. Grant administration privileges only to trusted
people; Django's user/group administration can itself confer privileged access.
WebSocket access is checked again against the database/session on every event,
so revoked device access, account disabling and logout take effect.

All device operations take a per-switch database lease. Junos changes also take
an exclusive candidate lock, refuse pre-existing candidate changes, compare the
current configuration with the staged baseline, and run commit-check. Preview
and failed loads discard their own candidate changes. Configuration conflicts
require a fresh synchronization and a newly staged change.

**A lost connection during commit has an uncertain outcome.** Mutating jobs are
not automatically retried. Synchronize and inspect the switch before retrying.
Beat recovers expired worker jobs after the operation lease period. There is no
cross-switch atomic commit or automatic rollback of a fleet.

Discovery accepts any IPv4 or IPv6 network with at most 256 addresses per run.
There is no network allowlist. Grant the **Scan networks and discover switches**
permission (`switches.discover_switches`) to authorized users or groups in Django
administration; a per-switch role alone does not permit scanning. Existing grants
of this permission are retained, and superusers have it automatically. The web
page, queue service and worker enforce scanning permission, and the worker
rechecks it before network contact. Only grant it to people authorized to scan
networks reachable from the worker. Without credentials discovery checks TCP
22, 80, 443, 830 and the selected port using one-second socket timeouts, and reads
at most 4 KiB per SSH/HTTP/HTTPS response within a two-second read budget.
It does not authenticate, follow HTTP redirects,
probe default passwords/communities, or enroll devices. Vendor markers and an
SSH banner on TCP 830 indicate a potential network device; routers and servers can
also match. A generic open management port (including SSH alone) is excluded.

Detection is implemented entirely with unprivileged Python sockets: SSH banners
and HTTP/HTTPS response headers and page content. No Nmap, sudo, raw sockets,
OS fingerprinting or external lookup services are used.
HTTPS discovery accepts self-signed certificates only to read public service
responses; no secrets are sent and this does not establish device trust for
authenticated management.

Recognized fingerprints include Cisco, Juniper, HP/Aruba/Comware/H3C, SMC,
Extreme, Brocade/Ruckus, D-Link, NETGEAR, TP-Link, MikroTik, Ubiquiti, Dell,
Huawei, Allied Telesis, Zyxel, Edgecore, Arista, Fortinet and Alcatel-Lucent.
Vendor fingerprints are heuristic and can be spoofed. Routers, access points or
servers with matching text may appear; switches exposing only generic banners
may be missed. An open port alone never qualifies. SSH on port 830 is labeled
as a possible NETCONF device, not a verified NETCONF service or switch.

When no vendor service fingerprint is found, discovery falls back to the local
MAC address and an offline IEEE MA-L OUI database. It can also identify a
neighbor with no open management ports. Supported manufacturer matches include
Cisco, Juniper, HP/HPE/Aruba, SMC, Extreme, Brocade/Ruckus, NETGEAR and the other
network vendors listed above. These matches are labeled as manufacturer-only
evidence, not proof of a switch. An available service fingerprint takes precedence.

The worker uses `ip` from `iproute2` to read directly connected ARP/NDP neighbors
without sudo, and never substitutes a gateway's MAC for a routed device.
Routed hosts, randomized MAC addresses and missing neighbor entries may have no
OUI fallback. The default database is `/usr/share/ieee-data/oui.csv`, supplied by
the `ieee-data` package on Debian/Ubuntu; override it with `DISCOVERY_OUI_FILE`.
Lookups are local and cached, and database updates are picked up on subsequent
lookups. Missing tools/files are logged and do not discard service detections.

Discovery history is ordered newest first, with only the latest visible run
expanded by default. Expand older runs to review their results. Select a
candidate's saved credential and SSH/NETCONF port, then choose **Verify and add**.
This directly checks that candidate using the selected credential, without
creating another discovery run. The selected driver's facts/model validation and
configuration read must succeed; the Juniper driver currently accepts
EX3300-24P/48P.

If the host key is unknown, a modal shows the address, port, key algorithm and
SHA-256 fingerprint. Independently compare the fingerprint before choosing
**Trust and add**. Approval expires after five minutes and is bound to your
session, candidate, credential and port. Verification retries with the exact
approved key pinned; changed keys are rejected. Only successful verification
saves the public key (with approving user and timestamp) in the application
database and enrolls the switch. Workers reuse these trusted keys for subsequent
operations; existing `SWITCH_KNOWN_HOSTS` trust remains supported. Cancel or a
verification failure adds neither a switch nor a trusted key. The original
candidate becomes a fleet link via live updates. Existing inventory credentials
and access are never overwritten by enrollment.

Supplying credentials to the original scan retains the existing authenticated
enrollment workflow; that workflow does not prompt for unknown keys.

Discovery runs sequentially to avoid
overloading switches; unavailable hosts may make a run take a long time (the
discovery task has a six-hour limit). Prefer small management subnets. Devices
without trusted keys or valid credentials are not enrolled. LLDP neighbors are
available as telemetry; discovery does not recursively scan neighboring networks.

## Add another vendor

Implement a subclass of `switches.drivers.base.BaseDriver` in a Python module.
Register its slug in `SWITCH_DRIVERS` in Django settings, alongside `juniper_ex`:

```python
SWITCH_DRIVERS = {
    "juniper_ex": "switches.drivers.juniper.JuniperEXDriver",
    "example_vendor": "your_package.driver.ExampleDriver",
}
```

The registry supplies `host`, `port`, `username`, `password`, `known_hosts` and
`timeout`. Implement context-managed connection cleanup and the capabilities
your vendor supports:

- `get_facts()`, `get_config()` and `snapshot()` for inventory and polling.
- `monitor(section)`, `run_command(command)` and `diagnostic(action, target)`.
- `build_change(section, values)` for structured forms.
- `preview(commands)`, `apply(commands, expected_config)` and
  `restore(config, expected_config)` for configuration management.

Advertise supported methods in `capabilities` and monitoring sections in
`monitor_sections`. Unsupported methods must raise `UnsupportedCapability`.
Application-specific forms can extend `BUILDERS` in `switches/forms.py`; generic
manual configuration remains available. Snapshot sections may be structured
JSON-compatible values or text. Only explicitly approved operational sections
are exposed to viewers; new configuration sections require operator access.

Drivers must validate user input, authenticate the remote endpoint, bound
timeouts/output sizes, sanitize errors, avoid shell interpolation, and enforce
configuration concurrency on the device. `get_config()` must return stable,
complete text suitable for baseline comparisons and later restoration. Transport
choices belong in drivers, not views or tasks. The included mocked Juniper tests
demonstrate framing, host-key rejection, input validation and candidate cleanup.

## Settings and deployment

`SWITCH_POLL_SECONDS` controls Beat polling (default 60, minimum 30).
`DATABASE_PATH` overrides the SQLite database location. SQLite is suitable for a
small initial installation; fleet-scale deployments should configure Django
`DATABASES` for PostgreSQL, install its database adapter, and size workers and
polling intervals for the target network. No live hardware validation or
fleet-scale performance certification is implied by the mocked tests.

For production, leave `DJANGO_DEBUG` unset, set a persistent random
`DJANGO_SECRET_KEY`, `CONFIG_ENCRYPTION_KEY`, `DJANGO_ALLOWED_HOSTS` and, if needed,
`DJANGO_CSRF_TRUSTED_ORIGINS`. Serve HTTPS through an ASGI-capable deployment:

```sh
python manage.py collectstatic --noinput
python manage.py check --deploy
daphne -b 127.0.0.1 -p 8000 tux_switch.asgi:application
```

WhiteNoise serves collected CSS/JavaScript through Django, including under Daphne;
the reverse proxy can serve `staticfiles/` directly instead. Forward WebSocket
upgrades. Set `DJANGO_TRUST_PROXY_HTTPS=1` only behind a trusted TLS-terminating
proxy that strips client-supplied `X-Forwarded-Proto` headers and sets its own;
otherwise leave it unset. Do not expose the development server publicly. Cookies are
secure and HTTPS redirect/HSTS are enabled outside debug mode. Keep Redis
private/authenticated, protect the worker environment, and encrypt database
backups. Revisions/history currently have no automatic retention policy.

## Tests

```sh
python manage.py test --settings=tux_switch.test_settings
python manage.py makemigrations --check --dry-run --settings=tux_switch.test_settings
```

The test settings generate ephemeral keys, use an in-memory channel layer and do
not contact real switches. Tests cover backend authorization, encrypted storage,
discovery boundaries, conflict detection, idempotent jobs, NETCONF transactions,
HTTP authorization/CSRF and WebSocket session/access revocation.
