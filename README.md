# Tux Switch Manager

A multi-switch management application built with Python, Django, Celery/Beat and
Django Channels. Switchman is the functional reference; there is intentionally
no switch image, faceplate mapping or image-detection integration. The initial
driver targets Juniper EX3300-24P and EX3300-48P, including older non-ELS Junos.

## Features

- Fleet inventory, per-device access and cached operational/configuration views.
- System, interface, VLAN, LAG, static-route, security and service configuration;
  validated manual `set`/`delete` commands for advanced settings.
- Stage changes, preview the device-generated diff and commit or discard.
  Immediate commit is also available. Junos commit-check runs before committing.
- Monitor chassis, health, interfaces, switching, routing, BGP, OSPF, ARP, MAC,
  LLDP, PoE and alarms. Optional SNMPv2c IF-MIB polling supplies interface names,
  administrative/operational status and 64-bit traffic counters.
- Background synchronization, command history, ping, traceroute and reboot.
- Approved-CIDR discovery with a selectable driver and credential reference.
  Discovered switches enter inventory without overwriting existing devices.
- Permission-filtered WebSocket notifications update cached data and job history
  without replacing configuration forms that users are editing.
- Encrypted configuration revisions, adjacent-revision diffs and restoration.
  Revisions are created when the configuration changes, including out-of-band
  changes detected by polling. Commits and restores record their initiating user.
- A vendor-independent driver contract and settings-based plugin registry.

## Run locally

Requires Python 3.12+ and Redis. Install Redis using your operating system's
package manager and start it, listening only on a trusted management network.
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
# Only these management networks may be scanned. No networks are allowed by default.
export DISCOVERY_NETWORKS=192.168.10.0/24

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

Verify each switch's host-key fingerprint independently and put its key in
`SWITCH_KNOWN_HOSTS`. Nonstandard ports use `[address]:port` known-host entries.
Do not blindly trust a key obtained by scanning the network. Unknown or changed
keys are rejected, including during discovery.

Supply the SSH password through a variable named `SWITCH_CREDENTIAL_<NAME>` in
the **worker's** environment. The web inventory stores only that variable's
name, never the password. Supply it to the web process too when using structured
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

Discovery scans at most 256 addresses per run and revalidates the approved CIDR
and initiating user's permission in the worker. It runs sequentially to avoid
overloading switches; unavailable hosts may make a run take a long time (the
discovery task has a six-hour limit). Prefer small management subnets. Devices
without trusted keys or valid credentials are not enrolled. LLDP neighbors are
available as telemetry; discovery does not recursively scan unapproved networks.

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

Serve collected static files through the reverse proxy and forward WebSocket
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
