"""Vendor-independent switch driver contract; importing this package needs no Django."""

from typing import Self


class DriverError(Exception):
    """Safe, user-facing driver failure. Messages must never contain credentials."""


class UntrustedHostKey(DriverError):
    def __init__(self, algorithm, public_key, fingerprint):
        super().__init__(
            "SSH host key is not trusted. Verify the switch fingerprint before trusting it."
        )
        self.algorithm = algorithm
        self.public_key = public_key
        self.fingerprint = fingerprint


class ConfigConflict(DriverError):
    """The committed configuration changed since the caller's snapshot."""


class UnsupportedCapability(DriverError):
    """The requested operation is not implemented by this driver."""


class BaseDriver:
    """Context-managed vendor interface.

    Constructors accept host, port, username, password, known_hosts, and timeout.
    Operations run only inside a connected context. ``capabilities`` contains
    method names actually implemented; callers should use ``require_capability``.
    ``get_config`` returns the exact text used for optimistic concurrency checks.
    ``snapshot`` returns raw or structured sections; unsupported monitor commands
    may be represented by empty values and a separate ``errors`` mapping.
    Preview never writes configuration. Transactional drivers compare the baseline
    under an exclusive candidate lock. Web adapters must explicitly disclose their
    weaker guarantees and verify readback; they must not advertise restore/atomic
    operations they cannot provide. Never interpolate inputs into a shell.
    """

    capabilities = frozenset()
    trusted_host_key = None
    monitor_sections = frozenset()
    transport = "ssh"
    requires_username = True

    def supports(self, capability):
        return capability in self.capabilities

    def require_capability(self, capability):
        if not self.supports(capability):
            raise UnsupportedCapability("This driver does not support that operation.")

    def __enter__(self) -> Self:
        raise UnsupportedCapability("This driver cannot connect.")

    def __exit__(self, exc_type, exc, traceback):
        return False

    def get_facts(self):
        self.require_capability("get_facts")
        raise NotImplementedError

    def get_config(self):
        self.require_capability("get_config")
        raise NotImplementedError

    def snapshot(self):
        self.require_capability("snapshot")
        raise NotImplementedError

    def monitor(self, section):
        self.require_capability("monitor")
        raise NotImplementedError

    def run_command(self, command):
        self.require_capability("run_command")
        raise NotImplementedError

    def diagnostic(self, action, target="", count=5):
        self.require_capability("diagnostic")
        raise NotImplementedError

    def preview(self, commands):
        self.require_capability("preview")
        raise NotImplementedError

    def apply(self, commands, expected_config):
        self.require_capability("apply")
        raise NotImplementedError

    def restore(self, config, expected_config):
        self.require_capability("restore")
        raise NotImplementedError

    def build_change(self, section, values):
        self.require_capability("build_change")
        raise NotImplementedError
