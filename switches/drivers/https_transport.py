"""TLS certificate pinning before sending HTTP headers or credentials."""

import hashlib
from http.client import HTTPSConnection
import socket
import ssl
from urllib.request import HTTPSHandler

from .base import DriverError
from .validation import address


def tls_context():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def certificate(host, port, timeout=15):
    """Unauthenticated certificate inspection; never send an HTTP request."""
    host = address(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise DriverError("Invalid HTTPS port.")
    context = tls_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=host) as secure:
                der = secure.getpeercert(binary_form=True)
                if not der:
                    raise DriverError("The switch did not provide a TLS certificate.")
                return {"fingerprint": hashlib.sha256(der).hexdigest(), "port": port, "tls": secure.version()}
    except (OSError, ssl.SSLError):
        raise DriverError(
            "HTTPS could not negotiate TLS 1.2 or newer. The device may require a firmware update or certificate setup. "
            "HTTPS may now be enabled on the switch, but the app has not changed transport. "
            "SSLv3, TLS 1.0/1.1 and weak ciphers will not be enabled."
        ) from None


class PinnedConnection(HTTPSConnection):
    def __init__(self, *args, fingerprint="", **kwargs):
        self.fingerprint = fingerprint
        super().__init__(*args, **kwargs)

    def connect(self):
        super().connect()
        if self.sock is None:
            raise DriverError("HTTPS connection could not be established.")
        der = self.sock.getpeercert(binary_form=True)
        if not der or hashlib.sha256(der).hexdigest() != self.fingerprint:
            self.close()
            raise DriverError("HTTPS certificate changed. No credentials were sent. Review and approve the new certificate.")


class PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, fingerprint):
        context = tls_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.fingerprint = fingerprint
        self.context = context
        super().__init__(context=context)

    def https_open(self, req):
        return self.do_open(PinnedConnection, req, context=self.context, fingerprint=self.fingerprint)
