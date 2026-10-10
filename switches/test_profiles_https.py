import hashlib
import ssl
from unittest import TestCase as UnitTestCase
from unittest.mock import MagicMock, Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from .drivers.base import DriverError
from .drivers.https_transport import PinnedConnection, PinnedHTTPSHandler, certificate, tls_context
from .drivers.netgear import NetgearGS108Tv2Driver, Page
from .forms import DiscoveryForm, SwitchForm
from .https_setup import execute_https
from .models import Credential, DiscoveryRun, Job, Switch, SwitchAccess
from .profiles import annotate, resolve
from .services import queue_job, record_revision
from .tasks import discover_switches, execute_job
from .test_netgear import canonical, state


def netgear_candidate(address="192.0.2.5"):
    return {"address": address, "status": "candidate", "vendor": "NETGEAR", "open_ports": [80],
            "evidence": ["NETGEAR marker"], "fingerprint": "<title>NetGear GS108T</title>"}


class ProfileMatchingTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("scanner")
        self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        self.credential = Credential.objects.create(name="web", username="", password="fake-password")
        self.client.force_login(self.user)

    def test_netgear_exact_and_possible_model_matching(self):
        candidate = annotate(netgear_candidate())
        self.assertEqual(candidate["profile"], "netgear_gs108tv2")
        self.assertIn("verification required", candidate["support"])
        self.assertEqual(candidate["profile_port"], 80)
        candidate = netgear_candidate()
        candidate["fingerprint"] = "GS108Tv2"
        self.assertIn("Supported profile", annotate(candidate)["support"])

    def test_vendor_alone_and_wrong_models_are_not_claimed_supported(self):
        for vendor, fingerprint in (("NETGEAR", "GS108Ev3"), ("Cisco", "Catalyst"), ("Juniper", "EX4300-48P"), ("NETGEAR", "")):
            with self.subTest(vendor=vendor, fingerprint=fingerprint):
                item = annotate({"vendor": vendor, "fingerprint": fingerprint})
                self.assertFalse(item["supported"])
                with self.assertRaises(DriverError):
                    resolve(item)

    def test_juniper_match_prefers_netconf_and_rechecks_model(self):
        candidate = annotate({"vendor": "Juniper", "open_ports": [22, 830], "fingerprint": "JUNOS"})
        self.assertEqual(candidate["profile"], "juniper_ex")
        self.assertEqual(candidate["profile_port"], 830)
        self.assertIn("verification required", candidate["support"])
        candidate = annotate({"vendor": "Juniper", "fingerprint": "EX3300-24P"})
        self.assertIn("Supported profile", candidate["support"])

    @override_settings(SWITCH_DRIVERS={})
    def test_disabled_profile_not_advertised(self):
        self.assertFalse(annotate(netgear_candidate())["supported"])

    def test_unknown_ssh_or_oui_only_netgear_not_automatched(self):
        for candidate in ({}, {"vendor": "Unknown (SSH on NETCONF port)", "open_ports": [830]},
                          {"vendor": "NETGEAR", "confidence": "manufacturer OUI fallback"}):
            with self.assertRaises(DriverError):
                resolve(candidate)

    def test_verified_result_stays_supported_in_live_rendering(self):
        result = annotate({"verified": True, "profile": "netgear_gs108tv2", "status": "found"})
        self.assertEqual(result["support"], "Supported — model verified")

    def test_manual_auto_selects_real_profile_and_preserves_custom_port(self):
        data = {"name": "Lab", "address": "192.0.2.5", "driver": "auto", "credential": self.credential.pk}
        with patch("switches.discovery.probe_candidate", return_value=netgear_candidate()):
            form = SwitchForm(data)
            self.assertTrue(form.is_valid(), form.errors)
            switch = form.save()
            self.assertEqual(switch.driver, "netgear_gs108tv2")
            self.assertEqual(switch.port, 80)
            form = SwitchForm({**data, "address": "192.0.2.6", "port": 8080})
            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data["port"], 8080)

    def test_manual_auto_reports_unmatched_instead_of_guessing(self):
        with patch("switches.discovery.probe_candidate", return_value=None):
            form = SwitchForm({"name": "Lab", "address": "192.0.2.5", "driver": "auto", "credential": self.credential.pk})
            self.assertFalse(form.is_valid())
            self.assertIn("No supported profile", str(form.errors))
        self.assertFalse(Switch.objects.exists())

    def test_auto_form_defaults(self):
        self.assertEqual(SwitchForm().initial["driver"], "auto")
        self.assertEqual(DiscoveryForm().fields["driver"].initial, "auto")

    def test_auto_enrollment_uses_candidate_profile_without_rescanning(self):
        run = DiscoveryRun.objects.create(
            network="192.0.2.5/32", driver="auto", created_by=self.user,
            results=[netgear_candidate()], status="success",
        )
        driver = MagicMock()
        driver.get_facts.return_value = {"hostname": "lab", "model": "GS108Tv2"}
        driver.get_config.return_value = canonical(state())
        with patch("switches.enrollment.get_driver", return_value=driver) as factory, patch("switches.tasks.probe_candidate") as probe:
            response = self.client.post(reverse("candidate-confirm", args=[run.pk]), {
                "address": "192.0.2.5", "credential": self.credential.pk, "port": 80, "driver": "auto",
            })
        self.assertEqual(response.json()["status"], "added")
        self.assertEqual(factory.call_args.args[0].driver, "netgear_gs108tv2")
        self.assertEqual(Switch.objects.get().driver, "netgear_gs108tv2")
        probe.assert_not_called()

    def test_auto_discovery_without_credentials_shows_support_over_http_and_ws(self):
        run = DiscoveryRun.objects.create(network="192.0.2.5/32", driver="auto", created_by=self.user)
        with patch("switches.tasks.probe_candidate", return_value=netgear_candidate()):
            discover_switches(run.pk)
        run.refresh_from_db()
        self.assertEqual(run.results[0]["profile"], "netgear_gs108tv2")
        response = self.client.get(reverse("discovery"))
        self.assertContains(response, "Possible supported profile")
        self.assertContains(response, 'value="80"')
        self.assertFalse(Switch.objects.exists())
        from .live import snapshot
        request = RequestFactory().get("/discovery/")
        request.user = self.user
        payload = snapshot(request, "discovery")
        self.assertIn("Possible supported profile", payload["html"])

    def test_auto_credentialed_scan_uses_matched_profile_not_auto(self):
        run = DiscoveryRun.objects.create(network="192.0.2.5/32", driver="auto", created_by=self.user, credential=self.credential)
        driver = MagicMock()
        driver.__enter__.return_value = driver
        driver.get_facts.return_value = {"hostname": "lab", "model": "GS108Tv2"}
        driver.get_config.return_value = canonical(state())
        with patch("switches.tasks.probe_candidate", return_value=netgear_candidate()), patch(
            "switches.tasks.get_driver", return_value=driver
        ) as factory:
            discover_switches(run.pk)
        self.assertEqual(factory.call_args.args[0].driver, "netgear_gs108tv2")
        self.assertEqual(factory.call_args.args[0].port, 80)
        self.assertEqual(Switch.objects.get().driver, "netgear_gs108tv2")

    def test_auto_unmatched_candidate_kept_visible_without_sending_credentials(self):
        run = DiscoveryRun.objects.create(network="192.0.2.5/32", driver="auto", created_by=self.user, credential=self.credential)
        with patch("switches.tasks.probe_candidate", return_value={"address": "192.0.2.5", "vendor": "Cisco", "status": "candidate"}), patch(
            "switches.tasks.get_driver"
        ) as factory:
            discover_switches(run.pk)
        run.refresh_from_db()
        self.assertEqual(run.results[0]["support"], "No matching supported profile")
        factory.assert_not_called()


class CapabilityTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("operator")
        self.switch = Switch.objects.create(name="Web", address="192.0.2.5", driver="netgear_gs108tv2", port=80)
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        record_revision(self.switch, canonical(state()))
        self.client.force_login(self.user)

    def test_supported_tabs_and_monitoring_only(self):
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        for section in ("ports", "vlans", "system"):
            self.assertContains(response, f'id="tab-{section}"')
        for section in ("lags", "aggregation", "routing", "firewall", "services"):
            self.assertNotContains(response, f'id="tab-{section}"')
            response2 = self.client.get(reverse("configuration-editor", args=[self.switch.pk, section]))
            self.assertEqual(response2.status_code, 403)
        self.assertNotContains(response, 'name="section" value="routing"')
        self.assertNotContains(response, "Reboot switch")
        with self.assertRaises(ValueError):
            queue_job(self.switch, "monitor", {"section": "routing"}, self.user)

    def test_live_snapshot_removes_unsupported_controls_after_profile_change(self):
        from .live import snapshot
        from .test_configuration import CONFIG_XML
        request = RequestFactory().get("/")
        request.user = self.user
        Switch.objects.filter(pk=self.switch.pk).update(
            driver="juniper_ex", snapshot={"config": "junos", "config_xml": CONFIG_XML},
        )
        record_revision(self.switch, "junos")
        before = snapshot(request, "switch", self.switch.pk)["html"]
        self.assertIn('id="tab-aggregation"', before)
        self.assertIn('name="section" value="routing"', before)
        Switch.objects.filter(pk=self.switch.pk).update(driver="netgear_gs108tv2", snapshot={})
        record_revision(self.switch, canonical(state()))
        after = snapshot(request, "switch", self.switch.pk)["html"]
        self.assertNotIn('id="tab-aggregation"', after)
        self.assertNotIn('name="section" value="routing"', after)
        self.assertNotIn("Stage commands", after)
        self.assertIn('id="tab-vlans"', after)

    def test_profile_declared_absent_aggregation_is_hidden_and_rejected(self):
        from .drivers.juniper import JuniperEXDriver
        from .test_configuration import CONFIG_XML
        self.switch.driver = "juniper_ex"
        Switch.objects.filter(pk=self.switch.pk).update(snapshot={"config": "junos", "config_xml": CONFIG_XML})
        self.switch.save()
        record_revision(self.switch, "junos")
        with patch.object(JuniperEXDriver, "configuration_sections", frozenset({"ports", "system"})):
            response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
            self.assertNotContains(response, 'id="tab-lags"')
            self.assertNotContains(response, 'id="tab-aggregation"')
            response = self.client.get(reverse("configuration-editor", args=[self.switch.pk, "aggregation"]))
            self.assertEqual(response.status_code, 403)


class HTTPSTransportTests(UnitTestCase):
    def test_real_tls_transport_sends_body_only_after_matching_certificate(self):
        from datetime import datetime, timedelta, timezone
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from pathlib import Path
        import sys
        import tempfile
        import threading
        from urllib.request import ProxyHandler, Request, build_opener

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-local")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=1)).sign(key, hashes.SHA256()))
        received = []
        expected_disconnects = []
        class Server(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                error = sys.exception()
                if isinstance(error, (BrokenPipeError, ConnectionResetError)):
                    expected_disconnects.append(type(error).__name__)
                else:
                    super().handle_error(request, client_address)
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"verified")

            def log_message(self, format, *args):
                pass

        with tempfile.TemporaryDirectory() as temporary:
            cert_path, key_path = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert_path, key_path)
            server = Server(("127.0.0.1", 0), Handler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_port
                inspected = certificate("127.0.0.1", port)
                self.assertEqual(inspected["fingerprint"], cert.fingerprint(hashes.SHA256()).hex())
                request = Request(f"https://127.0.0.1:{port}/", data=b"test-only-body")
                client = build_opener(ProxyHandler({}), PinnedHTTPSHandler(inspected["fingerprint"]))
                with client.open(request, timeout=3) as response:
                    self.assertEqual(response.read(), b"verified")
                self.assertEqual(received, [b"test-only-body"])
                wrong = build_opener(ProxyHandler({}), PinnedHTTPSHandler("0" * 64))
                with self.assertRaises(DriverError):
                    wrong.open(request, timeout=3)
                self.assertEqual(received, [b"test-only-body"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_radio_parser_keeps_checked_values(self):
        page = Page('<input type="radio" name="https_mode" value="Disable"><input type="radio" name="https_mode" value="Enable" checked>')
        self.assertEqual(page.fields["https_mode"], "Enable")

    def test_client_requires_modern_tls_and_chain_validation_without_pin(self):
        context = tls_context()
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        driver = NetgearGS108Tv2Driver("192.0.2.5", port=443, password="fake", protocol="https")
        self.addCleanup(driver.close)
        self.assertTrue(driver.origin.startswith("https://"))

    def test_unapproved_certificate_inspection_has_no_http_or_credentials(self):
        socket_mock = MagicMock()
        tls = MagicMock()
        tls.__enter__.return_value.getpeercert.return_value = b"fake-certificate"
        tls.__enter__.return_value.version.return_value = "TLSv1.3"
        context = Mock()
        context.wrap_socket.return_value = tls
        with patch("switches.drivers.https_transport.socket.create_connection", return_value=socket_mock), patch(
            "switches.drivers.https_transport.tls_context", return_value=context
        ):
            result = certificate("192.0.2.5", 443)
        self.assertEqual(result["fingerprint"], hashlib.sha256(b"fake-certificate").hexdigest())
        tls.sendall.assert_not_called()
        socket_mock.sendall.assert_not_called()

    def test_legacy_tls_error_is_explicit_and_never_downgrades(self):
        with patch("switches.drivers.https_transport.socket.create_connection", side_effect=ssl.SSLError("legacy")):
            with self.assertRaises(DriverError) as error:
                certificate("192.0.2.5", 443)
        self.assertIn("TLS 1.2", str(error.exception))

    def test_pin_is_checked_before_http_request_body_can_be_sent(self):
        expected = hashlib.sha256(b"certificate-a").hexdigest()
        connection = PinnedConnection("192.0.2.5", fingerprint=expected)
        sock = MagicMock()
        sock.getpeercert.return_value = b"certificate-b"
        def connect(peer):
            peer.sock = sock
        with patch("http.client.HTTPSConnection.connect", connect):
            with self.assertRaises(DriverError):
                connection.request("POST", "/base/main_login.html", body=b"fake-password")
        sock.sendall.assert_not_called()
        sock.close.assert_called()

    def test_matching_pin_allows_connect(self):
        expected = hashlib.sha256(b"certificate-a").hexdigest()
        connection = PinnedConnection("192.0.2.5", fingerprint=expected)
        sock = MagicMock()
        sock.getpeercert.return_value = b"certificate-a"
        def connect(peer):
            peer.sock = sock
        with patch("http.client.HTTPSConnection.connect", connect):
            connection.connect()
        self.assertEqual(connection.sock, sock)

    def test_handler_passes_pin_and_modern_context(self):
        handler = PinnedHTTPSHandler("a" * 64)
        with patch.object(handler, "do_open") as open_request:
            handler.https_open(Mock())
        self.assertEqual(open_request.call_args.kwargs["fingerprint"], "a" * 64)
        self.assertGreaterEqual(open_request.call_args.kwargs["context"].minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_enabling_https_preserves_timeout_and_port_and_disables_sslv3(self):
        driver = NetgearGS108Tv2Driver("192.0.2.5", password="fake")
        self.addCleanup(driver.close)
        fields = {"https_mode": "Disable", "ssl_version": "Enable", "tls_version": "Enable", "https_port": "4443",
                  "https_soft": "5", "https_hard": "24", "https_sessions": "2"}
        count = 0
        def page(path, payload=None):
            nonlocal count
            count += 1
            result = Page("")
            result.fields = {**fields, "https_mode": "Enable" if payload or count > 2 else "Disable"}
            return result
        driver._page = Mock(side_effect=page)
        self.assertEqual(driver.enable_https(), 4443)
        payload = driver._page.call_args_list[1].args[1]
        self.assertEqual(payload["ssl_version"], "Disable")
        self.assertEqual(payload["https_soft"], "5")
        self.assertEqual(payload["https_sessions"], "2")
        self.assertEqual(payload["submt"], "16")


class HTTPSSetupTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("device-admin")
        self.credential = Credential.objects.create(name="web", username="", password="fake")
        self.switch = Switch.objects.create(name="Web", address="192.0.2.5", port=80, driver="netgear_gs108tv2", credential=self.credential)
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="admin")
        self.client.force_login(self.user)
        self.pending = {"fingerprint": "a" * 64, "port": 443, "tls": "TLSv1.2", "address": self.switch.address, "original_port": 80}

    def test_http_connection_offers_https_opt_in_no_automatic_write(self):
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertContains(response, "Enable HTTPS and use it instead?")
        self.assertContains(response, "Enable / inspect HTTPS")
        self.assertEqual(Job.objects.count(), 0)

    def test_https_action_requires_admin_and_explicit_confirmation(self):
        url = reverse("switch-https", args=[self.switch.pk])
        self.assertEqual(self.client.post(url, {"action": "https_enable"}).status_code, 403)
        SwitchAccess.objects.filter(switch=self.switch).update(role="operator")
        self.assertEqual(self.client.post(url, {"action": "https_enable", "confirm": "yes"}).status_code, 403)
        self.assertEqual(Job.objects.count(), 0)

    def test_opt_in_is_queued_and_permission_rechecked(self):
        with patch("switches.services.publish_job"):
            response = self.client.post(reverse("switch-https", args=[self.switch.pk]), {"action": "https_enable", "confirm": "yes"})
        self.assertEqual(response.status_code, 302)
        job = Job.objects.get()
        SwitchAccess.objects.filter(switch=self.switch).update(role="viewer")
        with patch("switches.tasks.get_driver") as factory:
            execute_job(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        factory.assert_not_called()

    def test_enable_inspects_certificate_and_keeps_http_until_approved(self):
        job = Job.objects.create(switch=self.switch, action="https_enable", created_by=self.user)
        driver = Mock()
        driver.enable_https.return_value = 443
        with patch("switches.https_setup.certificate", return_value={key: self.pending[key] for key in ("fingerprint", "port", "tls")}):
            output = execute_https(self.switch, driver, job)
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.management_protocol, "http")
        self.assertEqual(self.switch.https_pending, self.pending)
        self.assertIn("No credentials", output)

    def test_legacy_tls_failure_keeps_transport_http_and_has_no_pending_trust(self):
        job = Job.objects.create(switch=self.switch, action="https_enable", created_by=self.user)
        driver = Mock()
        driver.enable_https.return_value = 443
        with patch("switches.https_setup.certificate", side_effect=DriverError("TLS 1.2 required")):
            with self.assertRaises(DriverError):
                execute_https(self.switch, driver, job)
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.management_protocol, "http")
        self.assertEqual(self.switch.https_pending, {})

    def test_forged_or_stale_certificate_approval_rejected(self):
        Switch.objects.filter(pk=self.switch.pk).update(https_pending=self.pending)
        self.switch.refresh_from_db()
        response = self.client.post(reverse("switch-https", args=[self.switch.pk]), {
            "action": "https_use", "confirm": "yes", "fingerprint": "b" * 64,
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Job.objects.count(), 0)

    def test_certificate_change_after_approval_sends_no_credentials(self):
        Switch.objects.filter(pk=self.switch.pk).update(https_pending=self.pending)
        self.switch.refresh_from_db()
        job = Job.objects.create(switch=self.switch, action="https_use", payload={"fingerprint": "a" * 64}, created_by=self.user)
        with patch("switches.https_setup.certificate", return_value={**self.pending, "fingerprint": "b" * 64}), patch(
            "switches.https_setup.get_driver"
        ) as factory:
            with self.assertRaises(DriverError):
                execute_https(self.switch, Mock(), job)
        factory.assert_not_called()
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.management_protocol, "http")
        self.assertEqual(self.switch.https_pending, {})

    def test_approval_authenticates_pinned_https_before_saving_protocol(self):
        Switch.objects.filter(pk=self.switch.pk).update(https_pending=self.pending)
        self.switch.refresh_from_db()
        job = Job.objects.create(switch=self.switch, action="https_use", payload={"fingerprint": "a" * 64}, created_by=self.user)
        secure = MagicMock()
        secure.__enter__.return_value = secure
        with patch("switches.https_setup.certificate", return_value=self.pending), patch(
            "switches.https_setup.get_driver", return_value=secure
        ) as factory, patch("switches.tasks.synchronize"):
            output = execute_https(self.switch, Mock(), job)
        self.assertIn("verified", output)
        self.assertEqual(factory.call_args.args[0].management_protocol, "https")
        self.assertEqual(factory.call_args.args[0].tls_fingerprint, "a" * 64)
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.management_protocol, "https")
        self.assertEqual(self.switch.port, 443)
        self.assertEqual(self.switch.tls_fingerprint, "a" * 64)
        self.assertEqual(self.switch.https_pending, {})

    def test_failed_https_login_never_changes_app_protocol(self):
        Switch.objects.filter(pk=self.switch.pk).update(https_pending=self.pending)
        self.switch.refresh_from_db()
        job = Job.objects.create(switch=self.switch, action="https_use", payload={"fingerprint": "a" * 64}, created_by=self.user)
        secure = MagicMock()
        secure.__enter__.side_effect = DriverError("Login failed")
        with patch("switches.https_setup.certificate", return_value=self.pending), patch(
            "switches.https_setup.get_driver", return_value=secure
        ):
            with self.assertRaises(DriverError):
                execute_https(self.switch, Mock(), job)
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.management_protocol, "http")

    def test_pin_not_cleared_when_editing_unrelated_inventory_fields(self):
        self.switch.management_protocol = "https"
        self.switch.port = 443
        self.switch.tls_fingerprint = "a" * 64
        self.switch.save()
        form = SwitchForm({"name": "Renamed", "address": self.switch.address, "port": 443,
                           "driver": self.switch.driver, "credential": self.credential.pk}, instance=self.switch)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().tls_fingerprint, "a" * 64)
