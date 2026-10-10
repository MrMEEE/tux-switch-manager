import base64
import hashlib
from unittest.mock import MagicMock, patch

import paramiko
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core import signing
from django.test import Client, TestCase
from django.urls import reverse

from .drivers.base import DriverError, UntrustedHostKey
from .drivers.registry import get_driver
from .enrollment import TRUST_SALT
from .models import Credential, DiscoveryRun, Switch, SwitchAccess, TrustedHostKey


class CandidateEnrollmentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user("scanner")
        cls.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        cls.credential = Credential.objects.create(name="Lab", username="netops", password="private-password")
        cls.key = paramiko.RSAKey.generate(1024)

    def setUp(self):
        self.client.force_login(self.user)
        self.run = DiscoveryRun.objects.create(
            network="192.0.2.0/30", driver="juniper_ex", created_by=self.user, status="success",
            results=[{"address": "192.0.2.1", "status": "candidate"}],
        )
        self.url = reverse("candidate-confirm", args=[self.run.pk])
        self.data = {"address": "192.0.2.1", "credential": self.credential.pk, "port": 830}
        self.driver = MagicMock()
        self.driver.get_facts.return_value = {"hostname": "edge", "model": "EX3300-24P"}
        self.driver.get_config.return_value = "system { host-name edge; }"
        self.factory = patch("switches.enrollment.get_driver", return_value=self.driver)
        self.factory.start()
        self.addCleanup(self.factory.stop)

    def challenge(self):
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(self.key.asbytes()).digest()).decode().rstrip("=")
        self.driver.__enter__.side_effect = UntrustedHostKey(self.key.get_name(), self.key.get_base64(), fingerprint)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "trust_required")
        self.assertEqual(response.json()["fingerprint"], fingerprint)
        self.assertFalse(Switch.objects.exists())
        self.assertFalse(TrustedHostKey.objects.exists())
        self.driver.get_facts.assert_not_called()
        self.driver.__enter__.side_effect = None
        return response.json()["trust_token"]

    def test_trust_and_add_pins_exact_key_and_updates_original_candidate(self):
        token = self.challenge()
        response = self.client.post(self.url, {**self.data, "trust_token": token})
        self.assertEqual(response.json()["status"], "added")
        self.assertEqual(self.driver.trusted_host_key, (self.key.get_name(), self.key.get_base64()))
        switch = Switch.objects.get()
        self.assertEqual(switch.credential, self.credential)
        self.assertEqual(switch.revisions.get().config, "system { host-name edge; }")
        self.assertTrue(SwitchAccess.objects.filter(user=self.user, switch=switch, role="admin").exists())
        self.assertEqual(DiscoveryRun.objects.count(), 1)
        self.run.refresh_from_db()
        self.assertEqual(self.run.results[0]["switch_id"], switch.pk)
        self.assertEqual(self.run.results[0]["status"], "found")
        key = TrustedHostKey.objects.get()
        self.assertEqual(key.trusted_by_id, self.user.pk)
        self.factory.stop()
        driver = get_driver(switch)
        self.assertEqual(driver.trusted_host_key, (self.key.get_name(), self.key.get_base64()))
        self.factory.start()
        self.assertEqual(self.client.post(self.url, {**self.data, "trust_token": token}).status_code, 403)

    def test_cancel_keeps_candidate_without_persisting_key(self):
        self.challenge()
        self.run.refresh_from_db()
        self.assertEqual(self.run.results[0]["status"], "candidate")
        self.assertEqual(DiscoveryRun.objects.count(), 1)

    def test_bad_credentials_or_changed_key_does_not_save_trust(self):
        token = self.challenge()
        for message in ["SSH authentication failed.", "SSH host key does not match the trusted key."]:
            with self.subTest(message=message):
                self.driver.__enter__.side_effect = DriverError(message)
                response = self.client.post(self.url, {**self.data, "trust_token": token})
                self.assertEqual(response.status_code, 400)
                self.assertIn(message, response.json()["message"])
                self.assertFalse(TrustedHostKey.objects.exists())
                self.assertFalse(Switch.objects.exists())

    def test_signed_approval_is_bound_to_user_session_candidate_credential_and_port(self):
        token = self.challenge()
        original = signing.loads(token, salt=TRUST_SALT)
        for field in ["run", "address", "credential", "port", "user", "session"]:
            with self.subTest(field=field):
                altered = signing.dumps({**original, field: "wrong"}, salt=TRUST_SALT)
                response = self.client.post(self.url, {**self.data, "trust_token": altered})
                self.assertEqual(response.status_code, 400)
        response = self.client.post(self.url, {**self.data, "trust_token": token + "tampered"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Switch.objects.exists())
        self.assertFalse(TrustedHostKey.objects.exists())

    def test_approval_expires(self):
        token = self.challenge()
        with patch("django.core.signing.time.time", return_value=99999999999):
            response = self.client.post(self.url, {**self.data, "trust_token": token})
        self.assertEqual(response.status_code, 400)
        self.assertIn("expired", response.json()["message"])

    def test_revoked_access_or_logout_during_verification_cannot_enroll(self):
        for revoke in [
            lambda: self.user.user_permissions.clear(),
            lambda: self.client.session.flush(),
        ]:
            self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
            self.client.force_login(self.user)
            self.driver.get_config.side_effect = lambda: (revoke(), "config")[1]
            self.assertEqual(self.client.post(self.url, self.data).status_code, 403)
            self.assertFalse(Switch.objects.exists())

    def test_existing_switch_is_never_overwritten_or_granted(self):
        existing = Switch.objects.create(name="Existing", address="192.0.2.1", port=22)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 400)
        existing.refresh_from_db()
        self.assertIsNone(existing.credential_id)
        self.assertFalse(existing.access.exists())

    def test_credential_changed_during_check_requires_retry(self):
        def change_credential():
            Credential.objects.filter(pk=self.credential.pk).update(username="different-login")
            return "config"

        self.driver.get_config.side_effect = change_credential
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 400)
        self.assertIn("changed during verification", response.json()["message"])
        self.assertFalse(Switch.objects.exists())

    def test_existing_trust_conflict_cannot_be_replaced(self):
        token = self.challenge()
        other_key = paramiko.RSAKey.generate(1024)
        TrustedHostKey.objects.create(
            address="192.0.2.1", port=830, algorithm=other_key.get_name(), public_key=other_key.get_base64(),
        )
        response = self.client.post(self.url, {**self.data, "trust_token": token})
        self.assertEqual(response.status_code, 400)
        self.assertIn("conflicts", response.json()["message"])
        self.assertFalse(Switch.objects.exists())
        self.assertEqual(TrustedHostKey.objects.get().public_key, other_key.get_base64())

    def test_unexpected_errors_are_sanitized(self):
        self.driver.get_config.side_effect = RuntimeError("private-password")
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("private-password", response.content.decode())
        self.assertFalse(Switch.objects.exists())

    def test_csrf_and_owner_permission_are_required(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(csrf_client.post(self.url, self.data).status_code, 403)
        self.user.user_permissions.clear()
        self.assertEqual(self.client.post(self.url, self.data).status_code, 403)
