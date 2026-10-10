from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from .discovery import probe_candidate
from .oui import lookup_oui, neighbor_mac


class OUIFallbackTests(SimpleTestCase):
    def test_local_database_and_invalid_or_randomized_macs(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "oui.csv"
            path.write_text(
                'Registry,Assignment,Organization Name\nMA-L,001122,"Juniper Networks, Inc."\n',
                encoding="utf-8",
            )
            with override_settings(DISCOVERY_OUI_FILE=str(path)):
                self.assertEqual(lookup_oui("00:11:22:33:44:55"), "Juniper Networks, Inc.")
                for mac in ["02:11:22:33:44:55", "01:11:22:33:44:55", "invalid", "00:99:88:33:44:55"]:
                    self.assertIsNone(lookup_oui(mac))

    def test_missing_database_warns(self):
        with override_settings(DISCOVERY_OUI_FILE="/nonexistent/oui.csv"):
            with self.assertLogs("switches.oui", level="WARNING"):
                self.assertIsNone(lookup_oui("00:11:22:33:44:55"))

    def test_gateway_mac_is_never_used(self):
        with patch("switches.oui.ip_json", return_value=[{"dev": "eth0", "gateway": "192.0.2.1"}]) as command:
            self.assertIsNone(neighbor_mac("198.51.100.2"))
        self.assertEqual(command.call_count, 1)

    def test_direct_neighbor_mac_is_used_for_ipv4_and_ipv6(self):
        for address in ["192.0.2.2", "2001:db8::2"]:
            with patch("switches.oui.ip_json", side_effect=[
                [{"dev": "eth0"}],
                [{"dst": address, "lladdr": "00:11:22:33:44:55", "state": ["STALE"]}],
            ]):
                self.assertEqual(neighbor_mac(address), "00:11:22:33:44:55")

    def test_vendor_fingerprint_takes_precedence_and_skips_oui(self):
        with patch("switches.discovery.socket.create_connection", side_effect=OSError), \
                patch("switches.discovery.classify_candidate", return_value={
                    "vendor": "Cisco", "confidence": "vendor service fingerprint",
                }) as classify, \
                patch("switches.discovery.neighbor_mac") as neighbor:
            candidate = probe_candidate("192.0.2.2")
        self.assertEqual(candidate["vendor"], "Cisco")
        classify.assert_called_once()
        neighbor.assert_not_called()

    def test_known_vendor_fallback_without_management_services(self):
        with patch("switches.discovery.socket.create_connection", side_effect=OSError), \
                patch("switches.discovery.neighbor_mac", return_value="00:11:22:33:44:55"), \
                patch("switches.discovery.lookup_oui", return_value="SMC Networks"):
            candidate = probe_candidate("192.0.2.2")
        self.assertEqual(candidate["vendor"], "SMC")
        self.assertEqual(candidate["mac"], "00:11:22:33:44:55")
        self.assertEqual(candidate["open_ports"], [])
        self.assertIn("fallback", candidate["confidence"])
        self.assertIn("SMC Networks", candidate["evidence"][-1])

    def test_unknown_and_non_network_manufacturers_are_excluded(self):
        for organization in [None, "Intel Corporation"]:
            with patch("switches.discovery.socket.create_connection", side_effect=OSError), \
                    patch("switches.discovery.neighbor_mac", return_value="00:11:22:33:44:55"), \
                    patch("switches.discovery.lookup_oui", return_value=organization):
                self.assertIsNone(probe_candidate("192.0.2.2"))

    def test_missing_mac_preserves_possible_netconf_detection(self):
        possible = {"vendor": "Unknown", "confidence": "possible NETCONF device"}
        with patch("switches.discovery.socket.create_connection", side_effect=OSError), \
                patch("switches.discovery.classify_candidate", return_value=possible), \
                patch("switches.discovery.neighbor_mac", return_value=None):
            self.assertEqual(probe_candidate("192.0.2.2"), possible)
