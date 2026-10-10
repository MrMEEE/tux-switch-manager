from unittest.mock import MagicMock

from django.test import SimpleTestCase

from .discovery import classify_candidate, read_response


class ServiceFingerprintTests(SimpleTestCase):
    def test_open_ports_and_generic_server_banners_are_excluded(self):
        for ports, banners in [
            ([22], {22: "SSH-2.0-OpenSSH"}),
            ([22, 80, 443], {80: "HTTP/1.0 200 OK\r\nServer: nginx"}),
            ([830], {}),
            ([830], {830: "HTTP/1.0 200 OK"}),
        ]:
            self.assertIsNone(classify_candidate("192.0.2.1", ports, banners))

    def test_network_vendor_fingerprints(self):
        for banner, vendor in [
            ("SSH-2.0-JUNOS", "Juniper"), ("Cisco Catalyst", "Cisco"),
            ("HP Switch", "HP / HPE / Aruba"), ("SMC Networks", "SMC"),
            ("Aruba", "HP / HPE / Aruba"), ("NETGEAR", "NETGEAR"),
            ("ExtremeXOS", "Extreme Networks"), ("Dell PowerConnect", "Dell"),
            ("Arista", "Arista"),
        ]:
            with self.subTest(banner=banner):
                candidate = classify_candidate("192.0.2.1", [443], {443: banner})
                self.assertEqual(candidate["vendor"], vendor)
                self.assertEqual(candidate["confidence"], "vendor service fingerprint")

    def test_netconf_requires_ssh_response_not_just_open_port(self):
        candidate = classify_candidate("192.0.2.1", [830], {830: "SSH-2.0-OpenSSH\n"})
        self.assertEqual(candidate["confidence"], "possible NETCONF device")

    def test_http_fingerprint_can_arrive_in_separate_packet(self):
        connection = MagicMock()
        connection.recv.side_effect = [b"HTTP/1.0 200 OK\r\n\r\n", b"<title>Juniper J-Web</title>", b""]
        banner = read_response(connection, http=True)
        self.assertIn("Juniper", banner)

    def test_response_size_is_bounded(self):
        connection = MagicMock()
        connection.recv.return_value = b"x" * 4096
        self.assertEqual(len(read_response(connection, http=True)), 4096)
        connection.recv.assert_called_once_with(4096)

    def test_partial_response_survives_timeout(self):
        connection = MagicMock()
        connection.recv.side_effect = [b"HTTP/1.0 200 OK\r\nServer: Aruba", TimeoutError()]
        self.assertIn("Aruba", read_response(connection, http=True))
