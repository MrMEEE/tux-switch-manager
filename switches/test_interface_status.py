from django.test import SimpleTestCase

from .interface_status import port_link_states


class InterfaceStatusTests(SimpleTestCase):
    def test_junos_uses_operational_not_administrative_state(self):
        self.assertEqual(port_link_states("juniper_ex", {"interfaces": """
Interface               Admin Link Proto
ge-0/0/0                up    down
ge-0/0/0.0              up    up   eth-switch
xe-0/1/0                up    up
ge-0/0/1                down  down
"""}), {"ge-0/0/0": "down", "xe-0/1/0": "up", "ge-0/0/1": "down"})

    def test_web_profiles_use_observed_link_not_configured_speed(self):
        for profile in ("netgear_gs108tv2", "netgear_plus"):
            with self.subTest(profile=profile):
                self.assertEqual(port_link_states(profile, {"interfaces": [
                    {"name": "1", "link": "Up", "physical_status": "Auto"},
                    {"name": "2", "link": "Link Down", "physical_status": "1000 Mbps"},
                    {"name": "3", "link": "Link Up"},
                    {"name": "4", "link": "unrecognized"},
                ]}), {"1": "up", "2": "down", "3": "up", "4": "unknown"})

    def test_comware_brief_names_and_administratively_down_links(self):
        self.assertEqual(port_link_states("hp_comware", {"interfaces": """
Interface Link Speed Duplex Type PVID Description
GE1/0/1 UP 1G(a) F(a) A 1 Desk
GigabitEthernet1/0/2 DOWN auto A 1
GE1/0/3 ADM auto A 1
XGE1/0/4 UP 10G F T 1
"""}), {"GigabitEthernet1/0/1": "up", "GigabitEthernet1/0/2": "down",
        "GigabitEthernet1/0/3": "down", "Ten-GigabitEthernet1/0/4": "up"})

    def test_missing_failed_and_unrecognized_telemetry_do_not_claim_links_are_down(self):
        for data in ({}, {"interfaces": "not supported"}, {"interfaces": None},
                     {"interfaces": "ge-0/0/0 up up", "errors": {"interfaces": "Collection failed"}}):
            self.assertEqual(port_link_states("juniper_ex", data), {})
