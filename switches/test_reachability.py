from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.utils import timezone

from .live import snapshot
from .models import Job, Switch, SwitchAccess
from .tasks import check_switch_online, check_switches_online


class ReachabilityTests(TestCase):
    def setUp(self):
        self.switch = Switch.objects.create(name="Edge", address="192.0.2.1", port=443, monitoring_enabled=False)

    def test_checks_every_active_switch_without_sync_or_job_lock(self):
        inactive = Switch.objects.create(name="Inactive", address="192.0.2.2", active=False)
        self.switch.operation_token = "00000000-0000-0000-0000-000000000001"
        self.switch.save()
        with patch("switches.tasks.check_switch_online.apply_async") as publish:
            check_switches_online()
        publish.assert_called_once_with(args=[self.switch.pk], expires=120)
        self.assertNotEqual(self.switch.pk, inactive.pk)
        self.assertFalse(Job.objects.exists())

    def test_success_uses_configured_management_port_and_pushes_result(self):
        with patch("switches.tasks.socket.create_connection") as connect, patch("switches.tasks.notify_switch") as notify:
            check_switch_online(self.switch.pk)
        connect.assert_called_once_with(("192.0.2.1", 443), timeout=3)
        notify.assert_called_once_with(self.switch.pk)
        self.switch.refresh_from_db()
        self.assertTrue(self.switch.reachable)
        self.assertIsNotNone(self.switch.last_checked)
        self.assertEqual(self.switch.reachability_status, "Online")
        self.assertEqual(self.switch.status, "unknown")
        self.assertIsNone(self.switch.last_synced)

    def test_refused_or_timed_out_connection_persists_offline(self):
        for error in (ConnectionRefusedError(), TimeoutError()):
            with patch("switches.tasks.socket.create_connection", side_effect=error):
                check_switch_online(self.switch.pk)
            self.switch.refresh_from_db()
            self.assertFalse(self.switch.reachable)
            self.assertEqual(self.switch.reachability_status, "Offline")

    def test_stale_endpoint_result_and_deactivated_switch_are_ignored(self):
        def changed(*args, **kwargs):
            Switch.objects.filter(pk=self.switch.pk).update(port=80)
            raise ConnectionRefusedError()
        with patch("switches.tasks.socket.create_connection", side_effect=changed), patch("switches.tasks.notify_switch") as notify:
            check_switch_online(self.switch.pk)
        self.switch.refresh_from_db()
        self.assertIsNone(self.switch.last_checked)
        notify.assert_not_called()
        self.switch.active = False
        self.switch.save()
        with patch("switches.tasks.socket.create_connection") as connect:
            check_switch_online(self.switch.pk)
            check_switch_online(9999)
        connect.assert_not_called()

    def test_unknown_inactive_and_overdue_states(self):
        self.assertEqual(self.switch.reachability_status, "Not checked")
        self.switch.reachable = True
        self.switch.last_checked = timezone.now() - timedelta(seconds=301)
        self.assertEqual(self.switch.reachability_status, "Check overdue")
        self.switch.active = False
        self.assertEqual(self.switch.reachability_status, "Inactive")

    def test_result_is_permission_filtered_in_both_live_views(self):
        user = get_user_model().objects.create_user("viewer")
        SwitchAccess.objects.create(user=user, switch=self.switch)
        hidden = Switch.objects.create(name="Hidden", address="192.0.2.99", reachable=True, last_checked=timezone.now())
        Switch.objects.filter(pk=self.switch.pk).update(reachable=False, last_checked=timezone.now())
        request = RequestFactory().get("/")
        request.user = user
        for topic, pk in (("fleet", None), ("switch", self.switch.pk)):
            html = snapshot(request, topic, pk)["html"]
            self.assertIn("Offline", html)
            self.assertNotIn(hidden.name, html)


class ScheduleAndTimeoutTests(SimpleTestCase):
    def test_online_checks_run_every_120_seconds_and_redis_read_exceeds_blocking_timeout(self):
        from tux_switch.settings import CELERY_BEAT_SCHEDULE, CHANNEL_LAYERS
        from channels_redis.core import RedisChannelLayer
        schedule = CELERY_BEAT_SCHEDULE["check-switch-reachability"]
        self.assertEqual(schedule["task"], "switches.tasks.check_switches_online")
        self.assertEqual(schedule["schedule"], 120)
        host = CHANNEL_LAYERS["default"]["CONFIG"]["hosts"][0]
        self.assertGreater(host["socket_timeout"], RedisChannelLayer.brpop_timeout)
        self.assertEqual(host["socket_connect_timeout"], 5)
