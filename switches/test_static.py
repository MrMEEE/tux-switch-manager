from tempfile import TemporaryDirectory

from asgiref.sync import async_to_sync
from channels.testing import HttpCommunicator
from django.core.asgi import get_asgi_application
from django.core.management import call_command
from django.test import SimpleTestCase, override_settings


class StaticAssetTests(SimpleTestCase):
    async def asset_response(self, application, filename):
        communicator = HttpCommunicator(
            application, "GET", f"/static/switches/{filename}",
        )
        await communicator.send_input({
            "type": "http.request", "body": b"", "more_body": False,
        })
        response = await communicator.receive_output()
        body = b""
        while True:
            chunk = await communicator.receive_output()
            self.assertEqual(chunk["type"], "http.response.body")
            body += chunk.get("body", b"")
            if not chunk.get("more_body", False):
                break
        await communicator.wait()
        return response, body

    def test_collected_theme_assets_are_served_by_asgi_without_debug(self):
        with TemporaryDirectory() as static_root:
            with override_settings(
                STATIC_ROOT=static_root, DEBUG=False, SECURE_SSL_REDIRECT=False,
            ):
                call_command("collectstatic", interactive=False, verbosity=0)
                application = get_asgi_application()
                for filename, content_type, marker in [
                    ("app.css", "text/css", b".sidebar"),
                    ("app.js", "text/javascript", b"menu-toggle"),
                ]:
                    with self.subTest(filename=filename):
                        response, body = async_to_sync(self.asset_response)(
                            application, filename,
                        )
                        self.assertEqual(response["status"], 200)
                        headers = {
                            name.lower(): value for name, value in response["headers"]
                        }
                        self.assertIn(content_type.encode(), headers[b"content-type"])
                        self.assertIn(marker, body)
