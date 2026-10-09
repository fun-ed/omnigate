from __future__ import annotations

import base64
import hashlib
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import tunnel_acceptance as acceptance


class TunnelAcceptanceTests(unittest.TestCase):
    def test_parser_defaults_and_command_usage(self):
        args = acceptance.build_parser().parse_args(
            ["probe", "--marker", "fixture-marker", "--output", "report.json"]
        )
        self.assertEqual(args.origin, "http://127.0.0.1:8081")
        self.assertEqual(args.public, "https://omni.curl.rs")
        self.assertEqual(args.user, "admin")
        self.assertEqual(args.password_env, "WEB_HTTP_AUTH_PASSWORD")
        self.assertIsNone(args.origin_external_scheme)
        args = acceptance.build_parser().parse_args(
            [
                "probe",
                "--marker",
                "fixture-marker",
                "--output",
                "report.json",
                "--origin-external-scheme",
                "https",
            ]
        )
        self.assertEqual(args.origin_external_scheme, "https")
        fixture = acceptance.build_parser().parse_args(["fixture", "--marker", "fixture-marker"])
        self.assertEqual((fixture.host, fixture.port), ("127.0.0.1", 0))

    def test_url_validation(self):
        origin = acceptance.validate_origin("http://[::1]:6767/")
        self.assertEqual((origin.host, origin.port, origin.scheme), ("::1", 6767, "http"))
        self.assertEqual(acceptance.validate_origin("http://127.0.0.1").port, 80)
        for unsafe in (
            "https://127.0.0.1:6767",
            "http://example.com:6767",
            "http://127.0.0.1:0",
            "http://user:password@127.0.0.1:6767",
            "http://127.0.0.1:6767/path",
            "http://127.0.0.1:6767/?token=value",
            "http://127.0.0.1:6767/#fragment",
            "ftp://127.0.0.1:6767",
        ):
            with self.subTest(url=unsafe), self.assertRaises(ValueError):
                acceptance.validate_origin(unsafe)

        public = acceptance.validate_public("https://omni.curl.rs")
        self.assertEqual((public.host, public.port, public.scheme), ("omni.curl.rs", 443, "https"))
        for unsafe in (
            "http://omni.curl.rs",
            "https://admin:secret@omni.curl.rs",
            "https://omni.curl.rs/path",
            "https://omni.curl.rs/?token=value",
            "https://omni.curl.rs/#fragment",
            "https://omni.curl.rs:0",
        ):
            with self.subTest(url=unsafe), self.assertRaises(ValueError):
                acceptance.validate_public(unsafe)

    def test_external_scheme_override_is_loopback_http_only(self):
        loopback = acceptance.validate_origin("http://127.0.0.1:8081")
        invalid_overrides = (
            (acceptance.Endpoint("https", "127.0.0.1", 443), "https"),
            (acceptance.Endpoint("http", "203.0.113.1", 8081), "https"),
            (acceptance.Endpoint("http", "127.0.0.1", 0), "https"),
            (loopback, "https\r\nX-Admin: yes"),
            (loopback, "ftp"),
        )
        for endpoint, scheme in invalid_overrides:
            with self.subTest(endpoint=endpoint, scheme=scheme), self.assertRaises(ValueError):
                acceptance.http_request(endpoint, "/", external_scheme=scheme)

        with self.assertRaises(ValueError):
            acceptance.websocket_echo(acceptance.Endpoint("https", "127.0.0.1", 443), external_scheme="https")
        with self.assertRaises(ValueError):
            acceptance.run_endpoint_checks(
                acceptance.validate_public("https://example.com"),
                "public",
                "marker",
                "admin",
                "password",
                external_scheme="https",
            )

    def test_probe_keeps_external_scheme_off_public_checks(self):
        with patch.object(acceptance, "run_endpoint_checks", return_value=[]) as run_checks:
            acceptance.run_probe(
                "http://127.0.0.1:8081",
                "https://example.com",
                "marker",
                "admin",
                "password",
                external_scheme="https",
            )
        self.assertEqual(run_checks.call_args_list[0].kwargs["external_scheme"], "https")
        self.assertNotIn("external_scheme", run_checks.call_args_list[1].kwargs)


    def test_secret_redaction(self):
        message = "Authorization: Basic c2VjcmV0; password=secret"
        cleaned = acceptance.sanitize_error(message, ("secret", "c2VjcmV0"))
        self.assertNotIn("secret", cleaned)
        self.assertNotIn("c2VjcmV0", cleaned)
        self.assertIn("[REDACTED]", cleaned)

    def test_frame_encoding_and_limits(self):
        masked = acceptance.encode_ws_frame(1, b"hello", masked=True, mask_key=b"abcd")
        frame = acceptance.read_ws_frame(io.BytesIO(masked), require_mask=True)
        self.assertEqual((frame.opcode, frame.payload, frame.fin, frame.masked), (1, b"hello", True, True))

        unmasked = acceptance.encode_ws_frame(1, b"echo", masked=False)
        frame = acceptance.read_ws_frame(io.BytesIO(unmasked), require_mask=False)
        self.assertEqual((frame.opcode, frame.payload), (1, b"echo"))
        with self.assertRaises(acceptance.WebSocketProtocolError):
            acceptance.read_ws_frame(io.BytesIO(unmasked), require_mask=True)
        with self.assertRaises(ValueError):
            acceptance.encode_ws_frame(1, b"x" * (acceptance.MAX_FRAME_BYTES + 1), masked=True)

    def test_fixture_http_websocket_and_authorization_rejection(self):
        marker = "local-fixture-marker"
        server = acceptance.create_fixture_server(marker)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        endpoint = acceptance.validate_origin(f"http://127.0.0.1:{server.server_port}")
        secret = "never-echo-this-password"
        authorization = acceptance.basic_authorization("admin", secret)
        try:
            status, _ = acceptance.http_request(endpoint, "/healthz", timeout=1)
            self.assertEqual(status, 200)
            status, body = acceptance.http_request(endpoint, "/nested/app", timeout=1)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"marker": marker})
            status, body = acceptance.http_request(endpoint, "/", authorization=authorization, timeout=1)
            self.assertEqual(status, 401)
            self.assertNotIn(secret.encode(), body)
            with self.assertRaises(acceptance.WebSocketProtocolError) as caught:
                acceptance.websocket_echo(endpoint, authorization=authorization, timeout=1)
            self.assertNotIn(secret, str(caught.exception))
            acceptance.websocket_echo(endpoint, nonce="local-nonce", ping_payload=b"ping", timeout=1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_local_origin_http_and_websocket_acceptance_checks(self):
        marker = "expected-marker"
        password = "local-only-password"
        user = "admin"
        authorization = acceptance.basic_authorization(user, password)
        websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        observed_external_schemes = []

        class GateHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format, *args):
                return

            def _body(self, status, document):
                body = json.dumps(document).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                observed_external_schemes.append(self.headers.get("X-Forwarded-Proto"))
                if self.path == "/socket":
                    if self.headers.get("Authorization") != authorization:
                        self._body(401, {"error": "unauthorized"})
                        return
                    key = self.headers.get("Sec-WebSocket-Key", "")
                    accept = base64.b64encode(hashlib.sha1((key + websocket_guid).encode()).digest()).decode()
                    self.send_response_only(101)
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    self.send_header("Sec-WebSocket-Accept", accept)
                    self.end_headers()
                    self.wfile.flush()
                    self.connection.settimeout(2)
                    try:
                        while True:
                            frame = acceptance.read_ws_frame(self.rfile, require_mask=True)
                            if frame.opcode == 9:
                                self.wfile.write(acceptance.encode_ws_frame(10, frame.payload, masked=False))
                                self.wfile.flush()
                            elif frame.opcode == 8:
                                self.wfile.write(acceptance.encode_ws_frame(8, frame.payload, masked=False))
                                self.wfile.flush()
                                return
                            else:
                                self.wfile.write(acceptance.encode_ws_frame(frame.opcode, frame.payload, masked=False))
                                self.wfile.flush()
                    except (OSError, acceptance.WebSocketProtocolError):
                        return
                elif self.path in ("/healthz", "/readyz"):
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif self.headers.get("Authorization") != authorization:
                    self._body(401, {"error": "unauthorized"})
                else:
                    self._body(200, {"marker": marker})

        server = ThreadingHTTPServer(("127.0.0.1", 0), GateHandler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        endpoint = acceptance.validate_origin(f"http://127.0.0.1:{server.server_port}")
        try:
            default_checks = acceptance.run_endpoint_checks(endpoint, "origin", marker, user, password, timeout=1)
            checks = acceptance.run_endpoint_checks(
                endpoint, "origin", marker, user, password, timeout=1, external_scheme="https"
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(all(check["status"] == "passed" for check in default_checks), default_checks)
        self.assertEqual(observed_external_schemes.count(None), 5)
        self.assertEqual(observed_external_schemes.count("https"), 5)
        self.assertEqual(len(observed_external_schemes), 10)
        self.assertEqual(
            [check["name"] for check in checks],
            [
                "origin_healthz",
                "origin_readyz",
                "origin_unauthenticated_401",
                "origin_authenticated_marker",
                "origin_websocket_echo",
            ],
        )
        self.assertTrue(all(check["status"] == "passed" for check in checks), checks)
        self.assertTrue(all("duration_ms" in check for check in checks))


if __name__ == "__main__":
    unittest.main()
