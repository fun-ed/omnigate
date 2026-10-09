from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from xml.etree import ElementTree

import load_test
import render_charts


class ToolTests(unittest.TestCase):
    def test_remote_and_credential_guards(self):
        load_test.validate_target("http://127.0.0.1:8080/", False)
        load_test.validate_target("https://[::1]:8443/", False)
        for value in ("http://example.com/", "http://user:password@127.0.0.1/", "http://127.0.0.1/?token=value", "ftp://127.0.0.1/", "http://127.0.0.1:0/"):
            with self.assertRaises(ValueError):
                load_test.validate_target(value, False)

    def test_percentiles(self):
        self.assertIsNone(load_test.percentile([], 99))
        self.assertEqual(load_test.percentile([4, 1, 3, 2], 50), 2)
        self.assertEqual(load_test.percentile([4, 1, 3, 2], 99), 4)

    def test_real_local_load_and_svg(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
        thread.start()
        try:
            target = load_test.validate_target(f"http://127.0.0.1:{server.server_port}/", False)
            row = load_test.run_stage(target, 2, 0.2, 1, None, None)
            self.assertGreater(row["successful"], 0)
            self.assertEqual(row["error_count"], 0)
            self.assertEqual(row["completed"], row["successful"])
            self.assertGreaterEqual(row["successful_latency_ms"]["p99"], row["successful_latency_ms"]["p50"])
            report = {"stages": [row], "protocol": "HTTP/1.1", "environment": {"system": "test", "machine": "test"}, "idle_server_rss_mib": None}
            charts = render_charts.render(report, "BenchmarkDefaultHTML-1 100 400.0 ns/op 288 B/op 4 allocs/op\n")
            self.assertEqual(len(charts), 4)
            for svg in charts.values():
                root = ElementTree.fromstring(svg)
                self.assertTrue(root.tag.endswith("svg"))
                self.assertIsNotNone(root.find("{http://www.w3.org/2000/svg}title"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_svg_escape(self):
        svg = render_charts.line_chart("title <script>", "A & B", [1], [("series", [1.0])], "MiB")
        self.assertNotIn("<script>", svg)
        ElementTree.fromstring(svg)


if __name__ == "__main__":
    unittest.main()
