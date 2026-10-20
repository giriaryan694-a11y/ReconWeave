"""Regression tests for ReconWeave's URL handling, scope checks, and parsing.

Run with: python -m unittest -v test_reconweave.py
These tests use only Python's standard library and a local HTTP server.
"""

import queue
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main as reconweave


class FakeApp:
    def __init__(self):
        self.ui_queue = queue.Queue()
        self.wordlists = {}
        self.subdomain_wordlists = {}
        self.osint = reconweave.OSINTEngine(self)


class LocalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        content_type = "text/plain; charset=utf-8"
        if self.path == "/large":
            body = b"abcdef"
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://outside.invalid/path")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif self.path == "/robots.txt":
            content_type = "text/plain; charset=utf-8"
            body = (f"User-agent: *\nDisallow: /admin\nSitemap: http://127.0.0.1:{self.server.server_port}/sitemap.xml\n").encode()
        elif self.path == "/sitemap.xml":
            content_type = "application/xml; charset=utf-8"
            body = (f'<urlset><url><loc>http://127.0.0.1:{self.server.server_port}/login</loc></url></urlset>').encode()
        elif self.path == "/":
            content_type = "text/html; charset=utf-8"
            body = ("<html><body><a href='/login'>login</a><a href='/config'>config</a>"
                    "<script src='/assets/app.js'></script>"
                    "<form action='/session' method='get'><input name='q'></form>"
                    "</body></html>").encode()
        elif self.path == "/assets/app.js":
            content_type = "application/javascript; charset=utf-8"
            body = b"fetch('/api/users');"
        elif self.path.startswith("/api/users"):
            content_type = "application/json; charset=utf-8"
            body = b'{"ok":true}'
        elif self.path == "/config":
            content_type = "text/plain; charset=utf-8"
            body = b'api_key = "ABCDEF1234567890"'
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class ReconWeaveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), LocalHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setUp(self):
        self.app = FakeApp()

    def test_target_normalization_and_rejections(self):
        self.assertEqual(
            reconweave.normalize_target_url("EXAMPLE.com/path?q=1#fragment"),
            "https://example.com/path?q=1",
        )
        self.assertEqual(
            reconweave.normalize_target_url("http://127.0.0.1:80/a"),
            "http://127.0.0.1/a",
        )
        with self.assertRaises(ValueError):
            reconweave.normalize_target_url("ftp://example.com")
        with self.assertRaises(ValueError):
            reconweave.normalize_target_url("https://user:pass@example.com")
        with self.assertRaises(ValueError):
            reconweave.normalize_target_url("https://example.com:99999")


    def test_brute_base_normalization_rejects_other_schemes_and_handles_hidden_dirs(self):
        self.assertEqual(
            reconweave.normalize_brute_base("HTTPS://Example.com/admin", "https://example.com/"),
            "https://example.com/admin/",
        )
        self.assertEqual(
            reconweave.normalize_brute_base("/.well-known", "https://example.com/"),
            "https://example.com/.well-known/",
        )
        self.assertEqual(reconweave.path_dirs("/.well-known"), ["/.well-known/"])
        with self.assertRaises(ValueError):
            reconweave.normalize_brute_base("ftp://example.com/admin", "https://example.com/")
        with self.assertRaises(ValueError):
            reconweave.normalize_brute_base("https://user:pass@example.com/admin", "https://example.com/")

    def test_http_request_returns_errors_for_invalid_proxy_and_headers(self):
        bad_proxy = reconweave.http_request(
            self.base_url + "/", "ReconWeave-test", proxy_url="socks5://127.0.0.1:9050"
        )
        self.assertEqual(bad_proxy["status"], 0)
        self.assertIn("Proxy must be", bad_proxy["error"])
        bad_agent = reconweave.http_request(self.base_url + "/", "valid\r\nX-Injected: yes")
        self.assertEqual(bad_agent["status"], 0)
        self.assertIn("User-Agent", bad_agent["error"])

    def test_secret_findings_are_deduplicated_per_url_not_globally(self):
        crawler = reconweave.Crawler(self.app)
        sample = 'const api_key = "ABCDEF1234567890";'
        crawler.scan_secrets("https://example.com/app.js", sample)
        crawler.scan_secrets("https://example.com/admin.js", sample)
        self.assertEqual(len(crawler.results["secrets"]), 2)
        self.assertEqual(
            {item["url"] for item in crawler.results["secrets"]},
            {"https://example.com/app.js", "https://example.com/admin.js"},
        )

    def test_domain_root_heuristics_and_suffix_guards(self):
        self.assertEqual(reconweave.registrable_root_domain("api.example.co.uk"), "example.co.uk")
        self.assertEqual(reconweave.registrable_root_domain("foo.bar.github.io"), "bar.github.io")
        self.assertTrue(reconweave.looks_like_public_suffix("co.uk"))
        self.assertTrue(reconweave.looks_like_public_suffix("github.io"))
        self.assertFalse(reconweave.looks_like_public_suffix("example.co.uk"))

    def test_http_request_bounds_body_but_reports_declared_length(self):
        result = reconweave.http_request(
            self.base_url + "/large", "ReconWeave-test", max_bytes=3, timeout=2
        )
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], b"abc")
        self.assertEqual(result["bytes_read"], 3)
        self.assertEqual(result["length"], 6)

    def test_redirect_policy_can_block_out_of_scope_destination(self):
        result = reconweave.http_request(
            self.base_url + "/redirect",
            "ReconWeave-test",
            timeout=2,
            follow_redirects=True,
            redirect_allowed=lambda url: "outside.invalid" not in url,
        )
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["location"], "https://outside.invalid/path")
        self.assertEqual(len(result["redirects"]), 1)

    def test_html_extractor_records_form_inputs_globally_and_locally(self):
        parser = reconweave.HTMLExtractor("https://example.com/login")
        parser.feed(
            '<form action="/session" method="post">'
            '<input name="username" type="text">'
            '<input name="password" type="password">'
            '</form><input name="outside">'
        )
        parser.close()
        self.assertEqual({item["name"] for item in parser.inputs}, {"username", "password", "outside"})
        self.assertEqual(
            {item["name"] for item in parser.forms[0]["inputs"]},
            {"username", "password"},
        )
        self.assertEqual(parser.forms[0]["action"], "https://example.com/session")


    def test_crawler_integration_finds_forms_scripts_and_api_calls(self):
        crawler = reconweave.Crawler(self.app)
        crawler.run(self.base_url + "/", {
            "max_depth": 2,
            "max_pages": 20,
            "delay": 0,
            "timeout": 2,
            "verify_tls": True,
            "include_subdomains": False,
            "fetch_js": True,
            "extract_js": True,
            "visit_discovered": True,
            "parse_robots": True,
            "parse_sitemap": True,
            "crawl_sitemap": True,
            "crawl_robots": False,
            "user_agent": "ReconWeave-test",
        })
        pages = {item["url"] for item in crawler.results["pages"]}
        self.assertIn(self.base_url + "/", pages)
        self.assertTrue(any(item["url"].endswith("/login") for item in crawler.results["pages"]))
        self.assertTrue(any(item["url"].endswith("/assets/app.js") for item in crawler.results["js_files"]))
        self.assertTrue(any(item["url"].endswith("/api/users") for item in crawler.results["api_endpoints"]))
        self.assertTrue(any(item["name"] == "q" for item in crawler.results["inputs"]))
        self.assertTrue(any(item["path"] == "/admin" for item in crawler.results["robots_paths"]))
        self.assertTrue(any(item["url"].endswith("/config") for item in crawler.results["secrets"]))

    def test_xhr_regex_extracts_second_argument_not_http_method(self):
        script = "xhr.open('GET', '/api/users'); fetch('/api/posts')"
        self.assertEqual(reconweave.XHR_OPEN_RE.findall(script), ["/api/users"])
        self.assertEqual(reconweave.JS_CALL_RE.findall(script), ["/api/posts"])

    def test_status_parser_discards_impossible_codes(self):
        self.assertEqual(reconweave.parse_status_list("200,999,-1,404;302"), {200, 302, 404})
        self.assertEqual(reconweave.parse_status_list("0,700,abc"), {200})

    def test_private_ip_regex_rejects_invalid_octets(self):
        pattern = reconweave.SECRETS_PATTERNS["Internal IP"]
        self.assertIsNotNone(pattern.search("10.1.2.3"))
        self.assertIsNotNone(pattern.search("172.16.2.3"))
        self.assertIsNotNone(pattern.search("192.168.2.3"))
        self.assertIsNone(pattern.search("10.999.2.3"))
        self.assertIsNone(pattern.search("172.32.2.3"))
        self.assertIsNone(pattern.search("10.1.2.3.4"))
        self.assertIsNone(pattern.search("x10.1.2.3"))

    def test_crawler_scope_honors_scheme_port_and_subdomain_option(self):
        crawler = reconweave.Crawler(self.app)
        crawler.root_hostname = "example.com"
        crawler.target_scheme = "https"
        crawler.target_port = None
        crawler.allowed_hosts = set()
        crawler.include_subdomains = False
        self.assertTrue(crawler.in_scope("https://example.com/page"))
        self.assertFalse(crawler.in_scope("http://example.com/page"))
        self.assertFalse(crawler.in_scope("https://sub.example.com/page"))
        crawler.include_subdomains = True
        self.assertTrue(crawler.in_scope("https://sub.example.com/page"))
        self.assertFalse(crawler.in_scope("https://evil-example.com/page"))
        crawler.root_hostname = "co.uk"
        self.assertFalse(crawler.in_scope("https://attacker.co.uk/page"))
        crawler.root_hostname = "127.0.0.1"
        self.assertFalse(crawler.in_scope("https://child.127.0.0.1/page"))

    def test_subdomain_base_is_validated_against_target_scope(self):
        bruter = reconweave.BruteEngine(self.app)
        self.assertEqual(
            bruter._normalize_subdomain_base("example.com", "https://api.example.com"),
            "https://example.com/",
        )
        self.assertIsNone(bruter._normalize_subdomain_base("evil.example.net", "https://api.example.com"))
        self.assertIsNone(bruter._normalize_subdomain_base("co.uk", "https://api.example.co.uk"))
        self.assertIsNone(bruter._normalize_subdomain_base("127.0.0.1", "https://127.0.0.1"))

    def test_directory_base_rejects_cross_host_scheme_and_port(self):
        bruter = reconweave.BruteEngine(self.app)
        origin = "https://example.com/"
        opts = {"include_subdomains": False}
        self.assertEqual(bruter._normalize_directory_base("/admin/", origin, opts), "https://example.com/admin/")
        self.assertIsNone(bruter._normalize_directory_base("https://evil.example/", origin, opts))
        self.assertIsNone(bruter._normalize_directory_base("http://example.com/admin/", origin, opts))
        self.assertIsNone(bruter._normalize_directory_base("https://example.com:8443/admin/", origin, opts))
        self.assertIsNone(bruter._normalize_directory_base(
            "https://child.127.0.0.1/admin/", "https://127.0.0.1/", {"include_subdomains": True}
        ))

    def test_word_validation_rejects_path_escape_and_bad_dns_labels(self):
        valid = reconweave.BruteEngine._valid_word
        self.assertIsNone(valid("../admin", "directory"))
        self.assertIsNone(valid("one?two", "directory"))
        self.assertIsNone(valid("https://evil.example", "directory"))
        self.assertEqual(valid("admin/login", "directory"), "admin/login")
        self.assertEqual(valid("API-V1", "subdomain"), "api-v1")
        self.assertIsNone(valid("bad..label", "subdomain"))
        self.assertIsNone(valid("-bad", "subdomain"))
        self.assertIsNone(valid(".admin", "subdomain"))
        self.assertIsNone(valid("admin.", "subdomain"))

    def test_osint_domain_matching_is_boundary_aware(self):
        osint = self.app.osint
        self.assertTrue(osint._is_valid_osint_url("https://api.example.com/", "www.example.com", "example.com"))
        self.assertFalse(osint._is_valid_osint_url("https://evil-example.com/", "example.com", "example.com"))
        self.assertFalse(osint._is_valid_osint_url("https://evil.co.uk/", "co.uk", "co.uk"))
        self.assertFalse(osint._is_valid_osint_url("javascript:alert(1)", "example.com", "example.com"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
