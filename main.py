#!/usr/bin/env python3
"""
ReconWeave - Attack Surface Mapper | Intelligent Crawler | OSINT & Secrets Scanner
Credit: made by Aryan Giri | giriaryan694-a11y

Authorized security testing only.
Requirement: pip install duckduckgo-search
"""

import json
import math
import queue
import re
import ssl
import threading
import time
import tkinter as tk
import webbrowser
import urllib.parse
import http.cookiejar
import random
from tkinter import ttk, messagebox, filedialog, scrolledtext
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, quote, unquote
from urllib.request import Request, urlopen, HTTPRedirectHandler, HTTPSHandler, build_opener, ProxyHandler, HTTPCookieProcessor
from urllib.error import HTTPError, URLError

# Safe import for DDGS library
try:
    from duckduckgo_search import DDGS
    DDGS_AVAILABLE = True
except ImportError:
    DDGS_AVAILABLE = False

APP_NAME = "ReconWeave"
CREDIT = "made by Aryan Giri | giriaryan694-a11y"
CONFIG_FILE = Path.home() / ".reconweave_config.json"

STATUS_DEFAULT = "200,301,302,303,307,308,401,403,500"

BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "signin", "signup", "register", "logout",
    "api", "api/v1", "api/v2", "graphql", "v1", "v2", "swagger", "swagger.json",
    "openapi.json", "docs", "console", "panel", "dashboard", "backup", "backups",
    "config", "configuration", "debug", "trace", "actuator", "env", "dev", "test",
    "staging", "internal", "private", "hidden", "old", "temp", "tmp", "uploads",
    "files", "static", "assets", "robots.txt", "sitemap.xml", ".git/", ".env",
    ".DS_Store", "wp-admin", "wp-login.php", "xmlrpc.php", "server-status",
    "phpmyadmin", "db", "database", "admin.php", "login.php",
]

# Built-in subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "www2", "www3", "www4", "mail", "mail2", "mail3", "smtp", "smtp2",
    "pop", "pop3", "imap", "webmail", "email", "mx", "mx1", "mx2", "mx3",
    "ftp", "ftp2", "sftp", "file", "files", "upload", "uploads", "download",
    "downloads", "cdn", "static", "static1", "static2", "assets", "media",
    "img", "images", "image", "pics", "photo", "photos", "video", "videos",
    "api", "api2", "api-v1", "api-v2", "api.dev", "api.dev", "api.staging",
    "api.test", "api.prod", "api.internal", "api.admin", "api.gateway",
    "admin", "admin2", "admin2", "admin2", "panel", "console", "dashboard",
    "portal", "portal2", "portal2", "portal2", "portal2", "portal2",
    "app", "apps", "app1", "app2", "web", "web2", "web3", "webapp", "webapps",
    "shop", "shop2", "shop2", "shop2", "shop2", "shop2", "shop2", "shop2",
    "store", "store2", "store2", "store2", "store2", "store2", "store2",
    "blog", "blog2", "blog2", "blog2", "blog2", "blog2", "blog2", "blog2",
    "news", "news2", "news2", "news2", "news2", "news2", "news2", "news2",
    "support", "support2", "support2", "support2", "support2", "support2",
    "help", "help2", "help2", "help2", "help2", "help2", "help2", "help2",
    "forum", "forum2", "forum2", "forum2", "forum2", "forum2", "forum2",
    "community", "community2", "community2", "community2", "community2",
    "members", "member", "members2", "member2", "members2", "member2",
    "auth", "auth2", "auth2", "auth2", "auth2", "auth2", "auth2", "auth2",
    "sso", "sso2", "sso2", "sso2", "sso2", "sso2", "sso2", "sso2",
    "oauth", "oauth2", "oauth2", "oauth2", "oauth2", "oauth2", "oauth2",
    "login", "login2", "login2", "login2", "login2", "login2", "login2",
    "secure", "secure2", "secure2", "secure2", "secure2", "secure2", "secure2",
    "my", "my2", "my2", "my2", "my2", "my2", "my2", "my2",
    "account", "account2", "account2", "account2", "account2", "account2",
    "accounts", "account2", "account2", "account2", "account2", "account2",
    "user", "user2", "user2", "user2", "user2", "user2", "user2", "user2",
    "users", "user2", "user2", "user2", "user2", "user2", "user2", "user2",
    "profile", "profile2", "profile2", "profile2", "profile2", "profile2",
    "settings", "settings2", "settings2", "settings2", "settings2",
    "search", "search2", "search2", "search2", "search2", "search2",
    "dev", "dev2", "dev2", "dev2", "dev2", "dev2", "dev2", "dev2",
    "test", "test2", "test2", "test2", "test2", "test2", "test2", "test2",
    "staging", "staging2", "staging2", "staging2", "staging2", "staging2",
    "uat", "uat2", "uat2", "uat2", "uat2", "uat2", "uat2", "uat2",
    "qa", "qa2", "qa2", "qa2", "qa2", "qa2", "qa2", "qa2",
    "sandbox", "sandbox2", "sandbox2", "sandbox2", "sandbox2", "sandbox2",
    "preview", "preview2", "preview2", "preview2", "preview2", "preview2",
    "beta", "beta2", "beta2", "beta2", "beta2", "beta2", "beta2", "beta2",
    "alpha", "alpha2", "alpha2", "alpha2", "alpha2", "alpha2", "alpha2",
    "nightly", "nightly2", "nightly2", "nightly2", "nightly2", "nightly2",
    "canary", "canary2", "canary2", "canary2", "canary2", "canary2",
    "internal", "internal2", "internal2", "internal2", "internal2",
    "intranet", "intranet2", "intranet2", "intranet2", "intranet2",
    "corp", "corp2", "corp2", "corp2", "corp2", "corp2", "corp2", "corp2",
    "corporate", "corp2", "corp2", "corp2", "corp2", "corp2", "corp2",
    "hr", "hr2", "hr2", "hr2", "hr2", "hr2", "hr2", "hr2",
    "finance", "finance2", "finance2", "finance2", "finance2", "finance2",
    "billing", "billing2", "billing2", "billing2", "billing2", "billing2",
    "payment", "payment2", "payment2", "payment2", "payment2", "payment2",
    "payments", "payment2", "payment2", "payment2", "payment2", "payment2",
    "checkout", "checkout2", "checkout2", "checkout2", "checkout2",
    "cart", "cart2", "cart2", "cart2", "cart2", "cart2", "cart2", "cart2",
    "order", "order2", "order2", "order2", "order2", "order2", "order2",
    "orders", "order2", "order2", "order2", "order2", "order2", "order2",
    "tracking", "tracking2", "tracking2", "tracking2", "tracking2",
    "track", "tracking2", "tracking2", "tracking2", "tracking2", "tracking2",
    "analytics", "analytics2", "analytics2", "analytics2", "analytics2",
    "metrics", "analytics2", "analytics2", "analytics2", "analytics2",
    "monitoring", "analytics2", "analytics2", "analytics2", "analytics2",
    "logs", "logs2", "logs2", "logs2", "logs2", "logs2", "logs2", "logs2",
    "log", "logs2", "logs2", "logs2", "logs2", "logs2", "logs2", "logs2",
    "status", "status2", "status2", "status2", "status2", "status2",
    "health", "status2", "status2", "status2", "status2", "status2",
    "ping", "status2", "status2", "status2", "status2", "status2",
    "healthcheck", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
    "metrics", "status2", "status2", "status2", "status2", "status2",
]

URL_RE = re.compile(r"""["']((?:https?://[^"'<>\s]+)|(?:/[a-zA-Z0-9_\-./?%=&]+)|(?:[a-zA-Z0-9_\-][a-zA-Z0-9_\-./]*\.(?:php|asp|aspx|jsp|html|htm|nsp|cfm|py|pl|rb|txt|xml|json|cgi|js|css)(?:\?[^"'\s]*)?)|(?:[a-zA-Z0-9_\-][a-zA-Z0-9_\-./]*\?[^"'\s]+))["']""", re.I)
API_RE = re.compile(r"""["'](/(?:api|v[0-9]+|graphql|rest|ajax|ws|internal)[^"'<>\s]*)["']""", re.I)
JS_CALL_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest\.open|\.open)\s*\(\s*["']([^"']+)["']""",
    re.I,
)
JS_REDIR_RE = re.compile(r"""(?:window\.location(?:\.href)?|document\.location(?:\.href)?|location\.(?:replace|assign|href))\s*[=(]\s*["']([^"']+)["']""", re.I)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)
STATIC_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|css|ico|woff2?|ttf|eot|otf|mp4|webm|webp|pdf|zip|tar|gz)$",
    re.I,
)

SECRETS_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS S3 Bucket": re.compile(r"[a-z0-9.\-_]+\.s3\.amazonaws\.com"),
    "GCP Bucket": re.compile(r"[a-z0-9.\-_]+\.storage\.googleapis\.com"),
    "Azure Storage": re.compile(r"[a-z0-9]+\.blob\.core\.windows\.net"),
    "GitHub Token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "Stripe Key": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "JWT Token": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "Generic Secret": re.compile(r"(?i)(?:api[_-]?key|apikey|token|secret|auth|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]"),
    "Internal IP": re.compile(r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"),
    "Email Address": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
}

DIAGRAM_CATEGORIES = [
    ("pages", "Pages"), ("directories", "Directories"), ("forms", "Forms"),
    ("inputs", "Inputs"), ("links", "Links"), ("js_files", "JavaScript"),
    ("api_endpoints", "API endpoints"), ("parameters", "Parameters"),
    ("redirects", "Redirects"), ("robots_paths", "robots.txt"),
    ("sitemap_urls", "Sitemap"), ("secrets", "Secrets & Creds"),
    ("security_issues", "Security Headers"), ("errors", "Errors"),
]


def default_results():
    return {
        "pages": [], "links": [], "forms": [], "inputs": [], "js_files": [],
        "api_endpoints": [], "parameters": [], "redirects": [], "robots_paths": [],
        "sitemap_urls": [], "directories": [], "errors": [], "secrets": [],
        "security_issues": [],
    }


def analyze_headers(headers):
    issues = []
    if not headers: return issues
    headers_lower = {k.lower(): v for k, v in headers.items()}
    if "strict-transport-security" not in headers_lower: issues.append("Missing HSTS")
    if "content-security-policy" not in headers_lower: issues.append("Missing CSP")
    if "x-frame-options" not in headers_lower: issues.append("Missing X-Frame-Options")
    if "x-content-type-options" not in headers_lower: issues.append("Missing X-Content-Type-Options")
    if "referrer-policy" not in headers_lower: issues.append("Missing Referrer-Policy")
    server = headers_lower.get("server", "")
    if server: issues.append(f"Server Disclosed: {server}")
    powered = headers_lower.get("x-powered-by", "")
    if powered: issues.append(f"Tech Disclosed: {powered}")
    return issues


def decode_bytes(data, content_type):
    if not data: return ""
    charset = "utf-8"
    try:
        if content_type and "charset=" in content_type:
            charset = content_type.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        return data.decode(charset, errors="ignore")
    except LookupError:
        return data.decode("utf-8", errors="ignore")


def origin_from_url(url):
    if not url: return "http://localhost/"
    if not url.startswith(("http://", "https://")): url = "http://" + url
    parts = urlsplit(url)
    if not parts.netloc: return "http://localhost/"
    return f"{parts.scheme}://{parts.netloc}"


def path_dirs(path):
    if not path: return []
    if "://" in path: path = urlsplit(path).path
    if not path.startswith("/"): path = "/" + path
    parts = [p for p in path.split("/") if p]
    if not parts: return ["/"]
    dirs = []
    current = ""
    for idx, part in enumerate(parts):
        current += "/" + part
        is_last = idx == len(parts) - 1
        if is_last:
            if path.endswith("/") or "." not in part: dirs.append(current + "/")
        else:
            dirs.append(current + "/")
    return list(dict.fromkeys(dirs))


def normalize_brute_base(base, target_origin):
    base = (base or "").strip()
    if not base: base = "/"
    if base.startswith(("http://", "https://")): url = base
    else:
        if not base.startswith("/"): base = "/" + base
        url = urljoin(target_origin or "http://localhost/", base)
    parts = urlsplit(url)
    path = parts.path or "/"
    if not path.endswith("/"):
        last = path.rstrip("/").split("/")[-1]
        if "." in last: path = path.rsplit("/", 1)[0] + "/"
        else: path += "/"
    if not path.startswith("/"): path = "/" + path
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def parse_status_list(text):
    out = set()
    for part in str(text).replace(";", ",").split(","):
        part = part.strip()
        if part.isdigit(): out.add(int(part))
    return out or {200}


def dot_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")[:180]


def mermaid_escape(value):
    return str(value).replace('"', "'").replace("\n", " ")[:160]


def host_matches(a, b):
    if not a or not b: return False
    if a == b: return True
    local_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    return a in local_hosts and b in local_hosts


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_request(url, user_agent, timeout=8, verify=True, max_bytes=2000000, follow_redirects=True, proxy_url=None):
    headers = {
        "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    req = Request(url, headers=headers)
    context = None if verify else ssl._create_unverified_context()

    handlers = []
    if proxy_url:
        handlers.append(ProxyHandler({'http': proxy_url, 'https': proxy_url}))
    if not follow_redirects:
        handlers.append(NoRedirectHandler())
    if context is not None:
        handlers.append(HTTPSHandler(context=context))
    opener = build_opener(*handlers)

    try:
        resp = opener.open(req, timeout=timeout)
        status = getattr(resp, "status", 200)
        final_url = resp.geturl()
        headers_dict = dict(resp.headers) if resp.headers else {}
        content_type = headers_dict.get("Content-Type", "")
        location = headers_dict.get("Location", "")
        body = resp.read(max_bytes) if max_bytes else b""
        resp.close()
        return {"status": status, "final_url": final_url, "content_type": content_type,
                "location": location, "body": body, "length": len(body), "headers": headers_dict}
    except HTTPError as e:
        body = b""
        try: body = e.read(max_bytes)
        except Exception: pass
        headers_dict = dict(e.headers) if e.headers else {}
        content_type = headers_dict.get("Content-Type", "")
        location = headers_dict.get("Location", "")
        return {"status": e.code, "final_url": getattr(e, "url", url), "content_type": content_type,
                "location": location, "body": body, "length": len(body), "headers": headers_dict}
    except Exception as e:
        return {"status": 0, "final_url": url, "content_type": "", "location": "",
                "body": str(e).encode(errors="ignore"), "length": 0, "error": str(e), "headers": {}}


class HTMLExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links = []
        self.media = []
        self.scripts = []
        self.forms = []
        self.inputs = []
        self.comments = []
        self.current_form = None

    def _normalize(self, value):
        if not value: return None
        value = value.strip()
        low = value.lower()
        if low.startswith(("javascript:", "mailto:", "tel:", "data:", "#")): return None
        try: return urljoin(self.base_url, value)
        except ValueError: return None

    def handle_starttag(self, tag, attrs):
        attrs_d = {k.lower(): v for k, v in attrs}
        if tag == "base":
            href = attrs_d.get("href")
            if href:
                try: self.base_url = urljoin(self.base_url, href)
                except ValueError: pass
            return
        if tag == "a":
            u = self._normalize(attrs_d.get("href"))
            if u: self.links.append(u)
        elif tag == "link":
            u = self._normalize(attrs_d.get("href"))
            if u: self.media.append(u)
        elif tag == "script":
            u = self._normalize(attrs_d.get("src"))
            if u: self.scripts.append(u)
        elif tag == "form":
            action = self._normalize(attrs_d.get("action") or "")
            self.current_form = {"action": action or self.base_url, "method": (attrs_d.get("method") or "get").lower(), "inputs": []}
        elif tag in ("input", "textarea", "select"):
            name = attrs_d.get("name")
            if name:
                item = {"name": name, "type": attrs_d.get("type") or tag, "form_action": self.current_form["action"] if self.current_form else None}
                if self.current_form is not None:
                    self.current_form["inputs"].append({"name": name, "type": attrs_d.get("type") or tag})
                else:
                    self.inputs.append(item)
        elif tag in ("iframe", "frame", "embed", "object"):
            u = self._normalize(attrs_d.get("src"))
            if u: self.media.append(u)

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_comment(self, data):
        self.comments.append(data)


class Crawler:
    def __init__(self, app):
        self.app = app
        self.stop_event = threading.Event()
        self.running = False
        self.results = default_results()
        self._seen = {}
        self.reset()

    def reset(self):
        self.results = default_results()
        self._seen = {k: set() for k in ["pages", "links", "forms", "inputs", "js", "api", "params", "redirects", "robots", "sitemap", "dirs", "secrets", "sec_issues"]}
        self.bfs_queue = deque()
        self.pending = set()
        self._robot_sitemaps = []
        self.allowed_hosts = set()

    def log(self, msg):
        self.app.ui_queue.put(("log", f"[crawl] {msg}"))

    def clean_url(self, url):
        try: parts = urlsplit(url)
        except ValueError: return None
        if parts.scheme not in ("http", "https"): return None
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))

    def in_scope(self, url):
        try: parts = urlsplit(url)
        except ValueError: return False
        if parts.scheme not in ("http", "https") or not parts.hostname: return False
        hostname = parts.hostname.lower()
        if getattr(self, 'allowed_hosts', None):
            for h in self.allowed_hosts:
                h_lower = h.lower()
                if hostname == h_lower or hostname.endswith("." + h_lower): return True
            return False
        if self.include_subdomains:
            return hostname == self.root_hostname.lower() or hostname.endswith("." + self.root_hostname.lower())
        return hostname == self.root_netloc.lower().split(':')[0]

    def enqueue_url(self, url, depth):
        if self.stop_event.is_set(): return
        if self.max_depth > 0 and depth > self.max_depth: return
        url = self.clean_url(url)
        if not url or not self.in_scope(url) or STATIC_RE.search(url): return
        if url in self._seen["pages"] or url in self.pending: return
        if len(self._seen["pages"]) + len(self.pending) >= self.max_pages: return
        self.pending.add(url)
        self.bfs_queue.append((url, depth))

    def add_directories_from_path(self, path, source):
        if not path or "*" in path or "$" in path: return
        for d in path_dirs(path):
            if d not in self._seen["dirs"]:
                self._seen["dirs"].add(d)
                self.results["directories"].append({"path": d, "source": source})

    def add_directories_from_url(self, url, source):
        try: path = urlsplit(url).path
        except ValueError: return
        self.add_directories_from_path(path, source)

    def add_page(self, url, status, final_url, depth, length, headers):
        if url in self._seen["pages"]: return
        self._seen["pages"].add(url)
        sec_issues = analyze_headers(headers)
        self.results["pages"].append({"url": url, "status": status, "final_url": final_url, "depth": depth, "length": length, "headers": headers, "security_issues": sec_issues})
        for issue in sec_issues:
            key = f"{url}|{issue}"
            if key not in self._seen["sec_issues"]:
                self._seen["sec_issues"].add(key)
                self.results["security_issues"].append({"url": url, "issue": issue})
        self.add_directories_from_url(url, "crawl")

    def add_link(self, url, source):
        url = self.clean_url(url)
        if not url or not self.in_scope(url): return
        if url not in self._seen["links"]:
            self._seen["links"].add(url)
            self.results["links"].append({"url": url, "source": source})
            self.add_directories_from_url(url, source)
            self.add_params_from_url(url)

    def add_js(self, url, source):
        url = self.clean_url(url)
        if not url or not self.in_scope(url): return
        if url not in self._seen["js"]:
            self._seen["js"].add(url)
            self.results["js_files"].append({"url": url, "source": source})
            self.add_directories_from_url(url, source)

    def add_api(self, url, source):
        url = self.clean_url(url)
        if not url or not self.in_scope(url): return
        if url not in self._seen["api"]:
            self._seen["api"].add(url)
            self.results["api_endpoints"].append({"url": url, "source": source})
            self.add_directories_from_url(url, source)
            self.add_params_from_url(url)

    def add_form(self, form):
        action = self.clean_url(form.get("action") or self.target)
        if not action: return
        inputs = form.get("inputs", [])
        input_names = ",".join(sorted({i.get("name", "") for i in inputs if i.get("name")}))
        key = f"{form.get('method', 'get')}|{action}|{input_names}"
        if key in self._seen["forms"]: return
        self._seen["forms"].add(key)
        self.results["forms"].append({"method": form.get("method", "get"), "action": action, "input_names": input_names, "inputs": inputs})
        self.add_directories_from_url(action, "form")
        for inp in inputs:
            self.add_param(inp.get("name", ""), "", action)

    def add_input(self, item):
        key = f"{item.get('name')}|{item.get('form_action') or ''}"
        if key in self._seen["inputs"]: return
        self._seen["inputs"].add(key)
        self.results["inputs"].append(item)

    def add_param(self, name, value, url):
        if not name: return
        try: path = urlsplit(url).path
        except ValueError: path = url
        key = f"{name}|{path}"
        if key in self._seen["params"]: return
        self._seen["params"].add(key)
        self.results["parameters"].append({"name": name, "value": value, "url": url, "path": path})

    def add_redirect(self, src, dst, status):
        key = f"{src}->{dst}"
        if key in self._seen["redirects"]: return
        self._seen["redirects"].add(key)
        self.results["redirects"].append({"from": src, "to": dst, "status": status})

    def add_robots_path(self, path):
        if path in self._seen["robots"]: return
        self._seen["robots"].add(path)
        self.results["robots_paths"].append({"path": path})
        self.add_directories_from_path(path, "robots.txt")

    def add_sitemap_url(self, url):
        url = self.clean_url(url)
        if not url or not self.in_scope(url): return
        if url not in self._seen["sitemap"]:
            self._seen["sitemap"].add(url)
            self.results["sitemap_urls"].append({"url": url})
            self.add_directories_from_url(url, "sitemap")

    def add_params_from_url(self, url):
        try: parts = urlsplit(url)
        except ValueError: return
        if not parts.query: return
        for key, val in parse_qsl(parts.query, keep_blank_values=True):
            self.add_param(key, val, url)

    def safe_join(self, source_url, value):
        try: absolute = urljoin(source_url, value.strip())
        except ValueError: return None
        return self.clean_url(absolute)

    def scan_secrets(self, url, text):
        if not text: return
        for name, pattern in SECRETS_PATTERNS.items():
            for match in pattern.finditer(text):
                val = match.group(0)
                if match.lastindex and match.lastindex >= 1: val = match.group(1)
                key = f"{name}|{val}"
                if key not in self._seen["secrets"]:
                    self._seen["secrets"].add(key)
                    start = max(0, match.start() - 30)
                    end = min(len(text), match.end() + 30)
                    snippet = text[start:end].replace('\n', ' ').strip()
                    self.results["secrets"].append({"type": name, "value": val, "url": url, "snippet": snippet})

    def harvest_robots(self, base_url):
        robots_url = urljoin(base_url, "/robots.txt")
        res = http_request(robots_url, self.ua, self.timeout, self.verify, self.max_bytes, True, self.proxy_url)
        if res["status"] == 200:
            text = decode_bytes(res["body"], res["content_type"])
            self.log(f"robots.txt found for {base_url}")
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"): continue
                low = line.lower()
                if low.startswith("disallow:") or low.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if not path or path == "*": continue
                    self.add_robots_path(path)
                    if self.opts.get("crawl_robots", False) and "*" not in path and "$" not in path:
                        self.enqueue_url(urljoin(base_url, path), 1)
                elif low.startswith("sitemap:"):
                    sitemap = line.split(":", 1)[1].strip()
                    if sitemap: self._robot_sitemaps.append(urljoin(base_url, sitemap))
        else:
            self.log(f"robots.txt status: {res['status']}")

    def harvest_sitemaps(self, base_url):
        initial = [urljoin(base_url, "/sitemap.xml")] + self._robot_sitemaps
        q = deque(initial)
        processed = set()
        count = 0
        while q and count < 5 and not self.stop_event.is_set():
            surl = self.clean_url(q.popleft())
            if not surl or surl in processed or not self.in_scope(surl): continue
            processed.add(surl)
            count += 1
            res = http_request(surl, self.ua, self.timeout, self.verify, self.max_bytes, True, self.proxy_url)
            if res["status"] != 200: continue
            text = decode_bytes(res["body"], res["content_type"])
            self.add_sitemap_url(surl)
            for loc in SITEMAP_LOC_RE.findall(text)[:1000]:
                if self.stop_event.is_set(): break
                loc = loc.strip()
                if not loc: continue
                absolute = urljoin(surl, loc)
                if not self.in_scope(absolute): continue
                self.add_sitemap_url(absolute)
                if self.opts.get("crawl_sitemap", True): self.enqueue_url(absolute, 1)
                if absolute.lower().endswith(".xml") and absolute not in processed: q.append(absolute)

    def parse_html(self, url, text, depth):
        if not text: return
        try:
            parser = HTMLExtractor(url)
            parser.feed(text)
            parser.close()
        except Exception as e:
            self.log(f"HTML parse error for {url}: {e}")
            return
        if parser.current_form is not None:
            parser.forms.append(parser.current_form)
            parser.current_form = None
        for link in set(parser.links):
            self.add_link(link, "html")
            self.enqueue_url(link, depth + 1)
        for script in set(parser.scripts):
            self.add_js(script, "html")
            if self.fetch_js: self.enqueue_url(script, depth + 1)
        for media in set(parser.media):
            if not STATIC_RE.search(media): self.add_link(media, "media")
        for form in parser.forms:
            self.add_form(form)
            if form.get("action") and form.get("method", "get") == "get":
                self.enqueue_url(form.get("action"), depth + 1)
        for inp in parser.inputs: self.add_input(inp)

    def extract_regex_endpoints(self, source_url, text, source_label, depth):
        if not text: return
        for match in API_RE.findall(text)[:500]:
            absolute = self.safe_join(source_url, match)
            if absolute:
                self.add_api(absolute, source_label)
                if self.visit_discovered: self.enqueue_url(absolute, depth + 1)
        for match in JS_CALL_RE.findall(text)[:500]:
            absolute = self.safe_join(source_url, match)
            if absolute:
                self.add_api(absolute, f"{source_label}:call")
                if self.visit_discovered: self.enqueue_url(absolute, depth + 1)
        for match in URL_RE.findall(text)[:500]:
            absolute = self.safe_join(source_url, match)
            if absolute:
                self.add_link(absolute, source_label)
                if self.visit_discovered: self.enqueue_url(absolute, depth + 1)
        for match in JS_REDIR_RE.findall(text)[:100]:
            absolute = self.safe_join(source_url, match)
            if absolute:
                self.add_link(absolute, f"{source_label}:js_redirect")
                self.add_params_from_url(absolute)
                if self.visit_discovered: self.enqueue_url(absolute, depth + 1)

    def run(self, target, opts):
        if self.running: return
        self.running = True
        self.stop_event.clear()
        self.reset()
        try:
            self.allowed_hosts = set(opts.get("allowed_hosts", []))
            target = target.strip()
            if not target.startswith(("http://", "https://")): target = "https://" + target
            parts = urlsplit(target)
            if not parts.hostname: raise ValueError("Invalid target URL")
            self.target = target
            self.opts = opts
            self.root_netloc = parts.netloc
            self.root_hostname = parts.hostname or ""
            self.target_port = parts.port
            self.max_depth = int(opts.get("max_depth", 0))
            self.max_pages = int(opts.get("max_pages", 150))
            self.delay = max(0.0, float(opts.get("delay", 0.25)))
            self.timeout = float(opts.get("timeout", 8))
            self.ua = opts.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            self.verify = bool(opts.get("verify_tls", True))
            self.include_subdomains = bool(opts.get("include_subdomains", False))
            self.fetch_js = bool(opts.get("fetch_js", True))
            self.extract_js = bool(opts.get("extract_js", True))
            self.visit_discovered = bool(opts.get("visit_discovered", True))
            self.proxy_url = opts.get("proxy_url", "").strip() or None
            self.max_bytes = 2_000_000

            self.log(f"Starting crawl...")
            if self.proxy_url: self.log(f"Using proxy: {self.proxy_url}")
            if self.allowed_hosts:
                self.log(f"Active recon targeting {len(self.allowed_hosts)} specific subdomain(s).")
                for h in self.allowed_hosts:
                    self.add_directories_from_path("/", "target")
                    self.enqueue_url(f"http://{h}/", 0)
                    self.enqueue_url(f"https://{h}/", 0)
                    if opts.get("parse_robots", True): self.harvest_robots(f"http://{h}")
                    if opts.get("parse_sitemap", True): self.harvest_sitemaps(f"http://{h}")
            else:
                self.log(f"Target: {self.target}")
                self.add_directories_from_path("/", "target")
                self.enqueue_url(self.target, 0)
                if opts.get("parse_robots", True): self.harvest_robots(self.target)
                if opts.get("parse_sitemap", True): self.harvest_sitemaps(self.target)

            while self.bfs_queue and not self.stop_event.is_set() and len(self._seen["pages"]) < self.max_pages:
                url, depth = self.bfs_queue.popleft()
                self.pending.discard(url)
                if url in self._seen["pages"]: continue
                if self.delay: time.sleep(self.delay)
                self.log(f"GET {url}")
                res = http_request(url, self.ua, self.timeout, self.verify, self.max_bytes, True, self.proxy_url)
                status = res["status"]
                headers = res.get("headers", {})
                if status == 0:
                    err = decode_bytes(res.get("body", b""), "")[:250]
                    self.results["errors"].append({"url": url, "error": err})
                    continue
                final_url = res.get("final_url", url)
                self.add_page(url, status, final_url, depth, res.get("length", 0), headers)
                if final_url and final_url != url:
                    self.add_redirect(url, final_url, status)
                    if self.in_scope(final_url): self.enqueue_url(final_url, depth)
                ctype = res.get("content_type", "").lower()
                body = res.get("body", b"")
                text = ""
                should_decode = ("html" in ctype or "javascript" in ctype or "json" in ctype or "xml" in ctype or
                                 url.lower().endswith((".js", ".html", ".htm", ".php", ".aspx", ".jsp", ".txt", ".xml")))
                if should_decode: text = decode_bytes(body, ctype)
                self.scan_secrets(url, text)
                if "html" in ctype:
                    self.parse_html(url, text, depth)
                    if self.extract_js: self.extract_regex_endpoints(url, text, "html", depth)
                elif self.extract_js and ("javascript" in ctype or url.lower().endswith(".js")):
                    self.extract_regex_endpoints(url, text, "js", depth)
                elif text:
                    self.extract_regex_endpoints(url, text, "text", depth)
                self.add_params_from_url(url)

            self.log("Crawl stopped by user." if self.stop_event.is_set() else "Crawl finished.")
        except Exception as e:
            self.log(f"Crawl fatal error: {e}")
        finally:
            self.running = False
            self.app.ui_queue.put(("crawl_done", None))


class BruteEngine:
    def __init__(self, app):
        self.app = app
        self.stop_event = threading.Event()
        self.running = False
        self.results = []
        self.total_requests = 0
        self.sent_requests = 0

    def log(self, msg): self.app.ui_queue.put(("log", f"[brute] {msg}"))
    def stop(self): self.stop_event.set()

    def load_wordlist(self, ref):
        ref = (ref or "").strip()
        if not ref or ref == "builtin:common": return BUILTIN_WORDLIST[:]
        path_value = self.app.wordlists.get(ref, ref)
        if not path_value or path_value == "builtin:common": return BUILTIN_WORDLIST[:]
        p = Path(path_value).expanduser()
        if not p.exists(): raise FileNotFoundError(f"Wordlist not found: {p}")
        return [line.strip() for line in p.read_text(errors="ignore").splitlines() if line.strip() and not line.startswith("#")]

    def load_subdomain_wordlist(self, ref):
        ref = (ref or "").strip()
        if not ref or ref == "builtin:subdomains": return SUBDOMAIN_WORDLIST[:]
        path_value = self.app.subdomain_wordlists.get(ref, ref)
        if not path_value or path_value == "builtin:subdomains": return SUBDOMAIN_WORDLIST[:]
        p = Path(path_value).expanduser()
        if not p.exists(): raise FileNotFoundError(f"Subdomain wordlist not found: {p}")
        return [line.strip() for line in p.read_text(errors="ignore").splitlines() if line.strip() and not line.startswith("#")]

    def start(self, bases, wordlist_ref, opts, mode="directory"):
        if self.running: return False
        self.results = []
        self.total_requests = 0
        self.sent_requests = 0
        threading.Thread(target=self._controller, args=(bases, wordlist_ref, opts, mode), daemon=True).start()
        return True

    def _controller(self, bases, wordlist_ref, opts, mode="directory"):
        self.running = True
        self.stop_event.clear()
        try:
            if mode == "subdomain":
                words = self.load_subdomain_wordlist(wordlist_ref)
            else:
                words = self.load_wordlist(wordlist_ref)
            if not words: return
            target_origin = opts.get("target_origin") or "http://localhost/"
            target_host = urlsplit(target_origin).hostname
            normalized = []
            seen = set()
            for base in bases:
                nb = normalize_brute_base(base, target_origin)
                if not nb: continue
                base_host = urlsplit(nb).hostname
                if target_host and not host_matches(base_host, target_host): continue
                if nb not in seen:
                    seen.add(nb)
                    normalized.append(nb)
            if not normalized: return
            mode_opt = opts.get("mode", "sequential")
            self.total_requests = len(normalized) * len(words)
            self.log(f"Brute starting: {len(normalized)} base(s), {len(words)} words, mode={mode_opt}, total={self.total_requests}")
            if mode_opt == "sequential":
                for base in normalized:
                    if self.stop_event.is_set(): break
                    self._brute_base(base, words, opts, mode)
            else:
                max_workers = max(1, min(int(opts.get("threads", 5)), len(normalized), 50))
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for fut in [executor.submit(self._brute_base, base, words, opts, mode) for base in normalized]:
                        try: fut.result()
                        except Exception as e: self.log(f"Brute worker error: {e}")
            self.log("Brute finished.")
        except Exception as e:
            self.log(f"Brute error: {e}")
        finally:
            self.running = False
            self.app.ui_queue.put(("brute_done", None))

    def _brute_base(self, base, words, opts, mode="directory"):
        delay = max(0.0, float(opts.get("delay", 0.2)))
        max_items = max(1, int(opts.get("max_per_dir", 500)))
        interesting = opts.get("interesting_statuses", {200})
        timeout = float(opts.get("timeout", 8))
        ua = opts.get("user_agent", f"{APP_NAME}/1.0")
        verify = bool(opts.get("verify_tls", True))
        log_all = bool(opts.get("log_all", False))
        proxy_url = opts.get("proxy_url", "").strip() or None
        count = 0
        seen_words = set()
        self.log(f"Bruting {base}")
        for raw in words:
            if self.stop_event.is_set() or count >= max_items: break
            word = raw.strip()
            if not word or word.startswith("#") or "://" in word: continue
            word = word.lstrip("/")
            if word in seen_words: continue
            seen_words.add(word)
            count += 1
            self.sent_requests += 1
            self.app.ui_queue.put(("brute_progress", (self.sent_requests, self.total_requests)))
            if delay: time.sleep(delay)
            if mode == "subdomain":
                # Subdomain brute: word.domain.com
                base_parsed = urlsplit(base)
                subdomain_url = f"{base_parsed.scheme}://{word}.{base_parsed.netloc}/"
                res = http_request(subdomain_url, ua, timeout=timeout, verify=verify, max_bytes=4096, follow_redirects=False, proxy_url=proxy_url)
            else:
                url = urljoin(base, word)
                res = http_request(url, ua, timeout=timeout, verify=verify, max_bytes=4096, follow_redirects=False, proxy_url=proxy_url)
            status = res.get("status", 0)
            length = res.get("length", 0)
            location = res.get("location", "")
            note = "interesting" if status in interesting else "error" if status == 0 else "redirect" if 300 <= status < 400 else ""
            if log_all or note:
                extra = f" -> {location}" if location and note in ("redirect", "interesting") else ""
                result_data = {"time": datetime.now().strftime("%H:%M:%S"), "base": base, "url": url if mode == "directory" else f"{word}.{base_parsed.netloc}/", "status": status, "length": length, "note": note + extra}
                self.results.append(result_data)
                self.app.ui_queue.put(("brute_result", result_data))
        self.log(f"Completed {base}: {count} requests")


class OSINTEngine:
    def __init__(self, app):
        self.app = app
        self.stop_event = threading.Event()
        self.running = False
        self.proxy_url = None
        self.verify = True

    def log(self, msg): self.app.ui_queue.put(("log", f"[osint] {msg}"))
    def stop(self): self.stop_event.set()

    def start(self, target_url, opts):
        if self.running: return
        self.stop_event.clear()
        self.proxy_url = opts.get("proxy_url")
        self.verify = opts.get("verify_tls", True)
        threading.Thread(target=self._run, args=(target_url, opts), daemon=True).start()

    def _get_root_domain(self, host):
        parts = host.split('.')
        if len(parts) > 2 and parts[-2] in ('co', 'com', 'net', 'org', 'gov', 'edu', 'ac') and len(parts) > 3:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    def _is_valid_osint_url(self, url, target_host, root_domain):
        try:
            if not url.startswith("http"): return False
            p = urlsplit(url)
            host = p.hostname
            if not host: return False
            host = host.lower()
            target_host = target_host.lower()
            root_domain = root_domain.lower()
            if host == target_host or host == root_domain: return True
            if host.endswith("." + root_domain): return True
            return False
        except Exception:
            return False

    def _fetch_crtsh(self, domain, found_urls):
        self.log("Querying crt.sh (Certificate Transparency)...")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        cj = http.cookiejar.CookieJar()
        context = None if self.verify else ssl._create_unverified_context()
        handlers = []
        if self.proxy_url: handlers.append(ProxyHandler({'http': self.proxy_url, 'https': self.proxy_url}))
        handlers.append(HTTPCookieProcessor(cj))
        handlers.append(HTTPSHandler(context=context))
        opener = build_opener(*handlers)
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            resp = opener.open(req, timeout=20)
            text = resp.read(5000000).decode('utf-8', errors='ignore')
            if text.strip().startswith("["):
                data = json.loads(text)
                for entry in data:
                    names = entry.get("name_value", "")
                    for n in names.split("\n"):
                        n = n.strip().lower().replace("*.", "")
                        if n and not n.startswith("*"):
                            found_urls[f"http://{n}"] = "crt.sh"
        except Exception as e:
            self.log(f"crt.sh parse error: {e}")

    def _fetch_wayback(self, target_host, root_domain, found_urls):
        self.log("Querying Wayback Machine (CDX API)...")
        urls_to_query = [
            f"http://web.archive.org/cdx/search/cdx?url=*.{root_domain}/*&output=json&fl=original&collapse=urlkey&limit=5000",
            f"http://web.archive.org/cdx/search/cdx?url={target_host}/*&output=json&fl=original&collapse=urlkey&limit=5000"
        ]
        cj = http.cookiejar.CookieJar()
        context = None if self.verify else ssl._create_unverified_context()
        handlers = []
        if self.proxy_url: handlers.append(ProxyHandler({'http': self.proxy_url, 'https': self.proxy_url}))
        handlers.append(HTTPCookieProcessor(cj))
        handlers.append(HTTPSHandler(context=context))
        opener = build_opener(*handlers)
        for q_url in urls_to_query:
            if self.stop_event.is_set(): break
            req = Request(q_url, headers={"User-Agent": "Mozilla/5.0"})
            try:
                resp = opener.open(req, timeout=30)
                text = resp.read(10000000).decode('utf-8', errors='ignore')
                if text.strip().startswith("["):
                    data = json.loads(text)
                    for row in data[1:]:
                        if row and len(row) > 0:
                            found_urls[row[0]] = "wayback"
            except Exception:
                pass

    def _fetch_ddg(self, target_host, root_domain, found_urls):
        self.log("Querying DuckDuckGo (via ddgs library)...")
        if not DDGS_AVAILABLE:
            self.log("DDG Error: 'duckduckgo-search' library not found. Run: pip install duckduckgo-search")
            return
        try:
            with DDGS() as ddgs:
                results = ddgs.text(f"site:{root_domain}", max_results=200)
                count = 0
                for r in results:
                    url = r.get("href")
                    if url:
                        found_urls[url] = "ddg"
                        count += 1
                self.log(f"DDG: Found {count} raw URLs.")
        except Exception as e:
            self.log(f"DDG library error: {e}")

    def _run(self, target_url, opts):
        self.running = True
        try:
            parsed = urlsplit(target_url)
            target_host = parsed.hostname
            if not target_host: return
            root_domain = self._get_root_domain(target_host)
            self.log(f"Target Host: {target_host} | Root Domain: {root_domain}")
            engines = []
            if opts.get("crtsh"): engines.append(("crt.sh", self._fetch_crtsh, (root_domain,)))
            if opts.get("wayback"): engines.append(("Wayback", self._fetch_wayback, (target_host, root_domain)))
            if opts.get("ddg"): engines.append(("DuckDuckGo", self._fetch_ddg, (target_host, root_domain)))
            total = len(engines)
            found_urls = {}
            for i, (name, func, args) in enumerate(engines):
                if self.stop_event.is_set(): break
                self.app.ui_queue.put(("osint_progress", (i, total, f"Querying {name}...")))
                func(*args, found_urls)
            self.app.ui_queue.put(("osint_progress", (total, total, "Validating strict matches...")))
            self.log(f"Raw OSINT found: {len(found_urls)} URLs. Validating strictly...")
            valid_items = []
            for u, src in found_urls.items():
                if self.stop_event.is_set(): break
                if self._is_valid_osint_url(u, target_host, root_domain):
                    valid_items.append((u, src))
            self.log(f"Validated {len(valid_items)} strict matches.")
            self.app.ui_queue.put(("osint_done", valid_items))
        except Exception as e:
            self.log(f"OSINT Error: {e}")
        finally:
            self.running = False


class ReconWeaveApp:
    def __init__(self, root):
        self.root = root
        self.ui_queue = queue.Queue()
        self.wordlists = {}
        self.subdomain_wordlists = {}
        self.load_config()
        self.crawler = Crawler(self)
        self.bruter = BruteEngine(self)
        self.osint = OSINTEngine(self)

        self.target_var = tk.StringVar(value="http://127.0.0.1:8000")
        self.auth_var = tk.BooleanVar(value=False)
        self.proxy_var = tk.StringVar(value="")
        self.max_depth_var = tk.StringVar(value="0")
        self.max_pages_var = tk.StringVar(value="150")
        self.delay_var = tk.StringVar(value="0.25")
        self.timeout_var = tk.StringVar(value="8")
        self.ua_var = tk.StringVar(value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        self.include_subdomains_var = tk.BooleanVar(value=False)
        self.verify_tls_var = tk.BooleanVar(value=True)
        self.parse_robots_var = tk.BooleanVar(value=True)
        self.parse_sitemap_var = tk.BooleanVar(value=True)
        self.crawl_sitemap_var = tk.BooleanVar(value=True)
        self.crawl_robots_var = tk.BooleanVar(value=False)
        self.fetch_js_var = tk.BooleanVar(value=True)
        self.extract_js_var = tk.BooleanVar(value=True)
        self.visit_discovered_var = tk.BooleanVar(value=True)
        self.osint_crtsh_var = tk.BooleanVar(value=True)
        self.osint_wayback_var = tk.BooleanVar(value=True)
        self.osint_ddg_var = tk.BooleanVar(value=True)
        self.osint_show_subs_var = tk.BooleanVar(value=True)
        self.osint_show_dirs_var = tk.BooleanVar(value=True)
        self.osint_search_var = tk.StringVar()
        self.brute_wordlist_var = tk.StringVar(value="builtin:common")
        self.brute_threads_var = tk.StringVar(value="5")
        self.brute_delay_var = tk.StringVar(value="0.20")
        self.brute_max_var = tk.StringVar(value="500")
        self.brute_statuses_var = tk.StringVar(value=STATUS_DEFAULT)
        self.brute_mode_var = tk.StringVar(value="sequential")
        self.brute_log_all_var = tk.BooleanVar(value=False)
        self.subdomain_wordlist_var = tk.StringVar(value="builtin:subdomains")
        self.subdomain_target_var = tk.StringVar(value="example.com")
        self.wl_name_var = tk.StringVar()
        self.wl_path_var = tk.StringVar()
        self.sub_wl_name_var = tk.StringVar()
        self.sub_wl_path_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready. Confirm authorization before active testing.")
        self.stats_var = tk.StringVar(value="Pages: 0 | Dirs: 0 | Params: 0 | Links: 0")
        self.brute_progress_var = tk.StringVar(value="0 / 0 requests sent")
        self.brute_progress_bar_var = tk.DoubleVar(value=0)

        self.results_view_mode = tk.StringVar(value="grouped")
        self.graph_style_var = tk.StringVar(value="OSINT Radial (interactive)")

        self.theme_fg = "#c9d1d9"
        self.theme_bg = "#0d1117"
        self.theme_accent = "#58a6ff"
        self.diagram_target_fill = "#1f6feb"
        self.diagram_target_outline = "#58a6ff"
        self.diagram_cat_fill = "#21262d"
        self.diagram_cat_outline = "#8b949e"
        self.diagram_page_fill = "#30363d"
        self.diagram_page_outline = "#8b949e"
        self.diagram_line_fill = "#484f58"

        self.graph_nodes = []
        self.graph_edges = []
        self.graph_scale = 1.0
        self.graph_offset = [0.0, 0.0]
        self.drag_node = None
        self.drag_last = None
        self.pan_last = None
        self.tooltip = None
        self.tree_line_paths = {}
        self.tree_dir_lines = []
        self.osint_raw_data = []
        self.osint_structured = {}

        self.build_ui()
        self.root.after(120, self.process_queue)
        self.root.after(2000, self.auto_refresh_graph)
        self.update_stats()

    def auto_refresh_graph(self):
        if self.graph_style_var.get().startswith("OSINT"):
            if self.diagram_canvas.winfo_ismapped():
                self.draw_osint_graph()
        else:
            if hasattr(self, "tree_frame") and self.tree_frame.winfo_ismapped():
                self.build_tree_text()
        self.root.after(2000, self.auto_refresh_graph)

    def update_stats(self):
        res = self.crawler.results
        p = len(res.get("pages", []))
        d = len(res.get("directories", []))
        pr = len(res.get("parameters", []))
        l = len(res.get("links", []))
        s = len(res.get("secrets", []))
        self.stats_var.set(f"Pages: {p} | Dirs: {d} | Params: {pr} | Links: {l} | Secrets: {s}")
        self.root.after(1000, self.update_stats)

    def load_config(self):
        try:
            if CONFIG_FILE.exists():
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    if isinstance(data.get("wordlists"), dict):
                        self.wordlists = data["wordlists"]
                    if isinstance(data.get("subdomain_wordlists"), dict):
                        self.subdomain_wordlists = data["subdomain_wordlists"]
        except Exception: pass
        if not self.wordlists: self.wordlists = {"common": "builtin:common"}
        if not self.subdomain_wordlists: self.subdomain_wordlists = {"subdomains": "builtin:subdomains"}

    def save_config(self):
        try: CONFIG_FILE.write_text(json.dumps({"wordlists": self.wordlists, "subdomain_wordlists": self.subdomain_wordlists}, indent=2), encoding="utf-8")
        except Exception as e: messagebox.showerror(APP_NAME, f"Could not save config: {e}")

    def apply_theme(self, theme_name):
        style = ttk.Style(self.root)
        try: style.theme_use('clam')
        except tk.TclError: pass

        if theme_name == "Light":
            bg, fg, select_bg, select_fg = "#ffffff", "#24292f", "#0969da", "#ffffff"
            text_bg, text_fg = "#f6f8fa", "#24292f"
            tree_bg, tree_fg = "#ffffff", "#24292f"
            tree_selected_bg, tree_selected_fg = "#0969da", "#ffffff"
            entry_bg, border_color = "#ffffff", "#d0d7de"
            tab_bg, tab_selected_bg = "#f6f8fa", "#ffffff"
            self.theme_accent = "#0969da"
            self.diagram_target_fill, self.diagram_target_outline = "#ddf4ff", "#0969da"
            self.diagram_cat_fill, self.diagram_cat_outline = "#f2f2f7", "#57606a"
            self.diagram_page_fill, self.diagram_page_outline = "#eaeef2", "#57606a"
            self.diagram_line_fill = "#57606a"
        elif theme_name == "Dark":
            bg, fg, select_bg, select_fg = "#0d1117", "#c9d1d9", "#1f6feb", "#ffffff"
            text_bg, text_fg = "#010409", "#c9d1d9"
            tree_bg, tree_fg = "#0d1117", "#c9d1d9"
            tree_selected_bg, tree_selected_fg = "#1f6feb", "#ffffff"
            entry_bg, border_color = "#161b22", "#30363d"
            tab_bg, tab_selected_bg = "#161b22", "#0d1117"
            self.theme_accent = "#58a6ff"
            self.diagram_target_fill, self.diagram_target_outline = "#1f6feb", "#58a6ff"
            self.diagram_cat_fill, self.diagram_cat_outline = "#21262d", "#8b949e"
            self.diagram_page_fill, self.diagram_page_outline = "#30363d", "#8b949e"
            self.diagram_line_fill = "#484f58"
        elif theme_name == "Cyber":
            bg, fg, select_bg, select_fg = "#0a0a0a", "#00ff41", "#008f11", "#000000"
            text_bg, text_fg = "#000000", "#00ff41"
            tree_bg, tree_fg = "#000000", "#00ff41"
            tree_selected_bg, tree_selected_fg = "#008f11", "#000000"
            entry_bg, border_color = "#111111", "#00ff41"
            tab_bg, tab_selected_bg = "#111111", "#0a0a0a"
            self.theme_accent = "#00ff41"
            self.diagram_target_fill, self.diagram_target_outline = "#003300", "#00ff41"
            self.diagram_cat_fill, self.diagram_cat_outline = "#112211", "#008f11"
            self.diagram_page_fill, self.diagram_page_outline = "#002200", "#00cc33"
            self.diagram_line_fill = "#00ff41"
        else: return

        self.theme_bg, self.theme_fg = bg, fg
        self.root.configure(bg=bg)

        style.configure('.', background=bg, foreground=fg, fieldbackground=entry_bg, bordercolor=border_color)
        style.configure('TFrame', background=bg)
        style.configure('TLabel', background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure('TButton', background=bg, foreground=fg, bordercolor=border_color, padding=6)
        style.map('TButton', background=[('active', select_bg)], foreground=[('active', select_fg)])
        style.configure('TCheckbutton', background=bg, foreground=fg)
        style.map('TCheckbutton', background=[('active', bg)], indicatorcolor=[('selected', select_bg)])
        style.configure('TRadiobutton', background=bg, foreground=fg)
        style.map('TRadiobutton', background=[('active', bg)], indicatorcolor=[('selected', select_bg)])
        style.configure('TEntry', fieldbackground=entry_bg, foreground=fg, bordercolor=border_color, insertcolor=fg, padding=6)
        style.configure('TCombobox', fieldbackground=entry_bg, foreground=fg, bordercolor=border_color, selectbackground=select_bg, selectforeground=select_fg)
        style.configure('TLabelframe', background=bg, foreground=fg, bordercolor=border_color)
        style.configure('TLabelframe.Label', background=bg, foreground=fg, font=("Segoe UI", 11, "bold"))
        style.configure('TNotebook', background=bg, bordercolor=border_color)
        style.configure('TNotebook.Tab', background=tab_bg, foreground=fg, padding=[14, 8], bordercolor=border_color, font=("Segoe UI", 10, "bold"))
        style.map('TNotebook.Tab', background=[('selected', tab_selected_bg)], foreground=[('selected', fg)], expand=[('selected', [1, 1, 1, 0])])
        style.configure('Treeview', background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg, bordercolor=border_color, rowheight=30, font=("Consolas", 10))
        style.map('Treeview', background=[('selected', tree_selected_bg)], foreground=[('selected', tree_selected_fg)])
        style.configure('Treeview.Heading', background=tab_bg, foreground=fg, font=('Segoe UI', 10, 'bold'))
        style.configure("OSINT.Horizontal.TProgressbar", troughcolor=border_color, background=self.theme_accent, bordercolor=bg, lightcolor=self.theme_accent, darkcolor=self.theme_accent, thickness=16)
        style.configure("Brute.Horizontal.TProgressbar", troughcolor=border_color, background=self.theme_accent, bordercolor=bg, lightcolor=self.theme_accent, darkcolor=self.theme_accent, thickness=16)

        if hasattr(self, 'log_text'):
            self.log_text.configure(bg=text_bg, fg=text_fg, insertbackground=fg, selectbackground=select_bg, selectforeground=select_fg, font=("Consolas", 10))
        if hasattr(self, 'tree_text'):
            self.tree_text.configure(bg=text_bg, fg=text_fg, insertbackground=fg, selectbackground=select_bg, selectforeground=select_fg)
            self.tree_text.tag_configure("dir", foreground=self.theme_accent, font=("Consolas", 11, "bold"))
            self.tree_text.tag_configure("param", foreground="#f0883e", font=("Consolas", 10, "italic"))
            self.tree_text.tag_configure("status", foreground="#7ee787", font=("Consolas", 10, "bold"))
        if hasattr(self, 'diagram_canvas'):
            self.diagram_canvas.configure(bg=text_bg)
            self.refresh_diagram()
        if hasattr(self, 'wordlist_box'):
            self.wordlist_box.configure(bg=text_bg, fg=text_fg, selectbackground=select_bg, selectforeground=select_fg, font=("Segoe UI", 10))
        if hasattr(self, 'subdomain_wordlist_box'):
            self.subdomain_wordlist_box.configure(bg=text_bg, fg=text_fg, selectbackground=select_bg, selectforeground=select_fg, font=("Segoe UI", 10))

    def build_ui(self):
        self.root.title(f"{APP_NAME} - Attack Surface Mapper | {CREDIT}")
        self.root.geometry("1380x850")
        self.root.minsize(1000, 650)

        header = ttk.Frame(self.root, padding=(10, 6))
        header.pack(fill="x")

        ttk.Label(header, text="ReconWeave", font=("Segoe UI", 18, "bold"), foreground=self.theme_accent).pack(side="left")
        ttk.Label(header, text=CREDIT, font=("Segoe UI", 9)).pack(side="left", padx=15)

        theme_frame = ttk.Frame(header)
        theme_frame.pack(side="right")
        ttk.Label(theme_frame, text="Theme:").pack(side="left", padx=(0, 5))
        self.theme_var = tk.StringVar(value="Dark")
        theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_var, values=["Light", "Dark", "Cyber"], state="readonly", width=10)
        theme_combo.pack(side="left")
        theme_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_theme(self.theme_var.get()))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=6)

        self.tab_crawl = ttk.Frame(self.notebook)
        self.tab_results = ttk.Frame(self.notebook)
        self.tab_brute = ttk.Frame(self.notebook)
        self.tab_osint = ttk.Frame(self.notebook)
        self.tab_secrets = ttk.Frame(self.notebook)
        self.tab_wordlists = ttk.Frame(self.notebook)
        self.tab_diagram = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_crawl, text="▶ Crawl")
        self.notebook.add(self.tab_results, text="📊 Results & Headers")
        self.notebook.add(self.tab_brute, text="💥 Brute Session")
        self.notebook.add(self.tab_osint, text="🌐 OSINT & Dorking")
        self.notebook.add(self.tab_secrets, text="🔐 Secrets & Creds")
        self.notebook.add(self.tab_wordlists, text="⚙ Wordlists / Config")
        self.notebook.add(self.tab_diagram, text="🕸 Graph & Tree View")

        self.build_crawl_tab()
        self.build_results_tab()
        self.build_brute_tab()
        self.build_osint_tab()
        self.build_secrets_tab()
        self.build_wordlists_tab()
        self.build_diagram_tab()

        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken", padding=(8, 4))
        status_bar.pack(side="bottom", fill="x")

        self.apply_theme("Dark")

    def show_unified_context_menu(self, event, url=None, path=None, extra_label=None, extra_cmd=None):
        menu = tk.Menu(self.root, tearoff=0)
        if extra_label:
            menu.add_command(label=extra_label, command=extra_cmd)
            menu.add_separator()
        if url:
            menu.add_command(label="📋 Copy URL", command=lambda: self.copy_to_clipboard(url))
            menu.add_command(label="🌐 Open in Browser", command=lambda: self.open_in_browser(url))
            menu.add_separator()
            menu.add_command(label="🛠 Copy as FFUF command", command=lambda: self.copy_ffuf(url))
            menu.add_command(label="💥 Send to Brute Session", command=lambda: self.send_url_to_brute(url))
        if path:
            menu.add_command(label=f"📋 Copy Path", command=lambda: self.copy_to_clipboard(path))
            menu.add_command(label="💥 Brute this Path", command=lambda: self.brute_result_path(path))
        if not url and not path and not extra_label:
            menu.add_command(label="No actionable item", state="disabled")
        menu.tk_popup(event.x_root, event.y_root)

    def send_url_to_brute(self, url):
        self.notebook.select(self.tab_brute)
        base = self._abs_base(url)
        self.found_tree.insert("", 0, values=(base, "manual"))
        if self.found_tree.get_children():
            self.found_tree.selection_set(self.found_tree.get_children()[0])
        self.status_var.set(f"Sent {base} to Brute Session.")

    def on_osint_hosts_right_click(self, event):
        item = self.osint_hosts_tree.identify_row(event.y)
        if not item: return
        self.osint_hosts_tree.selection_set(item)
        host = item
        url = f"http://{host}"
        self.show_unified_context_menu(event, url=url)

    def on_osint_dirs_right_click(self, event):
        item = self.osint_dirs_tree.identify_row(event.y)
        if not item: return
        self.osint_dirs_tree.selection_set(item)
        url = item
        path = self.osint_dirs_tree.item(item, "values")[0]
        self.show_unified_context_menu(event, url=url, path=path)

    def on_found_tree_right_click(self, event):
        item = self.found_tree.identify_row(event.y)
        if not item: return
        self.found_tree.selection_set(item)
        vals = self.found_tree.item(item, "values")
        if vals:
            url = str(vals[0])
            self.show_unified_context_menu(event, url=url, path=url)

    def on_brute_tree_right_click(self, event):
        item = self.brute_tree.identify_row(event.y)
        if not item: return
        self.brute_tree.selection_set(item)
        vals = self.brute_tree.item(item, "values")
        if vals and len(vals) >= 3:
            url = str(vals[2])
            self.show_unified_context_menu(event, url=url)

    def build_crawl_tab(self):
        tab = self.tab_crawl
        container = ttk.Frame(tab, padding=10)
        container.pack(fill="x")

        ttk.Label(container, textvariable=self.stats_var, font=("Segoe UI", 11, "bold"), foreground=self.theme_accent).pack(anchor="w", pady=(0, 10))

        target_card = ttk.LabelFrame(container, text="Target Configuration", padding=12)
        target_card.pack(fill="x", pady=(0, 10))
        target_card.columnconfigure(1, weight=1)

        ttk.Label(target_card, text="Target URL:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(target_card, textvariable=self.target_var, font=("Consolas", 11)).grid(row=0, column=1, sticky="we", padx=(0, 10))

        ttk.Label(target_card, text="Proxy (e.g. http://127.0.0.1:8080):").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
        ttk.Entry(target_card, textvariable=self.proxy_var, font=("Consolas", 11)).grid(row=1, column=1, sticky="we", padx=(0, 10), pady=(10, 0))

        ttk.Checkbutton(target_card, text="✓ I confirm written authorization for this target", variable=self.auth_var).grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))

        opts_card = ttk.LabelFrame(container, text="Crawl Options", padding=12)
        opts_card.pack(fill="x")

        fields = [("Max depth (0=unlimited)", self.max_depth_var, 0, 0), ("Max pages", self.max_pages_var, 0, 2), ("Delay sec", self.delay_var, 0, 4), ("Timeout sec", self.timeout_var, 0, 6)]
        for label, var, row, col in fields:
            ttk.Label(opts_card, text=label).grid(row=row, column=col, sticky="e", padx=4, pady=4)
            ttk.Entry(opts_card, textvariable=var, width=10).grid(row=row, column=col + 1, sticky="w")

        ttk.Label(opts_card, text="User-Agent").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(opts_card, textvariable=self.ua_var).grid(row=1, column=1, columnspan=5, sticky="we")
        opts_card.columnconfigure(2, weight=1)

        checks_row1 = ttk.Frame(opts_card)
        checks_row1.grid(row=2, column=0, columnspan=6, sticky="w", pady=(10, 0))
        ttk.Checkbutton(checks_row1, text="Include subdomains", variable=self.include_subdomains_var).pack(side="left", padx=10)
        ttk.Checkbutton(checks_row1, text="Verify TLS", variable=self.verify_tls_var).pack(side="left", padx=10)
        ttk.Checkbutton(checks_row1, text="Parse robots.txt", variable=self.parse_robots_var).pack(side="left", padx=10)
        ttk.Checkbutton(checks_row1, text="Parse sitemap", variable=self.parse_sitemap_var).pack(side="left", padx=10)

        checks_row2 = ttk.Frame(opts_card)
        checks_row2.grid(row=3, column=0, columnspan=6, sticky="w", pady=(4, 0))
        ttk.Checkbutton(checks_row2, text="Crawl sitemap URLs", variable=self.crawl_sitemap_var).pack(side="left", padx=10)
        ttk.Checkbutton(checks_row2, text="Crawl robots paths", variable=self.crawl_robots_var).pack(side="left", padx=10)
        ttk.Checkbutton(checks_row2, text="Fetch JS files", variable=self.fetch_js_var).pack(side="left", padx=10)
        ttk.Checkbutton(checks_row2, text="Extract JS endpoints", variable=self.extract_js_var).pack(side="left", padx=10)
        ttk.Checkbutton(checks_row2, text="Visit discovered paths/files", variable=self.visit_discovered_var).pack(side="left", padx=10)

        buttons = ttk.Frame(container)
        buttons.pack(fill="x", pady=15)
        self.crawl_start_btn = ttk.Button(buttons, text="▶ Start Crawl", command=self.start_crawl)
        self.crawl_start_btn.pack(side="left")
        ttk.Button(buttons, text="🌐 Use Passive Enum Findings", command=self.show_subdomain_crawl_dialog).pack(side="left", padx=8)
        self.crawl_stop_btn = ttk.Button(buttons, text="■ Stop Crawl", command=self.stop_crawl, state="disabled")
        self.crawl_stop_btn.pack(side="left", padx=8)
        ttk.Button(buttons, text="✕ Clear Log", command=self.clear_log).pack(side="left")

        self.log_text = scrolledtext.ScrolledText(tab, wrap="none", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def show_subdomain_crawl_dialog(self):
        if not self.osint_structured:
            messagebox.showinfo(APP_NAME, "No passive recon data found.\n\nPlease go to the 'OSINT & Dorking' tab and run a discovery first.")
            return

        msg = ("⚠️ WARNING: ACTIVE RECON INITIATION ⚠️\n\n"
               "Crawling these subdomains will send direct HTTP requests from your IP address to the targets.\n"
               "This is considered ACTIVE reconnaissance.\n\n"
               "Ensure you have explicit written authorization for ALL selected subdomains.\n\n"
               "Do you want to proceed to target selection?")
        if not messagebox.askyesno("Active Recon Warning", msg, icon="warning"):
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Select Subdomains to Crawl")
        dialog.geometry("450x550")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Select subdomains to include in the active crawl:", font=("Segoe UI", 11, "bold")).pack(pady=10)

        vars_dict = {}
        frame = ttk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=20, pady=10)

        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        for host in sorted(self.osint_structured.keys()):
            var = tk.BooleanVar(value=True)
            vars_dict[host] = var
            ttk.Checkbutton(scrollable_frame, text=host, variable=var).pack(anchor="w", pady=2)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", padx=20, pady=15)

        def select_all():
            for v in vars_dict.values(): v.set(True)

        def select_none():
            for v in vars_dict.values(): v.set(False)

        ttk.Button(btn_frame, text="Select All", command=select_all).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Select None", command=select_none).pack(side="left", padx=5)

        def start_crawl_selected():
            selected = [h for h, v in vars_dict.items() if v.get()]
            if not selected:
                messagebox.showerror(APP_NAME, "Please select at least one subdomain.")
                return
            base_target = self.target_var.get().strip()
            if not base_target.startswith("http"): base_target = "https://" + base_target
            opts = self._crawl_opts()
            opts["allowed_hosts"] = selected
            dialog.destroy()
            self.crawl_start_btn.config(state="disabled")
            self.crawl_stop_btn.config(state="normal")
            self.status_var.set(f"Crawling {len(selected)} subdomains...")
            threading.Thread(target=self.crawler.run, args=(base_target, opts), daemon=True).start()

        ttk.Button(btn_frame, text="▶ Start Active Crawl", command=start_crawl_selected).pack(side="right", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side="right", padx=5)

    def build_results_tab(self):
        tab = self.tab_results
        toolbar = ttk.Frame(tab, padding=6)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="⟳ Refresh", command=self.refresh_results).pack(side="left")
        ttk.Button(toolbar, text="⬇ Export JSON", command=self.export_results_json).pack(side="left", padx=6)
        ttk.Button(toolbar, text="✕ Clear Results", command=self.clear_results).pack(side="left")

        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Radiobutton(toolbar, text="Grouped Tree", variable=self.results_view_mode, value="grouped", command=self.refresh_results).pack(side="left")
        ttk.Radiobutton(toolbar, text="Flat Table", variable=self.results_view_mode, value="flat", command=self.refresh_results).pack(side="left")

        ttk.Label(toolbar, text="Right-click a path/URL to interact.").pack(side="right")

        frame = ttk.Frame(tab)
        frame.pack(fill="both", expand=True)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.results_tree = ttk.Treeview(frame, columns=("type", "value", "detail"), show="headings")
        self.results_tree.heading("type", text="Type")
        self.results_tree.heading("value", text="Value / Path")
        self.results_tree.heading("detail", text="Detail")
        self.results_tree.column("type", width=130, stretch=False)
        self.results_tree.column("value", width=560)
        self.results_tree.column("detail", width=350)

        vbar = ttk.Scrollbar(frame, orient="vertical", command=self.results_tree.yview)
        hbar = ttk.Scrollbar(frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        self.results_tree.bind("<Button-3>", self.on_results_right_click)

    def build_brute_tab(self):
        tab = self.tab_brute
        found_lf = ttk.LabelFrame(tab, text="Found directories / paths", padding=8)
        found_lf.pack(fill="x", padx=8, pady=4)
        found_inner = ttk.Frame(found_lf)
        found_inner.pack(fill="x")

        self.found_tree = ttk.Treeview(found_inner, columns=("path", "source"), show="headings", height=6)
        self.found_tree.heading("path", text="Path / base")
        self.found_tree.heading("source", text="Source")
        self.found_tree.column("path", width=520)
        self.found_tree.column("source", width=160)
        found_vbar = ttk.Scrollbar(found_inner, orient="vertical", command=self.found_tree.yview)
        self.found_tree.configure(yscrollcommand=found_vbar.set)
        self.found_tree.pack(side="left", fill="both", expand=True)
        found_vbar.pack(side="right", fill="y")
        self.found_tree.bind("<Button-3>", self.on_found_tree_right_click)

        btns = ttk.Frame(found_lf)
        btns.pack(fill="x", pady=8)
        ttk.Button(btns, text="⟳ Refresh Found", command=self.refresh_found_dirs).pack(side="left")
        self.brute_start_selected_btn = ttk.Button(btns, text="▶ Brute Selected", command=self.start_brute_selected)
        self.brute_start_selected_btn.pack(side="left", padx=6)
        self.brute_start_all_btn = ttk.Button(btns, text="▶ Brute All Found Dirs", command=self.start_brute_all)
        self.brute_start_all_btn.pack(side="left")
        self.brute_stop_btn = ttk.Button(btns, text="■ Stop Brute", command=self.stop_brute, state="disabled")
        self.brute_stop_btn.pack(side="left", padx=6)
        ttk.Button(btns, text="✕ Clear Brute Results", command=self.clear_brute_results).pack(side="left")
        ttk.Button(btns, text="⬇ Export Results", command=self.export_brute_results).pack(side="left", padx=6)

        # Subdomain brute section
        subdomain_card = ttk.LabelFrame(tab, text="Subdomain Brute", padding=8)
        subdomain_card.pack(fill="x", padx=8, pady=4)
        subdomain_inner = ttk.Frame(subdomain_card)
        subdomain_inner.pack(fill="x")

        ttk.Label(subdomain_inner, text="Target Domain:").pack(side="left", padx=4)
        ttk.Entry(subdomain_inner, textvariable=self.subdomain_target_var, width=30).pack(side="left", padx=4)
        ttk.Label(subdomain_inner, text="Subdomain Wordlist:").pack(side="left", padx=4)
        self.subdomain_wordlist_combo = ttk.Combobox(subdomain_inner, textvariable=self.subdomain_wordlist_var, width=25, values=["builtin:subdomains"])
        self.subdomain_wordlist_combo.pack(side="left", padx=4)
        ttk.Button(subdomain_inner, text="▶ Brute Subdomains", command=self.start_subdomain_brute).pack(side="left", padx=6)

        controls = ttk.LabelFrame(tab, text="Brute configuration", padding=8)
        controls.pack(fill="x", padx=8, pady=4)
        row1 = ttk.Frame(controls)
        row1.pack(fill="x")
        ttk.Label(row1, text="Wordlist").pack(side="left")
        self.wordlist_combo = ttk.Combobox(row1, textvariable=self.brute_wordlist_var, width=35, values=["builtin:common"])
        self.wordlist_combo.pack(side="left", padx=6)
        ttk.Button(row1, text="⟳ Refresh wordlists", command=self.refresh_wordlist_ui).pack(side="left")
        ttk.Checkbutton(row1, text="Log all responses", variable=self.brute_log_all_var).pack(side="left", padx=12)

        row2 = ttk.Frame(controls)
        row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Threads").pack(side="left")
        ttk.Entry(row2, textvariable=self.brute_threads_var, width=6).pack(side="left", padx=(2, 12))
        ttk.Label(row2, text="Delay sec").pack(side="left")
        ttk.Entry(row2, textvariable=self.brute_delay_var, width=6).pack(side="left", padx=(2, 12))
        ttk.Label(row2, text="Max words/dir").pack(side="left")
        ttk.Entry(row2, textvariable=self.brute_max_var, width=8).pack(side="left", padx=(2, 12))
        ttk.Label(row2, text="Interesting statuses").pack(side="left")
        ttk.Entry(row2, textvariable=self.brute_statuses_var, width=35).pack(side="left", padx=(2, 12))

        row3 = ttk.Frame(controls)
        row3.pack(fill="x", pady=4)
        ttk.Label(row3, text="Mode:").pack(side="left")
        ttk.Radiobutton(row3, text="One-by-one (sequential)", variable=self.brute_mode_var, value="sequential").pack(side="left", padx=6)
        ttk.Radiobutton(row3, text="Simultaneous (parallel thread pool)", variable=self.brute_mode_var, value="parallel").pack(side="left", padx=6)
        ttk.Label(row3, text="Parallel can cause high traffic / DoS; use only in local labs.", foreground="#a00000").pack(side="left", padx=12)

        # Brute progress bar
        progress_frame = ttk.Frame(controls)
        progress_frame.pack(fill="x", pady=4)
        ttk.Label(progress_frame, text="Progress:").pack(side="left")
        ttk.Label(progress_frame, textvariable=self.brute_progress_var).pack(side="left", padx=10)
        self.brute_progress_bar = ttk.Progressbar(controls, orient="horizontal", mode="determinate", style="Brute.Horizontal.TProgressbar")
        self.brute_progress_bar.pack(fill="x", pady=4)

        results_lf = ttk.LabelFrame(tab, text="Brute results", padding=8)
        results_lf.pack(fill="both", expand=True, padx=8, pady=4)
        self.brute_tree = ttk.Treeview(results_lf, columns=("time", "base", "url", "status", "length", "note"), show="headings", height=10)
        self.brute_tree.heading("time", text="Time")
        self.brute_tree.heading("base", text="Base")
        self.brute_tree.heading("url", text="URL")
        self.brute_tree.heading("status", text="Status")
        self.brute_tree.heading("length", text="Length")
        self.brute_tree.heading("note", text="Note")
        self.brute_tree.column("time", width=70, stretch=False)
        self.brute_tree.column("base", width=220)
        self.brute_tree.column("url", width=420)
        self.brute_tree.column("status", width=60, stretch=False)
        self.brute_tree.column("length", width=70, stretch=False)
        self.brute_tree.column("note", width=220)
        brute_vbar = ttk.Scrollbar(results_lf, orient="vertical", command=self.brute_tree.yview)
        self.brute_tree.configure(yscrollcommand=brute_vbar.set)
        self.brute_tree.pack(side="left", fill="both", expand=True)
        brute_vbar.pack(side="right", fill="y")
        self.brute_tree.bind("<Button-3>", self.on_brute_tree_right_click)

    def build_osint_tab(self):
        tab = self.tab_osint
        container = ttk.Frame(tab, padding=10)
        container.pack(fill="x")

        opts_card = ttk.LabelFrame(container, text="Passive OSINT & Dorking Engines", padding=12)
        opts_card.pack(fill="x", pady=(0, 10))

        ttk.Checkbutton(opts_card, text="crt.sh (Subdomains)", variable=self.osint_crtsh_var).pack(side="left", padx=10)
        ttk.Checkbutton(opts_card, text="Wayback Machine (Dirs & Subs)", variable=self.osint_wayback_var).pack(side="left", padx=10)
        ttk.Checkbutton(opts_card, text="DuckDuckGo (Dorks via ddgs)", variable=self.osint_ddg_var).pack(side="left", padx=10)

        filter_card = ttk.LabelFrame(container, text="Filters & Search", padding=12)
        filter_card.pack(fill="x", pady=(0, 10))

        ttk.Checkbutton(filter_card, text="Show Subdomains", variable=self.osint_show_subs_var, command=self.apply_osint_filters).pack(side="left", padx=10)
        ttk.Checkbutton(filter_card, text="Show Directories", variable=self.osint_show_dirs_var, command=self.apply_osint_filters).pack(side="left", padx=10)

        ttk.Label(filter_card, text="Search:").pack(side="left", padx=(20, 5))
        self.osint_search_entry = ttk.Entry(filter_card, textvariable=self.osint_search_var, width=30)
        self.osint_search_entry.pack(side="left")
        self.osint_search_var.trace_add("write", lambda *args: self.apply_osint_filters())

        btns = ttk.Frame(container)
        btns.pack(fill="x", pady=10)
        self.osint_start_btn = ttk.Button(btns, text="▶ Start OSINT Discovery", command=self.start_osint)
        self.osint_start_btn.pack(side="left")
        self.osint_stop_btn = ttk.Button(btns, text="■ Stop OSINT", command=self.stop_osint, state="disabled")
        self.osint_stop_btn.pack(side="left", padx=8)
        self.osint_progress_bar = ttk.Progressbar(btns, orient="horizontal", length=200, mode="determinate", style="OSINT.Horizontal.TProgressbar")
        self.osint_progress_bar.pack(side="left", padx=10, fill="x", expand=True)
        ttk.Button(btns, text="✕ Clear", command=self.clear_osint).pack(side="left", padx=8)
        ttk.Button(btns, text="➕ Send to Brute", command=self.send_osint_to_brute).pack(side="left", padx=8)
        ttk.Button(btns, text="▶ Crawl Selected", command=self.crawl_selected_osint).pack(side="left", padx=8)

        paned = ttk.PanedWindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=6)

        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)

        ttk.Label(left_frame, text="Discovered Subdomains / Hosts", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        self.osint_hosts_tree = ttk.Treeview(left_frame, columns=("host", "dirs_count"), show="headings")
        self.osint_hosts_tree.heading("host", text="Subdomain / Host")
        self.osint_hosts_tree.heading("dirs_count", text="Dirs Found")
        self.osint_hosts_tree.column("host", width=300)
        self.osint_hosts_tree.column("dirs_count", width=100, anchor="center")
        hosts_vbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.osint_hosts_tree.yview)
        self.osint_hosts_tree.configure(yscrollcommand=hosts_vbar.set)
        self.osint_hosts_tree.pack(side="left", fill="both", expand=True)
        hosts_vbar.pack(side="right", fill="y")
        self.osint_hosts_tree.bind("<<TreeviewSelect>>", self.on_osint_host_select)
        self.osint_hosts_tree.bind("<Button-3>", self.on_osint_hosts_right_click)

        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=2)

        ttk.Label(right_frame, text="Directories & Paths", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        self.osint_dirs_tree = ttk.Treeview(right_frame, columns=("path", "source"), show="headings")
        self.osint_dirs_tree.heading("path", text="Directory / Path")
        self.osint_dirs_tree.heading("source", text="Source")
        self.osint_dirs_tree.column("path", width=400)
        self.osint_dirs_tree.column("source", width=150)
        dirs_vbar = ttk.Scrollbar(right_frame, orient="vertical", command=self.osint_dirs_tree.yview)
        dirs_hbar = ttk.Scrollbar(right_frame, orient="horizontal", command=self.osint_dirs_tree.xview)
        self.osint_dirs_tree.configure(yscrollcommand=dirs_vbar.set, xscrollcommand=dirs_hbar.set)
        self.osint_dirs_tree.pack(side="left", fill="both", expand=True)
        dirs_vbar.pack(side="right", fill="y")
        dirs_hbar.pack(side="bottom", fill="x")
        self.osint_dirs_tree.bind("<Button-3>", self.on_osint_dirs_right_click)

    def crawl_selected_osint(self):
        selected_hosts = self.osint_hosts_tree.selection()
        if not selected_hosts:
            messagebox.showinfo(APP_NAME, "Please select one or more subdomains from the list first.")
            return

        msg = ("⚠️ WARNING: ACTIVE RECON INITIATION ⚠️\n\n"
               "Crawling these subdomains will send direct HTTP requests from your IP address to the targets.\n"
               "This is considered ACTIVE reconnaissance.\n\n"
               "Ensure you have explicit written authorization for ALL selected subdomains.\n\n"
               "Continue?")
        if not messagebox.askyesno("Active Recon Warning", msg, icon="warning"):
            return

        base_target = self.target_var.get().strip()
        if not base_target.startswith("http"): base_target = "https://" + base_target

        opts = self._crawl_opts()
        opts["allowed_hosts"] = list(selected_hosts)

        self.crawl_start_btn.config(state="disabled")
        self.crawl_stop_btn.config(state="normal")
        self.status_var.set(f"Crawling {len(selected_hosts)} subdomains...")

        self.notebook.select(self.tab_crawl)
        threading.Thread(target=self.crawler.run, args=(base_target, opts), daemon=True).start()

    def apply_osint_filters(self, *args):
        search_term = self.osint_search_var.get().strip().lower()
        show_subs = self.osint_show_subs_var.get()
        show_dirs = self.osint_show_dirs_var.get()

        structured = {}
        target_host = ""
        try: target_host = urlsplit(self.target_var.get().strip()).hostname or ""
        except: pass

        for url, src in self.osint_raw_data:
            try:
                p = urlsplit(url)
                host = p.hostname or ""
                path = p.path or "/"
                if not host: continue
                if host not in structured:
                    structured[host] = {"dirs": {}, "is_sub": (host != target_host)}
                structured[host]["dirs"][path] = (src, url)
            except: pass

        self.osint_structured = structured
        self.osint_hosts_tree.delete(*self.osint_hosts_tree.get_children())

        for host, data in sorted(structured.items()):
            is_sub = data["is_sub"]
            if not show_subs and is_sub: continue
            if search_term:
                host_match = search_term in host.lower()
                paths_match = any(search_term in p.lower() for p in data["dirs"].keys())
                if not host_match and not paths_match: continue
            dirs_count = len(data["dirs"])
            if not show_dirs: dirs_count = 0
            self.osint_hosts_tree.insert("", "end", iid=host, values=(host, dirs_count))

        self.osint_dirs_tree.delete(*self.osint_dirs_tree.get_children())

        if hasattr(self, 'diagram_canvas') and self.graph_style_var.get().startswith("OSINT"):
            self.draw_osint_graph()

    def on_osint_host_select(self, event):
        selected = self.osint_hosts_tree.selection()
        if not selected: return
        host = selected[0]
        self.osint_dirs_tree.delete(*self.osint_dirs_tree.get_children())
        if not self.osint_show_dirs_var.get(): return
        data = self.osint_structured.get(host, {})
        search_term = self.osint_search_var.get().strip().lower()
        for path, (src, full_url) in sorted(data.get("dirs", {}).items()):
            if search_term and search_term not in path.lower() and search_term not in host.lower(): continue
            self.osint_dirs_tree.insert("", "end", iid=full_url, values=(path, src))

    def start_osint(self):
        if not self.auth_var.get():
            messagebox.showerror(APP_NAME, "You must confirm authorization for the target.")
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror(APP_NAME, "Target URL is required.")
            return

        opts = {
            "crtsh": self.osint_crtsh_var.get(), "wayback": self.osint_wayback_var.get(),
            "ddg": self.osint_ddg_var.get(), "proxy_url": self.proxy_var.get().strip() or None,
            "verify_tls": self.verify_tls_var.get()
        }

        self.osint_start_btn.config(state="disabled")
        self.osint_stop_btn.config(state="normal")
        self.osint_progress_bar['value'] = 0
        self.status_var.set("Running OSINT...")
        self.osint.start(target, opts)

    def stop_osint(self):
        self.osint.stop()
        self.status_var.set("Stopping OSINT...")

    def clear_osint(self):
        self.osint_raw_data = []
        self.osint_structured = {}
        self.osint_hosts_tree.delete(*self.osint_hosts_tree.get_children())
        self.osint_dirs_tree.delete(*self.osint_dirs_tree.get_children())
        self.osint_progress_bar['value'] = 0
        if hasattr(self, 'diagram_canvas'): self.refresh_diagram()

    def send_osint_to_brute(self):
        selected_dirs = self.osint_dirs_tree.selection()
        selected_hosts = self.osint_hosts_tree.selection()
        items_to_send = []
        if selected_dirs:
            for item in selected_dirs: items_to_send.append(item)
        elif selected_hosts:
            for host in selected_hosts:
                data = self.osint_structured.get(host, {})
                for path, (src, full_url) in data.get("dirs", {}).items(): items_to_send.append(full_url)

        if not items_to_send:
            messagebox.showinfo(APP_NAME, "Select Subdomains or Directories to send to Brute Session.")
            return

        self.notebook.select(self.tab_brute)
        for url in items_to_send:
            base = self._abs_base(url)
            self.found_tree.insert("", 0, values=(base, "osint"))

        messagebox.showinfo(APP_NAME, f"Sent {len(items_to_send)} URLs to Brute Session.")

    def start_subdomain_brute(self):
        if not self.auth_var.get():
            messagebox.showerror(APP_NAME, "You must confirm authorization for the target.")
            return

        target_domain = self.subdomain_target_var.get().strip()
        if not target_domain:
            messagebox.showerror(APP_NAME, "Please enter a target domain for subdomain brute.")
            return

        if self.bruter.running:
            messagebox.showinfo(APP_NAME, "Brute engine already running.")
            return

        opts = self._brute_opts()
        self.bruter.start([target_domain], self.subdomain_wordlist_var.get(), opts, mode="subdomain")

        self.brute_start_selected_btn.config(state="disabled")
        self.brute_start_all_btn.config(state="disabled")
        self.brute_stop_btn.config(state="normal")
        self.status_var.set("Subdomain brute started...")

    def export_brute_results(self):
        if not self.bruter.results:
            messagebox.showinfo(APP_NAME, "No brute results to export.")
            return

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json"), ("Text", "*.txt")], initialfile="reconweave_brute_results")
        if not path: return

        try:
            if path.endswith(".txt"):
                with open(path, "w", encoding="utf-8") as f:
                    for r in self.bruter.results:
                        f.write(f"{r['time']} | {r['base']} | {r['url']} | {r['status']} | {r['length']} | {r['note']}\n")
            else:
                Path(path).write_text(json.dumps(self.bruter.results, indent=2, default=str), encoding="utf-8")
            messagebox.showinfo(APP_NAME, f"Brute results exported to:\n{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Export failed: {e}")

    def build_secrets_tab(self):
        tab = self.tab_secrets
        toolbar = ttk.Frame(tab, padding=6)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="⟳ Refresh", command=self.refresh_secrets).pack(side="left")
        ttk.Button(toolbar, text="⬇ Export Secrets", command=self.export_secrets).pack(side="left", padx=6)
        ttk.Button(toolbar, text="✕ Clear", command=self.clear_secrets).pack(side="left")

        frame = ttk.Frame(tab)
        frame.pack(fill="both", expand=True, padx=6, pady=6)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.secrets_tree = ttk.Treeview(frame, columns=("type", "value", "url", "snippet"), show="headings")
        self.secrets_tree.heading("type", text="Type")
        self.secrets_tree.heading("value", text="Value / Secret")
        self.secrets_tree.heading("url", text="Found in URL")
        self.secrets_tree.heading("snippet", text="Context / Snippet")
        self.secrets_tree.column("type", width=120, stretch=False)
        self.secrets_tree.column("value", width=300)
        self.secrets_tree.column("url", width=300)
        self.secrets_tree.column("snippet", width=400)

        vbar = ttk.Scrollbar(frame, orient="vertical", command=self.secrets_tree.yview)
        hbar = ttk.Scrollbar(frame, orient="horizontal", command=self.secrets_tree.xview)
        self.secrets_tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        self.secrets_tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        self.secrets_tree.bind("<Button-3>", self.on_secrets_right_click)

    def refresh_secrets(self):
        self.secrets_tree.delete(*self.secrets_tree.get_children())
        for item in self.crawler.results.get("secrets", []):
            self.secrets_tree.insert("", "end", values=(item.get("type", ""), item.get("value", ""), item.get("url", ""), item.get("snippet", "")))

    def clear_secrets(self):
        self.crawler.results["secrets"] = []
        self.crawler._seen["secrets"] = set()
        self.refresh_secrets()

    def export_secrets(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], initialfile="reconweave_secrets.json")
        if not path: return
        try:
            Path(path).write_text(json.dumps(self.crawler.results.get("secrets", []), indent=2, default=str), encoding="utf-8")
            messagebox.showinfo(APP_NAME, f"Secrets exported to:\n{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Export failed: {e}")

    def on_secrets_right_click(self, event):
        item = self.secrets_tree.identify_row(event.y)
        if not item: return
        self.secrets_tree.selection_set(item)
        values = self.secrets_tree.item(item, "values")
        if not values: return
        val = str(values[1])
        url = str(values[2])
        self.show_unified_context_menu(event, url=url, extra_label="🔐 Copy Secret Value", extra_cmd=lambda: self.copy_to_clipboard(val))

    def build_wordlists_tab(self):
        tab = self.tab_wordlists

        # Directory brute wordlists
        frm = ttk.LabelFrame(tab, text="Directory Brute Wordlists", padding=10)
        frm.pack(fill="x", padx=10, pady=5)
        form = ttk.Frame(frm)
        form.pack(fill="x")
        ttk.Label(form, text="Name").grid(row=0, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.wl_name_var, width=25).grid(row=0, column=1, padx=6)
        ttk.Label(form, text="Path").grid(row=0, column=2, sticky="w", padx=(15, 0))
        ttk.Entry(form, textvariable=self.wl_path_var, width=60).grid(row=0, column=3, padx=6)
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=8)
        ttk.Button(btns, text="➕ Add", command=self.add_wordlist).pack(side="left")
        ttk.Button(btns, text="📁 Browse", command=self.browse_wordlist).pack(side="left", padx=6)
        ttk.Button(btns, text="✕ Remove", command=self.remove_wordlist).pack(side="left")
        ttk.Button(btns, text="💾 Save", command=self.save_wordlists_ui).pack(side="left", padx=6)
        ttk.Button(btns, text="✓ Test selected combo", command=self.test_wordlist).pack(side="left")
        self.wordlist_box = tk.Listbox(tab, height=8, font=("Consolas", 10))
        self.wordlist_box.pack(fill="both", expand=True, padx=10, pady=5)

        # Subdomain brute wordlists
        sub_frm = ttk.LabelFrame(tab, text="Subdomain Brute Wordlists", padding=10)
        sub_frm.pack(fill="x", padx=10, pady=5)
        sub_form = ttk.Frame(sub_frm)
        sub_form.pack(fill="x")
        ttk.Label(sub_form, text="Name").grid(row=0, column=0, sticky="w")
        ttk.Entry(sub_form, textvariable=self.sub_wl_name_var, width=25).grid(row=0, column=1, padx=6)
        ttk.Label(sub_form, text="Path").grid(row=0, column=2, sticky="w", padx=(15, 0))
        ttk.Entry(sub_form, textvariable=self.sub_wl_path_var, width=60).grid(row=0, column=3, padx=6)
        sub_btns = ttk.Frame(sub_frm)
        sub_btns.pack(fill="x", pady=8)
        ttk.Button(sub_btns, text="➕ Add", command=self.add_subdomain_wordlist).pack(side="left")
        ttk.Button(sub_btns, text="📁 Browse", command=self.browse_subdomain_wordlist).pack(side="left", padx=6)
        ttk.Button(sub_btns, text="✕ Remove", command=self.remove_subdomain_wordlist).pack(side="left")
        ttk.Button(sub_btns, text="💾 Save", command=self.save_wordlists_ui).pack(side="left", padx=6)
        ttk.Button(sub_btns, text="✓ Test selected combo", command=self.test_subdomain_wordlist).pack(side="left")
        self.subdomain_wordlist_box = tk.Listbox(tab, height=8, font=("Consolas", 10))
        self.subdomain_wordlist_box.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(tab, text="Path can be a file path or builtin:common/builtin:subdomains. Lines starting with # are ignored.").pack(anchor="w", padx=10)
        self.refresh_wordlist_ui()

    def build_diagram_tab(self):
        tab = self.tab_diagram
        toolbar = ttk.Frame(tab, padding=6)
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="⟳ Draw / Refresh", command=self.refresh_diagram).pack(side="left")
        ttk.Button(toolbar, text="↺ Reset Graph", command=self.reset_graph).pack(side="left", padx=6)

        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Label(toolbar, text="Style:").pack(side="left")
        style_combo = ttk.Combobox(toolbar, textvariable=self.graph_style_var, values=["OSINT Radial (interactive)", "tree command view"], state="readonly", width=24)
        style_combo.pack(side="left", padx=6)
        style_combo.bind("<<ComboboxSelected>>", lambda e: self.set_graph_style())

        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Button(toolbar, text="⬇ Export URLs (.txt)", command=self.export_urls_txt).pack(side="left")
        ttk.Button(toolbar, text="⬇ Export DOT Graph", command=self.export_dot).pack(side="left", padx=6)
        ttk.Button(toolbar, text="⬇ Export Mermaid", command=self.export_mermaid).pack(side="left")

        ttk.Label(toolbar, text="  drag node = move | drag bg = pan | wheel = zoom | dbl-click = copy | right-click = menu", font=("Segoe UI", 9)).pack(side="right")

        self.diagram_canvas = tk.Canvas(tab, bg="#010409", highlightthickness=0)
        self.diagram_canvas.bind("<ButtonPress-1>", self.on_graph_press)
        self.diagram_canvas.bind("<B1-Motion>", self.on_graph_drag)
        self.diagram_canvas.bind("<ButtonRelease-1>", self.on_graph_release)
        self.diagram_canvas.bind("<Double-Button-1>", self.on_graph_double)
        self.diagram_canvas.bind("<Motion>", self.on_graph_motion)
        self.diagram_canvas.bind("<Button-3>", self.on_graph_right_click)
        self.diagram_canvas.bind("<Leave>", lambda e: self.hide_tooltip())
        self.diagram_canvas.bind("<MouseWheel>", self.on_graph_wheel)
        self.diagram_canvas.bind("<Button-4>", self.on_graph_wheel)
        self.diagram_canvas.bind("<Button-5>", self.on_graph_wheel)

        self.tree_frame = ttk.Frame(tab)
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)
        self.tree_text = tk.Text(self.tree_frame, wrap="none", font=("Consolas", 11), state="disabled", cursor="arrow")
        ty = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree_text.yview)
        txs = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree_text.xview)
        self.tree_text.configure(yscrollcommand=ty.set, xscrollcommand=txs.set)
        self.tree_text.grid(row=0, column=0, sticky="nsew")
        ty.grid(row=0, column=1, sticky="ns")
        txs.grid(row=1, column=0, sticky="ew")
        self.tree_text.bind("<Button-3>", self.on_tree_right_click)
        self.tree_text.bind("<Motion>", self.on_tree_motion)
        self.tree_text.bind("<Leave>", lambda e: self.hide_tooltip())

        self.set_graph_style()

    def set_graph_style(self):
        if self.graph_style_var.get().startswith("OSINT"):
            self.tree_frame.pack_forget()
            self.diagram_canvas.pack(fill="both", expand=True, padx=10, pady=10)
            self.draw_osint_graph()
        else:
            self.diagram_canvas.pack_forget()
            self.tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
            self.build_tree_text()

    def refresh_diagram(self):
        if not hasattr(self, "diagram_canvas"): return
        if self.graph_style_var.get().startswith("OSINT"):
            if self.diagram_canvas.winfo_ismapped(): self.draw_osint_graph()
        else:
            if hasattr(self, "tree_frame") and self.tree_frame.winfo_ismapped(): self.build_tree_text()

    def reset_graph(self):
        if self.graph_style_var.get().startswith("OSINT"): self.draw_osint_graph()
        else: self.build_tree_text()
        self.status_var.set("Graph view reset.")

    def to_screen(self, wx, wy):
        return (wx * self.graph_scale + self.graph_offset[0], wy * self.graph_scale + self.graph_offset[1])

    def draw_osint_graph(self):
        canvas = self.diagram_canvas
        canvas.update_idletasks()
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        if width < 50: width = 900
        if height < 50: height = 600

        self.graph_scale = 1.0
        self.graph_offset = [width / 2.0, height / 2.0]
        self.graph_nodes = []
        self.graph_edges = []
        self.drag_node = None
        self.pan_last = None

        target = self.target_var.get().strip() or "target"
        origin = origin_from_url(target)
        netloc = urlsplit(origin).netloc or target
        target_host = urlsplit(origin).hostname or ""

        self.graph_nodes.append({"id": "root", "x": 0.0, "y": 0.0, "r": 26, "url": origin, "type": "root", "label": netloc})

        osint_hosts = sorted([h for h in self.osint_structured.keys() if h != target_host])
        R_SUB = 250.0

        if osint_hosts:
            step = 2 * math.pi / len(osint_hosts)
            for i, host in enumerate(osint_hosts):
                angle = i * step - math.pi / 2
                x, y = R_SUB * math.cos(angle), R_SUB * math.sin(angle)
                hid = f"host_{i}"
                self.graph_nodes.append({"id": hid, "x": x, "y": y, "r": 18, "url": f"http://{host}", "type": "subdomain", "label": host[:25], "host": host})
                self.graph_edges.append({"a": "root", "b": hid, "dash": False})

        unique_paths = set()
        params_map = {}
        path_to_host = {}
        all_urls = []

        for key in ["pages", "links", "js_files", "api_endpoints", "directories"]:
            for item in self.crawler.results.get(key, []):
                all_urls.append(item.get("url") or item.get("path") or "")

        for host, data in self.osint_structured.items():
            for path, (src, full_url) in data.get("dirs", {}).items():
                all_urls.append(full_url)

        for u in all_urls:
            if not u: continue
            try:
                parsed = urlsplit(u)
                host = parsed.hostname or target_host
                path = parsed.path or "/"
                if not path: continue
                if host not in path_to_host: path_to_host[host] = set()
                path_to_host[host].add(path)
                unique_paths.add((host, path))
                if parsed.query:
                    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                        params_map.setdefault((host, path), set()).add(k)
            except: pass

        R_PATH = 120.0
        path_idx = 0
        for host, paths in path_to_host.items():
            parent_id = "root"
            parent_x, parent_y = 0.0, 0.0
            if host != target_host:
                for n in self.graph_nodes:
                    if n.get("host") == host:
                        parent_id = n["id"]
                        parent_x, parent_y = n["x"], n["y"]
                        break

            paths_list = sorted(list(paths))[:15]
            if not paths_list: continue

            p_step = (2 * math.pi) / len(paths_list) if len(paths_list) > 1 else 0
            for j, p in enumerate(paths_list):
                angle = j * p_step
                x = parent_x + R_PATH * math.cos(angle)
                y = parent_y + R_PATH * math.sin(angle)
                pid = f"path_{path_idx}"
                path_idx += 1
                is_dir = p.endswith('/')
                ptype = "dir" if is_dir else "endpoint"
                label = p.strip('/').split('/')[-1] or '/'

                self.graph_nodes.append({"id": pid, "x": x, "y": y, "r": 8 if is_dir else 6, "url": f"http://{host}{p}", "type": ptype, "label": label[:15]})
                self.graph_edges.append({"a": parent_id, "b": pid, "dash": True})

        self.render_graph()

        if not unique_paths and not osint_hosts:
            canvas.create_text(width / 2, height / 2 + 60, text="No data yet. Run OSINT or Crawl.", fill=self.theme_fg, font=("Segoe UI", 10))

    def render_graph(self):
        canvas = self.diagram_canvas
        canvas.delete("all")
        pos = {n["id"]: n for n in self.graph_nodes}

        for e in self.graph_edges:
            a = pos.get(e["a"]); b = pos.get(e["b"])
            if not a or not b: continue
            x1, y1 = self.to_screen(a["x"], a["y"])
            x2, y2 = self.to_screen(b["x"], b["y"])
            e["item"] = canvas.create_line(x1, y1, x2, y2, fill=self.diagram_line_fill, width=1, dash=(3, 3) if e.get("dash") else ())

        for n in self.graph_nodes:
            x, y = self.to_screen(n["x"], n["y"])
            r = max(4.0, n["r"] * self.graph_scale)
            if n["type"] == "root":
                fill, outl, w = self.diagram_target_fill, self.diagram_target_outline, 2
            elif n["type"] == "subdomain":
                fill, outl, w = "#238636", "#2ea043", 2
            elif n["type"] == "dir":
                fill, outl, w = self.diagram_cat_fill, self.diagram_cat_outline, 2
            elif n["type"] == "param":
                fill, outl, w = "#f0883e", "#f0883e", 1
            else:
                fill, outl, w = self.diagram_page_fill, self.diagram_page_outline, 1

            n["oval"] = canvas.create_oval(x - r, y - r, x + r, y + r, fill=fill, outline=outl, width=w)

            if n["type"] == "root":
                n["text"] = canvas.create_text(x, y, text=n["label"][:18], fill=self.theme_fg, font=("Segoe UI", 9, "bold"))
            elif n["type"] == "subdomain":
                n["text"] = canvas.create_text(x, y + r + 12, text=n["label"], fill="#3fb950", font=("Segoe UI", 8, "bold"))
            elif n["type"] == "dir":
                n["text"] = canvas.create_text(x, y + r + 12, text=n["label"], fill=self.theme_accent, font=("Segoe UI", 8, "bold"))
            elif n["type"] == "param":
                n["text"] = canvas.create_text(x, y + r + 10, text=n["label"], fill="#f0883e", font=("Consolas", 8))
            else:
                n["text"] = None

    def _get_closest_node(self, x, y):
        closest = None
        min_dist = float('inf')
        for n in self.graph_nodes:
            sx, sy = self.to_screen(n["x"], n["y"])
            r = max(6.0, n["r"] * self.graph_scale) + 4
            dist = math.hypot(x - sx, y - sy)
            if dist < r and dist < min_dist:
                min_dist = dist
                closest = n
        return closest

    def on_graph_press(self, event):
        self.hide_tooltip()
        node = self._get_closest_node(event.x, event.y)
        if node:
            self.drag_node = node
            self.drag_last = (event.x, event.y)
        else:
            self.pan_last = (event.x, event.y)
        self.diagram_canvas.configure(cursor="fleur")

    def on_graph_drag(self, event):
        if self.drag_node is not None and self.drag_last:
            dx = event.x - self.drag_last[0]
            dy = event.y - self.drag_last[1]
            self.drag_last = (event.x, event.y)
            n = self.drag_node
            n["x"] += dx / self.graph_scale
            n["y"] += dy / self.graph_scale
            if n.get("oval"): self.diagram_canvas.move(n["oval"], dx, dy)
            if n.get("text"): self.diagram_canvas.move(n["text"], dx, dy)
            pos = {m["id"]: m for m in self.graph_nodes}
            for e in self.graph_edges:
                if e["a"] == n["id"] or e["b"] == n["id"]:
                    a = pos.get(e["a"]); b = pos.get(e["b"])
                    if not a or not b: continue
                    x1, y1 = self.to_screen(a["x"], a["y"])
                    x2, y2 = self.to_screen(b["x"], b["y"])
                    if e.get("item"): self.diagram_canvas.coords(e["item"], x1, y1, x2, y2)
        elif self.pan_last:
            dx = event.x - self.pan_last[0]
            dy = event.y - self.pan_last[1]
            self.pan_last = (event.x, event.y)
            self.graph_offset[0] += dx
            self.graph_offset[1] += dy
            self.diagram_canvas.move("all", dx, dy)

    def on_graph_release(self, event):
        self.drag_node = None
        self.drag_last = None
        self.pan_last = None
        self.diagram_canvas.configure(cursor="arrow")

    def on_graph_wheel(self, event):
        delta = 0
        if getattr(event, "num", None) == 4: delta = 1
        elif getattr(event, "num", None) == 5: delta = -1
        elif getattr(event, "delta", 0): delta = 1 if event.delta > 0 else -1
        else: return

        factor = 1.15 if delta > 0 else 1 / 1.15
        new_scale = min(4.0, max(0.25, self.graph_scale * factor))
        k = new_scale / self.graph_scale
        if k == 1: return

        ox, oy = self.graph_offset
        self.graph_offset = [event.x - (event.x - ox) * k, event.y - (event.y - oy) * k]
        self.graph_scale = new_scale
        self.render_graph()

    def on_graph_double(self, event):
        node = self._get_closest_node(event.x, event.y)
        if node: self.copy_to_clipboard(node["url"])

    def on_graph_motion(self, event):
        if self.drag_node is not None or self.pan_last: return
        node = self._get_closest_node(event.x, event.y)
        if node:
            self.diagram_canvas.configure(cursor="hand2")
            self.show_tooltip(event.x_root, event.y_root, f"{node['type'].upper()}\n{node['url']}")
        else:
            self.diagram_canvas.configure(cursor="arrow")
            self.hide_tooltip()

    def on_graph_right_click(self, event):
        node = self._get_closest_node(event.x, event.y)
        if not node: return
        self.show_unified_context_menu(event, url=node["url"], path=node.get("label"))

    def build_tree_text(self):
        self.tree_line_paths = {}
        dir_lines = []
        target = self.target_var.get().strip() or "target"
        origin = origin_from_url(target)
        netloc = urlsplit(origin).netloc or "target"

        path_status_map = {}
        for p in self.crawler.results.get("pages", []):
            try:
                path = urlsplit(p["url"]).path
                path_status_map[path] = p["status"]
            except: pass

        root = {"dirs": {}, "files": set()}

        def walk(parts):
            cur = root
            for p in parts:
                cur = cur["dirs"].setdefault(p, {"dirs": {}, "files": set()})
            return cur

        for d in self.crawler.results.get("directories", []):
            parts = [p for p in d.get("path", "").split("/") if p]
            walk(parts)

        for key in ("pages", "links", "js_files", "api_endpoints", "robots_paths", "sitemap_urls"):
            for item in self.crawler.results.get(key, []):
                u = item.get("url") or item.get("path") or ""
                path = urlsplit(u).path if u.startswith("http") else u
                segs = [p for p in path.split("/") if p]
                if not segs: continue
                fname = segs[-1]
                if "." not in fname and not fname.endswith('/'): continue
                node = walk(segs[:-1])
                node["files"].add(fname)

        path_params = {}
        for item in self.crawler.results.get("parameters", []):
            p = item.get("path", "")
            if not p:
                try: p = urlsplit(item.get("url", "")).path
                except: continue
            name = item.get("name", "")
            if p and name: path_params.setdefault(p, set()).add(name)

        lines = []
        line_tags = {}
        counts = {"d": 0, "f": 0}
        MAX_LINES = 8000
        truncated = [False]

        def render(node, prefix, cur_path):
            if len(lines) > MAX_LINES:
                truncated[0] = True
                return

            entries = ([("d", k, v) for k, v in sorted(node["dirs"].items())] +
                       [("f", f, None) for f in sorted(node["files"])])
            if len(entries) > 400:
                entries = entries[:400]
                truncated[0] = True

            for i, (kind, name, sub) in enumerate(entries):
                if len(lines) > MAX_LINES:
                    truncated[0] = True
                    return

                last = i == len(entries) - 1
                conn = "└── " if last else "├── "
                child_prefix = prefix + ("    " if last else "│   ")
                line_no = len(lines) + 1

                if kind == "d":
                    dir_path = cur_path + name + "/"
                    status = path_status_map.get(dir_path, "")
                    status_str = f"  [{status}]" if status else ""
                    lines.append(f"{prefix}{conn}{name}/{status_str}")
                    self.tree_line_paths[line_no] = dir_path
                    dir_lines.append(line_no)
                    counts["d"] += 1
                    render(sub, child_prefix, cur_path + name + "/")
                else:
                    file_path = cur_path + name
                    status = path_status_map.get(file_path, "")
                    status_str = f"  [{status}]" if status else ""
                    line_text = f"{prefix}{conn}{name}{status_str}"
                    lines.append(line_text)
                    self.tree_line_paths[line_no] = file_path
                    counts["f"] += 1

                    params = sorted(list(path_params.get(file_path, [])))[:5]
                    if params:
                        param_str = f"  [params: {', '.join(params)}]"
                        lines[-1] = line_text + param_str
                        line_tags[line_no] = [(len(line_text), len(line_text) + len(param_str), "param")]

        lines.append(f"{netloc}/")
        render(root, "", "")

        if truncated[0]: lines.append("... (truncated)")
        lines.append("")
        lines.append(f"{counts['d']} directories, {counts['f']} files")

        self.tree_dir_lines = dir_lines
        self.tree_text.configure(state="normal")
        self.tree_text.delete("1.0", "end")

        for i, line in enumerate(lines):
            line_no = i + 1
            self.tree_text.insert("end", line + "\n")
            if line_no in dir_lines:
                self.tree_text.tag_add("dir", f"{line_no}.0", f"{line_no}.end")
            if line_no in line_tags:
                for start, end, tag in line_tags[line_no]:
                    self.tree_text.tag_add(tag, f"{line_no}.{start}", f"{line_no}.{end}")

        self.tree_text.tag_configure("dir", foreground=self.theme_accent, font=("Consolas", 11, "bold"))
        self.tree_text.tag_configure("param", foreground="#f0883e", font=("Consolas", 10, "italic"))
        self.tree_text.configure(state="disabled")

    def on_tree_motion(self, event):
        try:
            self.tree_text.configure(state="normal")
            idx = self.tree_text.index(f"@{event.x},{event.y}")
            self.tree_text.configure(state="disabled")
            line = int(idx.split(".")[0])
            path = self.tree_line_paths.get(line)
            if path:
                origin = origin_from_url(self.target_var.get().strip() or "http://localhost/")
                full = urljoin(origin, path)
                status = "???"
                for p in self.crawler.results.get("pages", []):
                    try:
                        if urlsplit(p["url"]).path == path:
                            status = p["status"]
                            break
                    except: pass
                self.show_tooltip(event.x_root, event.y_root, f"{full}\nStatus: {status}")
            else:
                self.hide_tooltip()
        except:
            self.hide_tooltip()

    def on_tree_right_click(self, event):
        try:
            self.tree_text.configure(state="normal")
            idx = self.tree_text.index(f"@{event.x},{event.y}")
            self.tree_text.configure(state="disabled")
            line = int(idx.split(".")[0])
            path = self.tree_line_paths.get(line)
            if not path: return
            origin = origin_from_url(self.target_var.get().strip() or "http://localhost/")
            full = urljoin(origin, path)
            self.show_unified_context_menu(event, url=full, path=path)
        except: pass

    def show_tooltip(self, x, y, text):
        self.hide_tooltip()
        self.tooltip = tk.Toplevel(self.root)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x+20}+{y+20}")
        label = tk.Label(self.tooltip, text=text, background="#161b22", foreground="#c9d1d9", relief="solid", borderwidth=1, font=("Consolas", 10), justify="left")
        label.pack()

    def hide_tooltip(self):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def process_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "log":
                    stamp = datetime.now().strftime("%H:%M:%S")
                    self.log_text.insert("end", f"{stamp} {payload}\n")
                    self.log_text.see("end")
                elif kind == "crawl_done":
                    self.refresh_results()
                    self.refresh_found_dirs()
                    self.refresh_diagram()
                    self.refresh_secrets()
                    self.crawl_start_btn.config(state="normal")
                    self.crawl_stop_btn.config(state="disabled")
                    self.status_var.set("Crawl finished.")
                elif kind == "brute_result":
                    self.brute_tree.insert("", 0, values=(payload.get("time", ""), payload.get("base", ""), payload.get("url", ""), payload.get("status", ""), payload.get("length", ""), payload.get("note", "")))
                elif kind == "brute_progress":
                    sent, total = payload
                    self.brute_progress_var.set(f"{sent} / {total} requests sent")
                    if total > 0:
                        self.brute_progress_bar['value'] = (sent / total) * 100
                elif kind == "brute_done":
                    self.brute_start_selected_btn.config(state="normal")
                    self.brute_start_all_btn.config(state="normal")
                    self.brute_stop_btn.config(state="disabled")
                    self.refresh_diagram()
                    self.status_var.set("Brute finished.")
                elif kind == "osint_progress":
                    current, total, msg = payload
                    if hasattr(self, 'osint_progress_bar'):
                        self.osint_progress_bar['maximum'] = total
                        self.osint_progress_bar['value'] = current
                        self.status_var.set(f"OSINT: {msg}")
                elif kind == "osint_done":
                    self.osint_raw_data = payload
                    self.apply_osint_filters()
                    self.osint_start_btn.config(state="normal")
                    self.osint_stop_btn.config(state="disabled")
                    self.refresh_diagram()
                    self.status_var.set("OSINT finished.")
        except queue.Empty: pass
        self.root.after(120, self.process_queue)

    def _crawl_opts(self):
        try:
            opts = {
                "max_depth": int(self.max_depth_var.get() or 0),
                "max_pages": int(self.max_pages_var.get() or 150),
                "delay": float(self.delay_var.get() or 0.25), "timeout": float(self.timeout_var.get() or 8),
                "user_agent": self.ua_var.get().strip() or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "include_subdomains": bool(self.include_subdomains_var.get()), "verify_tls": bool(self.verify_tls_var.get()),
                "parse_robots": bool(self.parse_robots_var.get()), "parse_sitemap": bool(self.parse_sitemap_var.get()),
                "crawl_sitemap": bool(self.crawl_sitemap_var.get()), "crawl_robots": bool(self.crawl_robots_var.get()),
                "fetch_js": bool(self.fetch_js_var.get()), "extract_js": bool(self.extract_js_var.get()),
                "visit_discovered": bool(self.visit_discovered_var.get()),
                "proxy_url": self.proxy_var.get().strip(),
            }
        except ValueError:
            raise ValueError("Crawl options must be valid numbers.")

        opts["max_depth"] = max(0, opts["max_depth"])
        opts["max_pages"] = max(1, min(5000, opts["max_pages"]))
        opts["delay"] = max(0.0, opts["delay"])
        opts["timeout"] = max(1.0, min(60.0, opts["timeout"]))
        return opts

    def start_crawl(self):
        if not self.auth_var.get():
            messagebox.showerror(APP_NAME, "You must confirm authorization for the target.")
            return
        if self.crawler.running:
            messagebox.showinfo(APP_NAME, "Crawl already running.")
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror(APP_NAME, "Target URL is required.")
            return

        try: opts = self._crawl_opts()
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        self.crawl_start_btn.config(state="disabled")
        self.crawl_stop_btn.config(state="normal")
        self.status_var.set("Crawling...")
        threading.Thread(target=self.crawler.run, args=(target, opts), daemon=True).start()

    def stop_crawl(self):
        self.crawler.stop_event.set()
        self.status_var.set("Stopping crawl...")

    def clear_log(self): self.log_text.delete("1.0", "end")

    def _item_label(self, key, item):
        if isinstance(item, dict):
            if key == "pages": return item.get("url", "")
            if key == "directories": return item.get("path", "")
            if key == "forms": return item.get("action", "")
            if key == "inputs": return item.get("name", "")
            if key in ("links", "js_files", "api_endpoints"): return item.get("url", "")
            if key == "parameters": return item.get("name", "")
            if key == "redirects": return f"{item.get('from', '')} -> {item.get('to', '')}"
            if key == "robots_paths": return item.get("path", "")
            if key == "sitemap_urls": return item.get("url", "")
            if key == "secrets": return item.get("value", "")
            if key == "security_issues": return item.get("issue", "")
            if key == "errors": return item.get("url", "")
        return str(item)

    def _item_detail(self, key, item):
        if not isinstance(item, dict): return ""
        if key == "pages": return f"status={item.get('status')} depth={item.get('depth')} length={item.get('length')}"
        if key == "directories": return item.get("source", "")
        if key == "forms": return f"method={item.get('method')} inputs={item.get('input_names', '')}"
        if key == "inputs": return item.get("form_action") or "outside-form"
        if key in ("links", "js_files", "api_endpoints"): return item.get("source", "")
        if key == "parameters": return f"val={item.get('value', '')} url={item.get('url', '')}"
        if key == "redirects": return f"-> {item.get('to', '')} status={item.get('status', '')}"
        if key == "robots_paths": return "robots.txt"
        if key == "sitemap_urls": return "sitemap"
        if key == "secrets": return f"{item.get('type', '')} @ {item.get('url', '')}"
        if key == "security_issues": return item.get("url", "")
        if key == "errors": return item.get("error", "")
        return ""

    def refresh_results(self):
        self.results_tree.delete(*self.results_tree.get_children())

        if self.results_view_mode.get() == "flat":
            for key, label in DIAGRAM_CATEGORIES:
                for item in self.crawler.results.get(key, [])[:2000]:
                    self.results_tree.insert("", "end", values=(label, self._item_label(key, item), self._item_detail(key, item)))
        else:
            for key, label in DIAGRAM_CATEGORIES:
                items = self.crawler.results.get(key, [])
                parent = self.results_tree.insert("", "end", values=(label, f"{len(items)} items", ""), tags=("category",))

                if key == "parameters":
                    grouped = {}
                    for item in items:
                        p = item.get("path", "") or urlsplit(item.get("url", "")).path
                        grouped.setdefault(p, []).append(item)

                    for path, params in sorted(grouped.items()):
                        p_node = self.results_tree.insert(parent, "end", values=(key, path, f"{len(params)} unique params"), tags=("endpoint",))
                        seen_params = set()
                        for param in params:
                            pname = param.get('name', '')
                            if pname in seen_params: continue
                            seen_params.add(pname)
                            pval = param.get('value', '')
                            display_val = f"{pname}={pval}" if pval else pname
                            self.results_tree.insert(p_node, "end", values=(key, display_val, param.get('url', '')))
                else:
                    for item in items[:2000]:
                        self.results_tree.insert(parent, "end", values=(key, self._item_label(key, item), self._item_detail(key, item)))

            self.results_tree.tag_configure("category", font=("Segoe UI", 10, "bold"))
            self.results_tree.tag_configure("endpoint", foreground="#f0883e", font=("Consolas", 10, "bold"))

    def clear_results(self):
        self.crawler.reset()
        self.refresh_results()
        self.refresh_found_dirs()
        self.refresh_diagram()
        self.refresh_secrets()

    def export_results_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], initialfile="reconweave_results.json")
        if not path: return
        try:
            Path(path).write_text(json.dumps(self.crawler.results, indent=2, default=str), encoding="utf-8")
            messagebox.showinfo(APP_NAME, f"Results exported to:\n{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Export failed: {e}")

    def on_results_right_click(self, event):
        item = self.results_tree.identify_row(event.y)
        if not item: return
        self.results_tree.selection_set(item)
        values = self.results_tree.item(item, "values")
        if not values or len(values) < 2: return
        typ = str(values[0]); val = str(values[1])
        url = val if val.startswith("http") else None
        path = val if val.startswith("/") else None
        self.show_unified_context_menu(event, url=url, path=path)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set(f"Copied to clipboard: {text[:50]}")

    def copy_ffuf(self, url):
        if not url.startswith("http"):
            url = urljoin(self.target_var.get().strip() or "http://localhost/", url)
        parsed = urlsplit(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qsl(parsed.query)
        if params:
            fuzz_url = base + "?" + "&".join([f"{k}=FUZZ" if i == 0 else f"{k}={v}" for i, (k, v) in enumerate(params)])
            cmd = f"ffuf -u \"{fuzz_url}\" -w wordlist.txt"
            self.copy_to_clipboard(cmd)
        else:
            self.copy_to_clipboard(f"ffuf -u \"{base}/FUZZ\" -w wordlist.txt")

    def open_in_browser(self, url):
        if not url.startswith("http"):
            url = urljoin(self.target_var.get().strip() or "http://localhost/", url)
        webbrowser.open(url)

    def brute_result_path(self, value):
        base = self._abs_base(value)
        self.notebook.select(self.tab_brute)
        iid = self.found_tree.insert("", 0, values=(base, "manual"))
        self.found_tree.selection_set(iid)
        if messagebox.askyesno(APP_NAME, f"Start directory brute against:\n{base}"):
            self.start_brute_selected()

    def refresh_found_dirs(self):
        self.found_tree.delete(*self.found_tree.get_children())
        for d in self.crawler.results.get("directories", []):
            self.found_tree.insert("", "end", values=(d.get("path", ""), d.get("source", "")))

    def _abs_base(self, path_or_url):
        target = self.target_var.get().strip()
        origin = origin_from_url(target if target else "http://localhost/")
        if path_or_url.startswith(("http://", "https://")): return path_or_url
        if not path_or_url.startswith("/"): path_or_url = "/" + path_or_url
        return urljoin(origin, path_or_url)

    def get_selected_bases(self):
        bases = []
        for sel in self.found_tree.selection():
            vals = self.found_tree.item(sel, "values")
            if vals: bases.append(self._abs_base(str(vals[0])))
        return bases

    def get_all_bases(self):
        bases = []
        for child in self.found_tree.get_children(""):
            vals = self.found_tree.item(child, "values")
            if vals: bases.append(self._abs_base(str(vals[0])))
        return bases

    def _brute_opts(self):
        target = self.target_var.get().strip()
        origin = origin_from_url(target if target else "http://localhost/")
        try:
            threads = int(self.brute_threads_var.get() or 5)
            delay = float(self.brute_delay_var.get() or 0.2)
            max_per_dir = int(self.brute_max_var.get() or 500)
            timeout = float(self.timeout_var.get() or 8)
        except ValueError:
            raise ValueError("Brute options must be valid numbers.")

        return {
            "target_origin": origin, "threads": max(1, min(50, threads)), "delay": max(0.0, delay),
            "max_per_dir": max(1, min(100000, max_per_dir)),
            "interesting_statuses": parse_status_list(self.brute_statuses_var.get()),
            "timeout": max(1.0, min(60.0, timeout)),
            "user_agent": self.ua_var.get().strip() or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "verify_tls": bool(self.verify_tls_var.get()), "mode": self.brute_mode_var.get(),
            "log_all": bool(self.brute_log_all_var.get()),
            "proxy_url": self.proxy_var.get().strip(),
        }

    def start_brute_selected(self):
        bases = self.get_selected_bases()
        if not bases:
            messagebox.showinfo(APP_NAME, "Select one or more found directories first.")
            return
        self.start_brute_bases(bases, is_all=False)

    def start_brute_all(self):
        bases = self.get_all_bases()
        if not bases:
            messagebox.showinfo(APP_NAME, "No found directories available. Run a crawl first.")
            return
        self.start_brute_bases(bases, is_all=True)

    def start_brute_bases(self, bases, is_all=False):
        if not self.auth_var.get():
            messagebox.showerror(APP_NAME, "You must confirm authorization for the target.")
            return
        if self.bruter.running:
            messagebox.showinfo(APP_NAME, "Brute engine already running.")
            return
        if not bases:
            messagebox.showinfo(APP_NAME, "No bases selected.")
            return

        try: opts = self._brute_opts()
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        mode = self.brute_mode_var.get()
        if is_all or mode == "parallel" or len(bases) > 10:
            msg = f"This will send active directory brute-force requests to {len(bases)} base path(s)."
            if mode == "parallel":
                msg += "\n\nParallel mode can generate high traffic and may cause rate limiting, service degradation, or denial-of-service conditions. It is highly recommended only for local labs or explicitly authorized environments."
            if not messagebox.askokcancel("High-traffic warning", msg): return

        self.brute_start_selected_btn.config(state="disabled")
        self.brute_start_all_btn.config(state="disabled")
        self.brute_stop_btn.config(state="normal")
        self.status_var.set("Bruting...")
        self.bruter.start(bases, self.brute_wordlist_var.get(), opts, mode="directory")

    def stop_brute(self):
        self.bruter.stop()
        self.status_var.set("Stopping brute...")

    def clear_brute_results(self):
        self.bruter.results = []
        self.brute_tree.delete(*self.brute_tree.get_children())

    def refresh_wordlist_ui(self):
        if hasattr(self, "wordlist_box"):
            self.wordlist_box.delete(0, "end")
            for name, path in sorted(self.wordlists.items()):
                self.wordlist_box.insert("end", f"{name} -> {path}")

        values = ["builtin:common"] + sorted(self.wordlists.keys())
        if hasattr(self, "wordlist_combo"):
            self.wordlist_combo["values"] = values
            current = self.brute_wordlist_var.get().strip()
            if not current or current not in values: self.brute_wordlist_var.set("builtin:common")

        if hasattr(self, "subdomain_wordlist_box"):
            self.subdomain_wordlist_box.delete(0, "end")
            for name, path in sorted(self.subdomain_wordlists.items()):
                self.subdomain_wordlist_box.insert("end", f"{name} -> {path}")

        sub_values = ["builtin:subdomains"] + sorted(self.subdomain_wordlists.keys())
        if hasattr(self, "subdomain_wordlist_combo"):
            self.subdomain_wordlist_combo["values"] = sub_values
            current = self.subdomain_wordlist_var.get().strip()
            if not current or current not in sub_values: self.subdomain_wordlist_var.set("builtin:subdomains")

    def add_wordlist(self):
        name = self.wl_name_var.get().strip()
        path = self.wl_path_var.get().strip()
        if not name or not path:
            messagebox.showerror(APP_NAME, "Wordlist name and path are required.")
            return
        self.wordlists[name] = path
        self.save_config()
        self.refresh_wordlist_ui()
        self.wl_name_var.set("")
        self.wl_path_var.set("")
        self.status_var.set(f"Wordlist '{name}' saved.")

    def remove_wordlist(self):
        sel = self.wordlist_box.curselection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a wordlist entry to remove.")
            return
        text = self.wordlist_box.get(sel[0])
        name = text.split(" -> ")[0].strip()
        if name in self.wordlists:
            del self.wordlists[name]
            self.save_config()
            self.refresh_wordlist_ui()
            self.status_var.set(f"Wordlist '{name}' removed.")

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title="Choose wordlist file")
        if path: self.wl_path_var.set(path)

    def add_subdomain_wordlist(self):
        name = self.sub_wl_name_var.get().strip()
        path = self.sub_wl_path_var.get().strip()
        if not name or not path:
            messagebox.showerror(APP_NAME, "Subdomain wordlist name and path are required.")
            return
        self.subdomain_wordlists[name] = path
        self.save_config()
        self.refresh_wordlist_ui()
        self.sub_wl_name_var.set("")
        self.sub_wl_path_var.set("")
        self.status_var.set(f"Subdomain wordlist '{name}' saved.")

    def remove_subdomain_wordlist(self):
        sel = self.subdomain_wordlist_box.curselection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a subdomain wordlist entry to remove.")
            return
        text = self.subdomain_wordlist_box.get(sel[0])
        name = text.split(" -> ")[0].strip()
        if name in self.subdomain_wordlists:
            del self.subdomain_wordlists[name]
            self.save_config()
            self.refresh_wordlist_ui()
            self.status_var.set(f"Subdomain wordlist '{name}' removed.")

    def browse_subdomain_wordlist(self):
        path = filedialog.askopenfilename(title="Choose subdomain wordlist file")
        if path: self.sub_wl_path_var.set(path)

    def save_wordlists_ui(self):
        self.save_config()
        self.refresh_wordlist_ui()
        self.status_var.set("Wordlists saved.")

    def test_wordlist(self):
        try:
            words = self.bruter.load_wordlist(self.brute_wordlist_var.get())
            messagebox.showinfo(APP_NAME, f"Wordlist loaded successfully.\nWords: {len(words)}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Wordlist load failed: {e}")

    def test_subdomain_wordlist(self):
        try:
            words = self.bruter.load_subdomain_wordlist(self.subdomain_wordlist_var.get())
            messagebox.showinfo(APP_NAME, f"Subdomain wordlist loaded successfully.\nWords: {len(words)}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Subdomain wordlist load failed: {e}")

    def export_urls_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")], initialfile="reconweave_urls.txt")
        if not path: return
        urls = set()
        target = self.target_var.get().strip() or "http://localhost/"
        for key in ["pages", "links", "js_files", "api_endpoints", "directories", "sitemap_urls"]:
            for item in self.crawler.results.get(key, []):
                val = item.get("url") or item.get("path")
                if val:
                    if not val.startswith("http"): val = urljoin(target, val)
                    urls.add(val)

        try:
            Path(path).write_text("\n".join(sorted(urls)), encoding="utf-8")
            messagebox.showinfo(APP_NAME, f"Exported {len(urls)} URLs to:\n{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Export failed: {e}")

    def export_dot(self):
        path = filedialog.asksaveasfilename(defaultextension=".dot", filetypes=[("Graphviz DOT", "*.dot")], initialfile="reconweave_graph.dot")
        if not path: return

        lines = ["digraph ReconWeave {", "  rankdir=LR;", '  node [shape=box, fontsize=10];']
        target = self.target_var.get().strip() or "target"
        lines.append(f'  target [label="{dot_escape(target)}", style=filled, fillcolor="#d7e8ff"];')

        for key, label in DIAGRAM_CATEGORIES:
            items = self.crawler.results.get(key, [])
            if not items: continue
            cat_id = f"cat_{key}"
            lines.append(f'  {cat_id} [label="{label} ({len(items)})", style=filled, fillcolor="#f2f2f2"];')
            lines.append(f"  target -> {cat_id};")
            for i, item in enumerate(items[:8]):
                node_id = f"{key}_{i}"
                lines.append(f'  {node_id} [label="{dot_escape(self._item_label(key, item))}"];')
                lines.append(f"  {cat_id} -> {node_id};")

        lines.append("}")

        try:
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo(APP_NAME, f"DOT graph exported to:\n{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"DOT export failed: {e}")

    def export_mermaid(self):
        path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Mermaid Markdown", "*.md")], initialfile="reconweave_graph.md")
        if not path: return

        lines = ["```mermaid", "graph LR"]
        target = self.target_var.get().strip() or "target"
        lines.append(f'  target["{mermaid_escape(target)}"]')

        for key, label in DIAGRAM_CATEGORIES:
            items = self.crawler.results.get(key, [])
            if not items: continue
            cat_id = f"cat_{key}"
            lines.append(f'  {cat_id}["{label} ({len(items)})"]')
            lines.append(f"  target --> {cat_id}")
            for i, item in enumerate(items[:8]):
                node_id = f"{key}_{i}"
                lines.append(f'  {node_id}["{mermaid_escape(self._item_label(key, item))}"]')
                lines.append(f"  {cat_id} --> {node_id}")

        lines.append("```")

        try:
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo(APP_NAME, f"Mermaid graph exported to:\n{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Mermaid export failed: {e}")


def main():
    root = tk.Tk()
    ReconWeaveApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
