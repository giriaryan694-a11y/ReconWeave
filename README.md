# ReconWeave

**Attack-surface mapping · Web crawling · Passive OSINT · Secret-pattern detection**

ReconWeave is a desktop reconnaissance helper for authorised security assessments and lab environments. It combines a Tkinter interface with a bounded HTTP crawler, URL and form extraction, JavaScript endpoint heuristics, passive OSINT lookups, regex-based secret detection, and scoped directory/subdomain discovery.

> **Use only within written authorisation and the agreed scope.** ReconWeave has an authorisation checkbox and confirmation prompts as guardrails, not as proof of permission. You are responsible for validating the exact hosts, ports, protocols, request rate, and activities approved by the asset owner.

## Features

### Crawler and application mapping

- Breadth-first crawling with configurable depth, page cap, timeout, delay, TLS verification, user-agent, and HTTP/HTTPS proxy. A depth value of `0` means unlimited depth; the page cap still applies.
- Extraction of links, scripts, forms, named inputs, query parameters, URL paths, API-like routes, and JavaScript `fetch`, Axios, XHR, and redirect patterns.
- Optional discovery from `robots.txt` and XML sitemaps.
- Tracks response status, response length, redirect history, and basic security-header observations.
- Keeps crawl requests within the configured scheme/port and host scope. Out-of-scope redirects are recorded but not followed.

Endpoint extraction is heuristic rather than a JavaScript parser. Minified code, dynamically generated routes, framework-specific APIs, and unusual syntax may be missed; regex matches can also be false positives.

### Passive OSINT

- Certificate Transparency data from `crt.sh`.
- Historical URLs from the Internet Archive CDX API.
- Optional DuckDuckGo results when a compatible `ddgs` or `duckduckgo-search` package is installed.
- Domain-boundary filtering before OSINT results are shown.

Passive OSINT asks third-party providers for public data. It does not establish that a discovered host is in your contractual scope. Review hosts individually before launching active requests.

### Secret-pattern scanning

The scanner searches fetched textual responses for patterns resembling cloud identifiers, API tokens, JWTs, private-key headers, internal IPv4 addresses, email addresses, and generic hard-coded secrets.

Matches are **unverified leads**, not proof that a credential is valid or exploitable. False positives and false negatives are expected. Results can contain sensitive material, so protect exports and delete them when no longer needed.

### Directory and subdomain discovery

- Built-in common wordlists and user-supplied wordlists.
- Sequential or parallel directory checks, with configurable request delay, concurrency, timeout, proxy, and interesting HTTP statuses.
- Subdomain checks use validated DNS-label candidates and are restricted to the configured target's estimated domain scope.
- Copy a generated `ffuf` command from the context menu; review the command and scope before running it.

Parallel mode can create significant request bursts even when a per-worker delay is set. Use conservative settings against shared or production systems. The bundled root-domain logic is a **best-effort heuristic**, not a complete Public Suffix List. Be especially careful with country-code suffixes and multi-tenant hosting domains. When uncertain, disable subdomain expansion and use an explicit host allowlist.

### Results, visualisation, and export

- Tabs: **Crawl**, **Results & Headers**, **Brute Session**, **OSINT & Dorking**, **Secrets & Creds**, **Wordlists / Config**, and **Graph & Tree View**.
- Dark, Light, and Cyber interface themes.
- JSON exports for crawl, brute, and secret results; URL-list, Graphviz DOT, and Mermaid exports for visualisation.

Missing security headers and server banners are observations. They are not, by themselves, confirmation of an exploitable vulnerability.

## Requirements

- Python 3.8 or later.
- Tkinter. It is usually bundled with Python on Windows and macOS. On Debian/Ubuntu/Kali, install it with:

  ```bash
  sudo apt update
  sudo apt install python3-tk
  ```

Core crawling and parsing use Python's standard library. DuckDuckGo search is optional. Install one compatible package if you want that source enabled:

```bash
python -m pip install ddgs
```

A legacy-compatible alternative, when suitable for your Python version, is:

```bash
python -m pip install duckduckgo-search
```

## Installation and launch

```bash
git clone https://github.com/giriaryan694-a11y/ReconWeave.git
cd ReconWeave
python main.py
```

On Linux, if the GUI does not open, verify that the Tkinter package is installed and that a graphical display is available. ReconWeave is a desktop Tk application; a headless SSH shell alone is not sufficient to show its interface.

## Basic workflow

1. Start ReconWeave and enter the exact authorised target URL in **Target Configuration**.
2. Confirm that written authorisation covers the target, protocol, port, and planned activity. Editing the target URL clears the confirmation.
3. Start with a conservative crawl: a low page cap, a positive delay, TLS verification enabled, and subdomain inclusion disabled unless it is explicitly in scope.
4. Review **Results & Headers**, **Secrets & Creds**, and **Graph & Tree View**. Treat findings as leads and verify them manually.
5. Before active directory or subdomain discovery, review the selected bases and wordlist. Keep parallelism low on shared systems and stop immediately if the owner requests it.
6. Export only the data you need. Secret exports may contain credentials or personal information.

### Using Burp Suite or OWASP ZAP

1. Start the local proxy listener (for example, Burp's `http://127.0.0.1:8080`).
2. Enter the listener URL in ReconWeave's **Proxy** field.
3. Start the intended crawl or brute session and verify the requests in the proxy history.
4. Keep TLS verification enabled where possible by trusting the proxy's CA certificate. Disabling verification makes the connection less secure and should be limited to controlled local testing when necessary.

## Regression tests

The accompanying `test_reconweave.py` exercises URL normalization, scheme/port scope checks, redirect restrictions, response-size bounds, form parsing, regex extraction, word validation, secret-finding de-duplication, and OSINT domain matching. Tests use a local HTTP server and do not scan external targets.

```bash
python -m unittest -v test_reconweave.py
python -m py_compile main.py
```

## Project files

```text
ReconWeave/
├── main.py              # Desktop application
├── README.md            # Project documentation
├── test_reconweave.py   # Local regression tests
└── LICENSE              # Include the repository's actual license file
```

## Credits and licence

**Author:** Aryan Giri · `giriaryan694-a11y`

The supplied files did not include the repository's `LICENSE` file, and the previous README mixed an MIT badge with an Apache-2.0 statement. Include the actual licence file in the repository and make the GitHub licence metadata and README agree with it. Do not treat this note as granting a licence that is not present in the repository.
