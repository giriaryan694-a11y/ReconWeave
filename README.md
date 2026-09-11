# 🕸️ ReconWeave

**Attack Surface Mapper | Intelligent Crawler | OSINT & Secrets Scanner**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GUI](https://img.shields.io/badge/GUI-Tkinter-orange.svg)]()

**ReconWeave** is an elite, zero-dependency Attack Surface Mapper and Intelligent Web Crawler designed for penetration testers, bug bounty hunters, and security researchers. Built entirely on Python's standard library, it requires no `pip` installations and provides deep inspection of web applications, automatic secret detection, and seamless proxy chaining.

> ⚠️ **Disclaimer:** This tool is strictly for **authorized security testing**, educational purposes, and sanctioned lab environments. Unauthorized scanning or exploitation is illegal. Always obtain explicit written permission before testing any target.

---

## ✨ Core Features

### 🕸️ Intelligent Crawling & Parsing
* **Strict URL Extraction:** Advanced Regex patterns eliminate false positives (e.g., ignoring environment variables like `APPDATA` or `COMSPEC` while catching valid relative paths and extensions).
* **Deep JS Inspection:** Parses JavaScript source code to extract hidden API endpoints, `fetch`/`axios`/`XHR` calls, and `window.location` redirects.
* **Unlimited Depth:** BFS (Breadth-First Search) crawler with configurable depth (set to `0` for unlimited) and page limits.

### 🔐 Secrets & OSINT Scanner
Automatically scans all HTML and JS responses for exposed credentials and sensitive infrastructure:
* ☁️ **Cloud Buckets:** AWS S3, GCP Storage, Azure Blob
* 🔑 **Tokens & Keys:** AWS Access Keys, GitHub Tokens (`ghp_`), Stripe Live Keys, Google API Keys, JWTs
* 📜 **Certificates:** RSA/EC Private Keys
* 🌐 **Network Info:** Internal IP addresses (RFC 1918), Email addresses
* 🗝️ **Generic Secrets:** Hardcoded passwords, API keys, and auth tokens in source code

### 🌐 Proxy Chaining (Burp Suite / ZAP)
* Full support for upstream HTTP/HTTPS proxies.
* Route all crawler and brute-force traffic directly through **Burp Suite** (`http://127.0.0.1:8080`) for manual inspection, interception, and repeater testing.

### 💥 Directory & Path Brute-Forcer
* Built-in brute-force engine with **Sequential** and **Parallel** (Thread Pool) modes.
* Automatically populates found directories from the crawler for immediate recursive fuzzing.
* Generates ready-to-use `ffuf` commands via right-click context menus.

### 📊 Interactive Visualizations
* **OSINT Radial Graph:** Interactive node-based graph. Drag nodes, pan, zoom, and hover for details.
* **Tree Command View:** `tree`-style directory mapping displaying **HTTP Status Codes** and **Parameters** inline.
* **Hover Tooltips:** Instantly view full URLs and status codes by hovering over paths.

### 🎨 UI & Export
* **Themes:** Dark (GitHub), Light, and Cyber (Matrix/Hacker) themes.
* **Exports:** JSON, TXT URL lists, Graphviz DOT, and Mermaid Markdown.

---

## 🚀 Installation

ReconWeave is built using **only Python standard libraries** (Tkinter, urllib, re, threading, etc.). No `requirements.txt` or `pip install` is needed!

### Prerequisites
* **Python 3.8+**
* **Tkinter** (Usually bundled with Python on Windows/macOS. Linux users may need to install it):
  ```bash
  # Debian/Ubuntu/Kali
  sudo apt update && sudo apt install python3-tk
  ```

### Setup
```bash
git clone https://github.com/giriaryan694-a11y/ReconWeave.git
cd ReconWeave
python3 main.py
```

---

## 🛠️ Usage Guide

### 1. Basic Crawl
1. Launch `main.py`.
2. Enter your **Target URL** (e.g., `http://testphp.vulnweb.com/`).
3. Check the **"I confirm written authorization"** box.
4. Click **Start Crawl**.
5. Monitor the logs and switch to the **Results & Tables** or **Secrets & OSINT** tabs to view findings.

### 2. Chaining with Burp Suite
1. Open Burp Suite and ensure the Proxy listener is active on `127.0.0.1:8080`.
2. In ReconWeave's **Target Configuration** card, enter `http://127.0.0.1:8080` in the **Proxy** field.
3. Start your crawl or brute-force session. All traffic will now appear in Burp's HTTP History.

### 3. Brute-Forcing Discovered Paths
1. Run a crawl to populate the **Brute Session** tab with discovered directories.
2. Select a directory, choose a wordlist (built-in or custom), and click **Brute Selected**.
3. Right-click any result in the Tree View to instantly copy an `ffuf` or `feroxbuster` command.

---

## 📂 Project Structure

```text
ReconWeave/
├── main.py                 # Main application entry point (Complete standalone script)
├── README.md               # Project documentation
└── LICENSE                 # MIT License
```

---

## 🖥️ Interface Tabs

| Tab | Description |
| :--- | :--- |
| **Crawl** | Target config, proxy settings, crawler options, and live execution logs. |
| **Results & Tables** | Grouped tree or flat table of all pages, links, forms, parameters, and redirects. |
| **Brute Session** | Directory brute-forcer with thread management and custom wordlist support. |
| **Secrets & OSINT** | Dedicated table for leaked AWS keys, tokens, internal IPs, and cloud buckets. |
| **Wordlists / Config** | Manage and test custom brute-force wordlists. |
| **Graph & OSINT View** | Interactive Radial Graph and CLI-style Tree View with status codes. |

---

## 📜 License

This project is licensed under the Apache2.0 License. 

**Credit:** Made by **Aryan Giri** | [giriaryan694-a11y](https://github.com/giriaryan694-a11y)

---

<p align="center">
  <i>Happy Hunting! 🏴‍☠️</i>
</p>
```
