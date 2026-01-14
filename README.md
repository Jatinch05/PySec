# PySec

A concise toolkit of practical Python utilities for cybersecurity tasks. Each tool is CLI-driven, testable, and designed for realistic lab use. Use responsibly and only on assets you own or are authorized to test.

## What this repository contains

* **Port scanner** — high-performance TCP connect scanner with multithreading, banner grabbing, and export options.
* **Recon** — domain reconnaissance including HTTP metadata, DNS enumeration, whois, and subdomain enumeration.
* **Packet sniffer** — Scapy-based capture with lightweight alerting rules (example: SYN-rate detection).
* **File analyzer** — hashing, PE introspection, and YARA scanning for basic static analysis.
* **Mini SIEM** — integration layer that ingests events, matches indicators, and emits alerts.
* **Data** — supporting assets such as wordlists and threat indicator feeds.
* **Tests** — unit tests for core functionality and integration checks.

## Core technologies used

`socket`, `ipaddress`, `threading`, `asyncio` (optional), `requests`, `dnspython`, `scapy`, `pefile`, `yara-python`, `sqlite3`, `pandas`, `argparse`, `logging`.

## Quick start

1. Clone the repository:

```bash
git clone https://github.com/<your-org>/pysec.git
cd pysec
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate    # Linux / macOS
.\.venv\Scripts\activate   # Windows PowerShell
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run any tool with `--help` to see available options:

```bash
python tools/port_scanner.py --help
```

## Validation checklist

* Scanner completes a /24 scan within reasonable time and exports results.
* Recon produces structured output with DNS, HTTP headers, and whois information.
* Sniffer generates at least one synthetic alert under test traffic.
* File analyzer yields correct hashes and enumerates PE imports for Windows binaries.
* Mini SIEM ingests events and writes alerts for matching indicators.

## Security and ethics

Only test systems you own or have explicit permission to test. Handle malware samples and indicators in isolated, controlled environments.

## License — MIT

```
MIT License

Copyright (c) 2025 Jatin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
