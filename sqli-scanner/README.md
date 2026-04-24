# 🔍 SQLi Scanner

A lightweight, command-line SQL injection vulnerability scanner written in Python. Built for use in authorized penetration testing engagements, CTF challenges, and web security learning environments.

---

## ⚠️ Legal Disclaimer

> This tool is intended **solely** for authorized security testing and educational purposes.  
> **Do not run this against any system you do not own or have explicit written permission to test.**  
> Unauthorized use may violate computer fraud laws in your jurisdiction.

Tested on: DVWA, bWAPP, HackTheBox, TryHackMe labs.

---

## Features

- **Error-based detection** — identifies SQL syntax errors leaked in HTTP responses
- **Time-based blind detection** — detects `SLEEP()` / `WAITFOR DELAY` response delays
- **Multi-parameter support** — tests all URL query parameters automatically
- **Custom payload lists** — drop in your own `.txt` payload file
- **Automatic report generation** — saves findings to a timestamped `.txt` report
- **Clean terminal output** — colour-coded results (degrades gracefully on Windows)
- **Configurable rate limiting** — adjustable delay between requests to avoid triggering WAFs

---

## Installation

```bash
git clone https://github.com/yourusername/sqli-scanner.git
cd sqli-scanner
pip install -r requirements.txt
```

**Requirements:** Python 3.8+

---

## Usage

### Basic scan (all parameters)
```bash
python3 sqli_scanner.py -u "http://testsite.com/item?id=1"
```

### Scan with a custom payload file
```bash
python3 sqli_scanner.py -u "http://testsite.com/item?id=1" --payloads payloads.txt
```

### Scan a specific parameter only
```bash
python3 sqli_scanner.py -u "http://testsite.com/search?q=test&page=1" --params q
```

### Save output to a report file
```bash
python3 sqli_scanner.py -u "http://testsite.com/item?id=1" --output report.txt
```

### Slow down requests (bypass simple rate-limiting)
```bash
python3 sqli_scanner.py -u "http://testsite.com/item?id=1" --delay 1.5
```

### All options
```
-u, --url        Target URL with query parameters (required)
--payloads       Path to custom payload file (one per line)
--params         Comma-separated parameter names to test
--timeout        Request timeout in seconds (default: 8)
--delay          Delay between requests in seconds (default: 0.3)
--output         Output report file path
```

---

## Example Output

```
╔═══════════════════════════════════════════════════╗
║   SQLi Scanner v1.0  |  Authorized Testing Only   ║
╚═══════════════════════════════════════════════════╝

[+] Target     : http://testsite.com/item?id=1
[+] Parameters : id
[+] Payloads   : 30
[+] Timeout    : 8s  |  Delay: 0.3s

[*] Baseline → HTTP 200 | 4821 bytes
[*] Testing parameter: id

[VULN] param=id  type=error-based  payload="'"
[VULN] param=id  type=error-based  payload="' OR 1=1 --"
[VULN] param=id  type=time-based blind  payload="' AND SLEEP(3) --"

──────────────────────────────────────────────────
[!] 3 vulnerability/ies detected.
    Review the findings carefully before reporting.
──────────────────────────────────────────────────
[+] Report saved → sqli_report_20260501_142301.txt
```

---

## Safe Testing Environments

Use this tool legally against these intentionally vulnerable targets:

| Target | Type | Link |
|--------|------|------|
| DVWA | Local VM | https://dvwa.co.uk |
| bWAPP | Local VM | http://www.itsecgames.com |
| HackTheBox | Online labs | https://hackthebox.com |
| TryHackMe | Online labs | https://tryhackme.com |
| WebGoat | Local / Docker | https://owasp.org/www-project-webgoat |

---

## How It Works

1. **Parses** all query parameters from the target URL
2. **Sends a baseline** request to record the normal response
3. **Injects** each payload into each parameter, one at a time
4. **Checks** the response for:
   - SQL error strings from MySQL, PostgreSQL, MSSQL, Oracle, SQLite
   - Abnormal response delays (≥ 2.8s) on time-based payloads
5. **Reports** all confirmed findings with payload, parameter, and detection type

---

## Limitations

- Tests **GET parameters only** (POST body injection not yet implemented)
- Does not support **authenticated sessions** (cookie-based auth)
- Time-based detection may produce false positives on slow connections
- Not a replacement for manual testing or tools like `sqlmap` for deep assessment

---

## Planned Improvements

- [ ] POST request support
- [ ] Cookie/header injection testing
- [ ] JSON body parameter testing
- [ ] HTML report output
- [ ] Integration with a proxy (Burp Suite / OWASP ZAP)

---

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQLi Guide](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
