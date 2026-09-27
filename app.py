"""
Vulnerability Detection Web App
Upload a file or .zip project folder → get a full vulnerability report in your browser.
"""

import os, re, json, uuid, zipfile, shutil, datetime, threading, stat
from pathlib import Path
from flask import Flask, request, render_template_string, jsonify, redirect, url_for

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   # 50 MB max upload
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────
#  In-memory job store  {job_id: {...}}
# ─────────────────────────────────────────────
jobs = {}

# ══════════════════════════════════════════════
#  SAST ENGINE  (same rules as vuln_detector.py)
# ══════════════════════════════════════════════
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SAST_RULES = {
    r"\.py$": [
        (r"eval\s*\(",             "CRITICAL", "Use of eval()",                        "Avoid eval(); use ast.literal_eval()."),
        (r"exec\s*\(",             "CRITICAL", "Use of exec()",                        "Avoid exec() with untrusted input."),
        (r"os\.system\s*\(",       "HIGH",     "Shell injection via os.system()",      "Use subprocess with list args."),
        (r"subprocess\..*shell\s*=\s*True","HIGH","subprocess shell=True",            "Pass command as list; avoid shell=True."),
        (r"pickle\.loads?\s*\(",   "HIGH",     "Insecure deserialization (pickle)",    "Never unpickle untrusted data."),
        (r"hashlib\.md5\s*\(",     "MEDIUM",   "Weak hashing: MD5",                   "Use SHA-256 or bcrypt."),
        (r"hashlib\.sha1\s*\(",    "MEDIUM",   "Weak hashing: SHA-1",                 "Use SHA-256 or bcrypt."),
        (r"random\.\w+\(",         "LOW",      "Insecure random (use secrets module)", "Use the secrets module."),
        (r"DEBUG\s*=\s*True",      "MEDIUM",   "Debug mode enabled",                  "Disable DEBUG in production."),
        (r"SECRET_KEY\s*=\s*['\"][\w\-@#$!%^&*]+['\"]","HIGH","Hardcoded SECRET_KEY","Load from environment variable."),
        (r"password\s*=\s*['\"].+['\"]","HIGH","Hardcoded password",                  "Use environment variables."),
        (r"yaml\.load\s*\(",       "HIGH",     "Unsafe yaml.load()",                  "Use yaml.safe_load() instead."),
        (r"open\(.*['\"]w['\"]",   "LOW",      "File write – verify path sanitization","Sanitize paths to prevent traversal."),
        (r"assert\s+",             "LOW",      "assert (stripped with -O flag)",       "Use proper error handling."),
        (r"\.format\(.*request\.", "MEDIUM",   "Potential format-string injection",    "Validate request data before formatting."),
        (r"flask.*debug\s*=\s*True","MEDIUM",  "Flask debug mode on",                 "Never run Flask with debug=True in production."),
        (r"app\.run\(.*debug\s*=\s*True","MEDIUM","Flask debug=True in app.run()",    "Set debug=False in production."),
        (r"\.execute\s*\(\s*f[\"']|\.execute\s*\(.*%s.*%\s*\(","HIGH","Possible SQL injection in query construction","Use parameterized query placeholders; do not interpolate values."),
        (r"requests\.(get|post|put|delete)\s*\(.*verify\s*=\s*False","MEDIUM","TLS certificate verification disabled","Keep certificate verification enabled; configure a trusted CA when needed."),
        (r"subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True","HIGH","Shell execution enabled for subprocess","Pass an argument list and keep shell=False."),
        (r"\b(hashlib\.(md5|sha1)|md5|sha1)\s*\(","MEDIUM","Weak hash function","Use SHA-256 for integrity or a password hashing function for credentials."),
        (r"@app\.route.*methods.*['\"]GET['\"].*password","MEDIUM","Password over GET","Never send passwords via GET."),
        (r"render_template_string\s*\(.*request\.\w+","HIGH","SSTI via render_template_string","Never pass raw user input to render_template_string."),
    ],
    r"\.[jt]sx?$": [
        (r"eval\s*\(",             "CRITICAL", "Use of eval() – XSS/RCE risk",        "Never use eval() with user input."),
        (r"innerHTML\s*=",         "HIGH",     "innerHTML assignment – XSS risk",      "Use textContent or DOMPurify."),
        (r"document\.write\s*\(",  "HIGH",     "document.write() – XSS risk",         "Avoid document.write()."),
        (r"dangerouslySetInnerHTML","HIGH",    "React dangerouslySetInnerHTML",        "Sanitize HTML before use."),
        (r"localStorage\.setItem\s*\(.*(?:password|token|secret)","HIGH","Sensitive data in localStorage","Never store credentials in localStorage."),
        (r"Math\.random\s*\(",     "LOW",      "Math.random() not cryptographically secure","Use crypto.getRandomValues()."),
        (r"new Function\s*\(",     "CRITICAL", "new Function() – code injection",     "Avoid new Function() with user input."),
        (r"\.exec\s*\(",           "MEDIUM",   "exec() call – verify usage",           "Sanitize inputs."),
        (r"http://",               "LOW",      "Plain HTTP URL",                       "Use HTTPS."),
        (r"fetch\s*\(.*\+\s*\w+","MEDIUM","Dynamic URL construction in fetch()","Validate URL inputs and restrict allowed origins."),
        (r"\b(postMessage)\s*\([^\n]*,\s*['\"]\*['\"]","HIGH","postMessage sent to any origin","Specify the exact trusted target origin."),
    ],
    r"\.php$": [
        (r"eval\s*\(",             "CRITICAL", "eval() – Remote Code Execution",       "Never use eval() with user input."),
        (r"mysql_query\s*\(",      "CRITICAL", "Deprecated mysql_query – SQLi risk",   "Use PDO with prepared statements."),
        (r"mysqli_query\s*\(.*\$", "HIGH",     "Possible SQLi via mysqli_query",       "Use prepared statements."),
        (r"system\s*\(|shell_exec\s*\(|exec\s*\(|passthru\s*\(","CRITICAL","Shell execution function","Never pass user input to shell."),
        (r"include\s*\(\s*\$|require\s*\(\s*\$","HIGH","Dynamic file inclusion – LFI/RFI","Whitelist allowed files."),
        (r"md5\s*\(",              "MEDIUM",   "MD5 used – weak for passwords",        "Use password_hash() with PASSWORD_BCRYPT."),
        (r"base64_decode\s*\(",    "MEDIUM",   "base64_decode() – possible obfuscated payload","Audit all usages."),
        (r"extract\s*\(\s*\$_",   "HIGH",     "extract() on superglobals",            "Never use extract() on user input."),
        (r"\$_GET\[|\$_POST\[|\$_REQUEST\[","MEDIUM","Unvalidated superglobal input", "Validate/sanitize all inputs."),
        (r"\b(?:SELECT|UPDATE|DELETE|INSERT)\b.*\$[A-Za-z_]","HIGH","Possible SQL injection via interpolated variable","Use prepared statements with bound parameters."),
        (r"header\s*\(.*Location.*\$","HIGH",  "Unvalidated redirect",                "Validate redirect destinations."),
    ],
    r"\.java$": [
        (r"Runtime\.getRuntime\(\)\.exec","CRITICAL","Runtime.exec() – command injection","Use ProcessBuilder with validated inputs."),
        (r"new ObjectInputStream",  "HIGH",    "Java deserialization – RCE risk",      "Validate serialized objects."),
        (r"MessageDigest\.getInstance\s*\(\s*['\"]MD5","MEDIUM","MD5 – weak hashing", "Use SHA-256 or stronger."),
        (r"System\.out\.println.*password","MEDIUM","Password logged to stdout",       "Never log credentials."),
        (r"\.executeQuery\s*\(.*\+","CRITICAL","String-concat SQL query – SQLi",       "Use PreparedStatement."),
        (r"catch\s*\(Exception\s+\w+\s*\)\s*\{?\s*\}","LOW","Swallowed exception",    "Log or rethrow exceptions."),
    ],
    r"\.go$": [
        (r"exec\.Command\s*\(.*\+","HIGH",     "Command injection via exec.Command",  "Never concatenate user input into commands."),
        (r"fmt\.Sprintf.*\bSELECT\b","HIGH",   "String-formatted SQL query – SQLi",   "Use parameterized queries."),
        (r"md5\.",                  "MEDIUM",   "MD5 usage – weak hashing",            "Use SHA-256 or bcrypt."),
        (r"math/rand",              "LOW",      "math/rand – not cryptographically secure","Use crypto/rand."),
    ],
    r"\.cs$": [
        (r"\b(?:SqlCommand|ExecuteSqlCommand)\s*\([^\n]*\+","HIGH","Possible SQL injection via string concatenation","Use parameterized queries and bind values."),
        (r"Process\.Start\s*\([^\n]*\+","HIGH","Possible command injection in Process.Start","Use fixed executable paths and validated argument lists."),
        (r"JavaScriptSerializer|BinaryFormatter","HIGH","Unsafe or legacy deserialization API","Use a safe serializer and restrict input types."),
        (r"ServerCertificateValidationCallback\s*=\s*.*=>\s*true","HIGH","TLS certificate validation disabled","Validate certificates against trusted issuers."),
    ],
    r"\.(c|cc|cpp|h|hpp)$": [
        (r"\bgets\s*\(","HIGH","Unsafe gets() can overflow a buffer","Use bounded input functions and validate lengths."),
        (r"\bstrcpy\s*\(|\bstrcat\s*\(","MEDIUM","Unbounded string copy or concatenation","Use length-bounded operations and verify destination capacity."),
        (r"\bsprintf\s*\(","MEDIUM","Unbounded sprintf() call","Use snprintf() with a verified destination size."),
        (r"\b(system|popen)\s*\(","HIGH","Shell command execution","Avoid shell execution or strictly validate all command inputs."),
    ],
    r"\.rb$": [
        (r"eval\s*\(",             "CRITICAL", "eval() – RCE risk",                   "Never eval user input."),
        (r"system\s*\(",           "HIGH",     "system() – command injection",         "Sanitize all inputs."),
        (r"MD5\.hexdigest",        "MEDIUM",   "MD5 – weak hashing",                  "Use bcrypt or SHA-256."),
        (r"params\[.*\]\s*\.html_safe","HIGH", ".html_safe on user input – XSS",      "Never call html_safe on user data."),
    ],
    r"\.(env|ini|cfg|conf|config|properties)$": [
        (r"(?i)(password|passwd|pwd|secret|key|token)\s*[=:]\s*\S+","HIGH","Hardcoded credential in config","Use environment variable references."),
        (r"(?i)(aws_access_key_id|aws_secret)","CRITICAL","AWS credential in config file","Rotate immediately; use IAM roles."),
    ],
    r"\.(yaml|yml)$": [
        (r"(?i)(password|secret|token|key)\s*:\s*\S+","HIGH","Hardcoded secret in YAML","Use environment variable references."),
        (r"(?i)(aws_access_key_id|AKIA[A-Z0-9]{16})","CRITICAL","AWS key in YAML file","Rotate immediately."),
    ],
    r".*": [
        (r"(?i)(password|passwd|api.?key|secret|token|auth)\s*[=:]\s*['\"][\w\-@#$!%^&*]{4,}['\"]","HIGH","Hardcoded credential","Move to env vars or secrets manager."),
        (r"(?i)(AKIA[A-Z0-9]{16})","CRITICAL","AWS Access Key ID exposed","Rotate immediately; use IAM roles."),
        (r"(?i)(BEGIN RSA PRIVATE KEY|BEGIN EC PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY)","CRITICAL","Private key in source","Remove from source; use secrets manager."),
        (r"(?i)http://[^\s\"']+","LOW","Plain HTTP URL","Use HTTPS."),
        (r"(?i)(TODO|FIXME|HACK|XXX).*(vuln|secur|auth|sql|xss|inject)","INFO","Security-related TODO","Address before deploying."),
    ],
}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv",
             "dist", "build", ".tox", "vendor", "env", ".env"}

# Keep archive scans bounded and reject paths that could escape the upload area.
MAX_ARCHIVE_FILES = 10000
MAX_EXTRACTED_BYTES = 200 * 1024 * 1024
MAX_MEMBER_BYTES = 25 * 1024 * 1024

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java",
    ".rb", ".go", ".cs", ".cpp", ".c", ".h",
    ".env", ".json", ".yaml", ".yml", ".xml",
    ".conf", ".cfg", ".ini", ".config", ".properties",
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
                            results.append({
                                "severity": severity,
                                "type": desc,
                                "description": desc,
                                "file": str(filepath.name),
                                "line": i,
                                "code": line.strip()[:120],
                                "remediation": fix,
                            })
    except Exception:
        pass
    return results

def run_sast(scan_root: Path):
    all_findings = []
    files_scanned = []
    if scan_root.is_file():
        files_scanned = [scan_root]
    else:
        for f in scan_root.rglob("*"):
            if f.is_file() and f.suffix.lower() in SCAN_EXTENSIONS:
                if not any(part in SKIP_DIRS for part in f.parts):
                    files_scanned.append(f)

    for f in files_scanned:
        for finding in sast_scan_file(f):
            # make file path relative to scan root
            try:
                finding["file"] = str(f.relative_to(scan_root if scan_root.is_dir() else scan_root.parent))
            except Exception:
                finding["file"] = f.name
            all_findings.append(finding)

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return all_findings, len(files_scanned)


def safe_extract_zip(archive: Path, destination: Path):
    """Extract regular files only; reject traversal, links, and oversized archives."""
    with zipfile.ZipFile(archive) as zf:
        members = [m for m in zf.infolist() if not m.is_dir()]
        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError(f"Archive contains too many files (limit {MAX_ARCHIVE_FILES:,}).")
        total = 0
        root = destination.resolve()
        for member in members:
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("Archive contains a symbolic link; scan cancelled for safety.")
            if member.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"Archive member exceeds the {MAX_MEMBER_BYTES // (1024 * 1024)} MB limit.")
            total += member.file_size
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError("Archive expands beyond the 200 MB scan limit.")
            target = (root / member.filename).resolve()
            if target != root and root not in target.parents:
                raise ValueError("Archive contains an unsafe path; scan cancelled for safety.")
        extracted = 0
        for member in members:
            target = (root / member.filename).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as source, target.open("wb") as output:
                member_bytes = 0
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    member_bytes += len(chunk)
                    extracted += len(chunk)
                    if member_bytes > MAX_MEMBER_BYTES or extracted > MAX_EXTRACTED_BYTES:
                        raise ValueError("Archive expands beyond the allowed scan size.")
                    output.write(chunk)


# ══════════════════════════════════════════════
#  BACKGROUND SCAN WORKER
# ══════════════════════════════════════════════
def scan_worker(job_id, scan_path: Path):
    jobs[job_id]["status"] = "scanning"
    try:
        findings, file_count = run_sast(scan_path)
        summary = {s: sum(1 for f in findings if f["severity"] == s)
                   for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
        jobs[job_id].update({
            "status": "done",
            "findings": findings,
            "summary": summary,
            "file_count": file_count,
            "finished_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)
    finally:
        # Remove the complete per-job directory for both single files and archives.
        try:
            shutil.rmtree(scan_path.parent, ignore_errors=True)
        except Exception:
            pass


# ══════════════════════════════════════════════
#  HTML TEMPLATES
# ══════════════════════════════════════════════
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnDetect – Code Scanner</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh;display:flex;flex-direction:column;align-items:center}
header{width:100%;background:linear-gradient(135deg,#161b22,#1f2937);border-bottom:1px solid #30363d;padding:22px 40px;text-align:center}
header h1{font-size:1.9em;color:#58a6ff;letter-spacing:1px}
header p{color:#8b949e;margin-top:6px;font-size:0.95em}
.container{width:100%;max-width:700px;margin:50px auto;padding:0 20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:40px;text-align:center}
.card h2{font-size:1.3em;color:#c9d1d9;margin-bottom:8px}
.card p{color:#8b949e;font-size:0.9em;margin-bottom:30px}
.drop-zone{border:2px dashed #30363d;border-radius:12px;padding:50px 30px;cursor:pointer;transition:all .2s;position:relative}
.drop-zone:hover,.drop-zone.dragover{border-color:#58a6ff;background:#1c2840}
.drop-zone .icon{font-size:3em;margin-bottom:12px}
.drop-zone p{color:#8b949e;font-size:0.95em;margin:0}
.drop-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
.file-name{margin-top:14px;color:#58a6ff;font-size:0.9em;min-height:20px}
.btn{display:inline-block;margin-top:22px;padding:12px 36px;background:#238636;color:#fff;border:none;border-radius:8px;font-size:1em;cursor:pointer;transition:background .2s;font-weight:600}
.btn:hover{background:#2ea043}
.btn:disabled{background:#3d4451;cursor:not-allowed}
.supported{margin-top:26px;color:#484f58;font-size:0.82em}
.supported span{color:#58a6ff}
.progress-wrap{display:none;margin-top:24px}
.progress-bar{height:6px;background:#21262d;border-radius:4px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,#238636,#58a6ff);width:0%;transition:width .4s;animation:scan 1.5s linear infinite}
@keyframes scan{0%{background-position:0%}100%{background-position:200%}}
.scan-msg{color:#8b949e;font-size:0.85em;margin-top:10px;text-align:center}
/* Focused responsive dashboard treatment */
body{background:#0b1020;color:#edf2f7;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:rgba(12,18,34,.88);border-bottom:1px solid #202b42;backdrop-filter:blur(16px)}
header h1{color:#eaf1ff;letter-spacing:-.04em} header h1:first-letter{color:#70e1c1}
header p{color:#94a3b8}
.container{max-width:880px;margin:64px auto}
.card{background:linear-gradient(145deg,#141d32,#101827);border-color:#263550;border-radius:22px;padding:clamp(24px,5vw,52px);box-shadow:0 28px 80px #0005}
.card h2{font-size:1.65rem;letter-spacing:-.035em;color:#f1f5f9}
.card>p{color:#9cabc0;margin-bottom:26px}
.drop-zone{border:1px dashed #3a4c6b;background:#0d1526;border-radius:16px;padding:56px 24px}
.drop-zone:hover,.drop-zone.dragover{border-color:#70e1c1;background:#102333;box-shadow:inset 0 0 0 1px #70e1c133}
.drop-zone .icon{font-size:2.5em}.drop-zone p{color:#d4deed;line-height:1.8}
.file-name{color:#70e1c1;overflow-wrap:anywhere}
.btn{background:#43c6a4;color:#06231d;border-radius:10px;padding:13px 24px;font-weight:750}
.btn:hover{background:#70e1c1}.btn:focus-visible,.back-btn:focus-visible,.export-btn:focus-visible{outline:3px solid #70e1c1;outline-offset:3px}
.supported{color:#8190a7;line-height:1.8}.supported span{color:#b4c4dc}
@media(max-width:600px){header{padding:20px 18px}header h1{font-size:1.45em}.container{margin:28px auto}.card{padding:24px 18px}.drop-zone{padding:38px 16px}.btn{width:100%}}
</style>
</head>
<body>
<header>
  <h1>&#x1F512; VulnDetect – Code Scanner</h1>
  <p>Upload a source file or a <strong>.zip</strong> of your project — get a full vulnerability report instantly</p>
</header>
<div class="container">
  <div class="card">
    <h2>Upload Your Code</h2>
    <p>Supports single files or a <strong>.zip</strong> of an entire project directory</p>
    <form id="uploadForm" method="POST" action="/scan" enctype="multipart/form-data">
      <div class="drop-zone" id="dropZone">
        <div class="icon">&#x1F4C2;</div>
        <p>Drag &amp; drop your file here<br><small>or click to browse</small></p>
      <input type="file" name="file" id="fileInput" accept=".py,.js,.ts,.jsx,.tsx,.php,.java,.rb,.go,.cs,.c,.h,.cpp,.cc,.hpp,.zip,.env,.yml,.yaml,.json,.xml,.ini,.conf,.cfg,.config,.properties">
      </div>
      <div class="file-name" id="fileName">No file selected</div>
      <button class="btn" type="submit" id="scanBtn" disabled>&#x1F50D; Scan for Vulnerabilities</button>
      <div class="progress-wrap" id="progressWrap">
        <div class="progress-bar"><div class="progress-fill"></div></div>
        <div class="scan-msg">Scanning your code... please wait</div>
      </div>
    </form>
    <div class="supported">
      Scans Python, JavaScript/TypeScript, PHP, Java, Ruby, Go, C/C++, C# and common config files.<br>
      <span>Single file or .zip · 50 MB upload limit · ZIP extraction is bounded and path-checked</span><br>
      Static pattern analysis surfaces review candidates; findings need context and are not proof of exploitability.
    </div>
  </div>
</div>
<script>
const dz=document.getElementById('dropZone');
const fi=document.getElementById('fileInput');
const fn=document.getElementById('fileName');
const btn=document.getElementById('scanBtn');
const form=document.getElementById('uploadForm');
const pw=document.getElementById('progressWrap');
fi.addEventListener('change',()=>{
  if(fi.files[0]){fn.textContent='Selected: '+fi.files[0].name;btn.disabled=false;}
});
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('dragover');});
dz.addEventListener('dragleave',()=>dz.classList.remove('dragover'));
dz.addEventListener('drop',e=>{
  e.preventDefault();dz.classList.remove('dragover');
  if(e.dataTransfer.files[0]){
    fi.files=e.dataTransfer.files;
    fn.textContent='Selected: '+e.dataTransfer.files[0].name;
    btn.disabled=false;
  }
});
form.addEventListener('submit',()=>{
  btn.disabled=true;btn.textContent='Scanning...';
  pw.style.display='block';
});
</script>
</body>
</html>"""

REPORT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3}
header{background:linear-gradient(135deg,#161b22,#1f2937);border-bottom:1px solid #30363d;padding:24px 40px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
header h1{font-size:1.6em;color:#58a6ff}
header .meta{color:#8b949e;font-size:0.85em;text-align:right}
.container{max-width:1400px;margin:0 auto;padding:30px 40px}
.summary{display:flex;gap:16px;margin-bottom:30px;flex-wrap:wrap}
.scard{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 24px;flex:1;min-width:110px;text-align:center;border-top:3px solid var(--c)}
.scard .num{font-size:2.4em;font-weight:700;color:var(--c)}
.scard .lbl{font-size:0.78em;color:#8b949e;margin-top:4px;letter-spacing:1px;text-transform:uppercase}
.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;align-items:center}
.filters label{color:#8b949e;font-size:0.88em}
.filter-btn{padding:6px 16px;border-radius:20px;border:1px solid #30363d;background:#161b22;color:#8b949e;cursor:pointer;font-size:0.82em;transition:all .15s}
.filter-btn.active,.filter-btn:hover{background:#1f2937;color:#e6edf3;border-color:#58a6ff}
.filter-btn[data-sev="CRITICAL"].active{background:#3d0f0f;border-color:#f85149;color:#f85149}
.filter-btn[data-sev="HIGH"].active{background:#2d1800;border-color:#e3632a;color:#e3632a}
.filter-btn[data-sev="MEDIUM"].active{background:#2b2200;border-color:#e3b341;color:#e3b341}
.filter-btn[data-sev="LOW"].active{background:#001433;border-color:#58a6ff;color:#58a6ff}
.filter-btn[data-sev="INFO"].active{background:#1a1f2e;border-color:#8b949e;color:#8b949e}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:12px;overflow:hidden}
th{background:#1f2937;padding:11px 16px;text-align:left;color:#8b949e;font-size:0.78em;letter-spacing:1px;text-transform:uppercase;white-space:nowrap}
td{padding:12px 16px;border-bottom:1px solid #21262d;vertical-align:top;font-size:0.88em}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2332}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.75em;font-weight:700;letter-spacing:.5px;white-space:nowrap}
.CRITICAL{background:#3d0f0f;color:#f85149;border:1px solid #f85149}
.HIGH{background:#2d1800;color:#e3632a;border:1px solid #e3632a}
.MEDIUM{background:#2b2200;color:#e3b341;border:1px solid #e3b341}
.LOW{background:#001433;color:#58a6ff;border:1px solid #58a6ff}
.INFO{background:#1a1f2e;color:#8b949e;border:1px solid #8b949e}
.code-snippet{font-family:'Courier New',monospace;background:#0d1117;padding:4px 8px;border-radius:5px;font-size:0.8em;color:#f0883e;word-break:break-all;margin-top:4px;border-left:2px solid #30363d}
.file-loc{color:#58a6ff;font-size:0.82em}
.line-no{color:#8b949e;font-size:0.8em}
.fix{color:#3fb950;font-size:0.82em}
.none-msg{text-align:center;padding:60px;color:#484f58;font-size:1.1em}
.back-btn{padding:8px 20px;background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:8px;text-decoration:none;font-size:0.88em;transition:background .2s}
.back-btn:hover{background:#30363d}
.search-box{padding:7px 14px;background:#21262d;border:1px solid #30363d;border-radius:8px;color:#e6edf3;font-size:0.88em;width:220px;outline:none}
.search-box:focus{border-color:#58a6ff}
.export-btn{padding:7px 16px;background:#1f2937;border:1px solid #30363d;border-radius:8px;color:#8b949e;font-size:0.82em;cursor:pointer;transition:all .2s}
.export-btn:hover{background:#30363d;color:#e6edf3}
.no-findings{background:#0d2b0d;border:1px solid #238636;color:#3fb950;padding:18px 24px;border-radius:10px;text-align:center;font-size:1em;margin-top:10px}
body{background:#0b1020;color:#edf2f7;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:#0e1729;border-color:#202b42}header h1{color:#eaf1ff;letter-spacing:-.035em}
.container{max-width:1480px}.scard,table{background:#121b2d;border-color:#263550}.scard{border-radius:14px}
.scard .lbl{letter-spacing:.08em}.filters{gap:8px}.filter-btn{border-color:#34435d;background:#121b2d;color:#aebbd0}
.filter-btn.active,.filter-btn:hover{background:#1a2940;border-color:#70e1c1;color:#eaf1ff}
.search-box{background:#10192a;border-color:#34435d}.search-box:focus{border-color:#70e1c1}
th{background:#19253a;color:#aebbd0}td{border-color:#202b42}tr:hover td{background:#19243a}
.file-loc{color:#9bbaf4}.fix{color:#70e1c1}.code-snippet{background:#0b1020;color:#ffbd8b}
.back-btn,.export-btn{background:#172238;border-color:#34435d;color:#d9e3f2}
.no-findings{background:#102b29;border-color:#286455;color:#70e1c1}
@media(max-width:900px){.container{padding:24px 18px}header{padding:20px;align-items:flex-start}.summary{gap:10px}.scard{min-width:100px;padding:14px}.scard .num{font-size:1.8em}table{display:block;overflow-x:auto;white-space:normal}}
</style>
</head>
<body>
<header>
  <div>
    <h1>&#x1F512; Vulnerability Report</h1>
    <div style="color:#8b949e;font-size:0.85em;margin-top:4px">
      File: <strong style="color:#c9d1d9">{{ filename }}</strong> &nbsp;|&nbsp;
      Files scanned: <strong style="color:#c9d1d9">{{ file_count }}</strong>
    </div>
  </div>
  <div class="meta">
    {{ finished_at }}<br>
    <a href="/" class="back-btn" style="display:inline-block;margin-top:8px">&#x2190; New Scan</a>
    &nbsp;
    <button class="export-btn" onclick="exportJSON()">&#x1F4E5; Export JSON</button>
  </div>
</header>

<div class="container">
  <!-- Summary cards -->
  <div class="summary">
    {% set colors = {"CRITICAL":"#f85149","HIGH":"#e3632a","MEDIUM":"#e3b341","LOW":"#58a6ff","INFO":"#8b949e"} %}
    {% for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] %}
    <div class="scard" style="--c:{{ colors[sev] }}">
      <div class="num">{{ summary.get(sev,0) }}</div>
      <div class="lbl">{{ sev }}</div>
    </div>
    {% endfor %}
    <div class="scard" style="--c:#3fb950">
      <div class="num">{{ findings|length }}</div>
      <div class="lbl">TOTAL</div>
    </div>
  </div>

  {% if findings %}
  <!-- Filters -->
  <div class="filters">
    <label>Filter:</label>
    <button class="filter-btn active" data-sev="ALL" onclick="filterFindings('ALL',this)">All</button>
    {% for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] %}
    {% if summary.get(sev,0) > 0 %}
    <button class="filter-btn" data-sev="{{ sev }}" onclick="filterFindings('{{ sev }}',this)">{{ sev }} ({{ summary.get(sev,0) }})</button>
    {% endif %}
    {% endfor %}
    <input class="search-box" type="text" id="searchBox" placeholder="Search findings..." onkeyup="searchFindings()">
  </div>

  <!-- Table -->
  <table id="findingsTable">
    <thead>
      <tr>
        <th>#</th>
        <th>Severity</th>
        <th>Vulnerability</th>
        <th>File &amp; Line</th>
        <th>Code Snippet</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr data-sev="{{ f.severity }}">
        <td style="color:#484f58">{{ loop.index }}</td>
        <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
        <td><strong>{{ f.type }}</strong></td>
        <td>
          <div class="file-loc">{{ f.file }}</div>
          <div class="line-no">Line {{ f.line }}</div>
        </td>
        <td><div class="code-snippet">{{ f.code }}</div></td>
        <td><div class="fix">{{ f.remediation }}</div></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  {% else %}
  <div class="no-findings">
    &#x2705; No vulnerabilities detected in the uploaded code!
  </div>
  {% endif %}
</div>

<script>
const allFindings = {{ findings|tojson }};
let currentSev = 'ALL';

function filterFindings(sev, btn){
  currentSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}
function searchFindings(){ applyFilters(); }
function applyFilters(){
  const q = document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('#findingsTable tbody tr').forEach(row=>{
    const sev = row.dataset.sev;
    const text = row.textContent.toLowerCase();
    const sevMatch = currentSev==='ALL' || sev===currentSev;
    const searchMatch = !q || text.includes(q);
    row.style.display = (sevMatch && searchMatch) ? '' : 'none';
  });
}
function exportJSON(){
  const blob = new Blob([JSON.stringify(allFindings,null,2)],{type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'vuln_report.json';
  a.click();
}
</script>
</body>
</html>"""

ERROR_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan could not start</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#edf2f7;font:16px system-ui}main{max-width:560px;margin:24px;padding:32px;border:1px solid #34435d;border-radius:18px;background:#121b2d}h1{font-size:1.35rem}p{color:#aebbd0;line-height:1.6}a{color:#70e1c1}</style></head>
<body><main><h1>We couldn’t start this scan</h1><p>{{ error }}</p><a href="/">Back to scanner</a></main></body></html>"""

WAIT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scanning...</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
.card{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:50px 60px;text-align:center;max-width:480px;width:100%;margin:20px}
.spinner{width:56px;height:56px;border:5px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:spin 0.9s linear infinite;margin:0 auto 24px}
@keyframes spin{to{transform:rotate(360deg)}}
h2{font-size:1.4em;color:#c9d1d9;margin-bottom:10px}
p{color:#8b949e;font-size:0.92em}
.dots::after{content:'';animation:dots 1.5s steps(4,end) infinite}
@keyframes dots{0%,100%{content:''}25%{content:'.'}50%{content:'..'}75%{content:'...'}}
</style>
<script>
// Poll every 1.5s until done
function poll(){
  fetch('/status/{{ job_id }}')
    .then(r=>r.json())
    .then(d=>{
      if(d.status==='done') window.location='/report/{{ job_id }}';
      else if(d.status==='error') window.location='/error/{{ job_id }}';
      else setTimeout(poll,1500);
    });
}
window.onload=()=>setTimeout(poll,1500);
</script>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h2>Scanning your code<span class="dots"></span></h2>
  <p>Running SAST analysis across your files.<br>This may take a few seconds.</p>
</div>
</body>
</html>"""


# ══════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/scan", methods=["POST"])
def scan():
    f = request.files.get("file")
    if not f or not f.filename:
        return redirect(url_for("index"))

    job_id = str(uuid.uuid4())[:8]
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    filename = Path(f.filename.replace("\\", "/")).name
    if not filename:
        return redirect(url_for("index"))
    save_path = job_dir / filename
    f.save(save_path)

    # If zip → extract
    if filename.lower().endswith(".zip"):
        extract_dir = job_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        try:
            safe_extract_zip(save_path, extract_dir)
        except (zipfile.BadZipFile, ValueError, OSError, RuntimeError) as exc:
            shutil.rmtree(job_dir, ignore_errors=True)
            return render_template_string(ERROR_HTML, error=str(exc)), 400
        scan_path = extract_dir
    else:
        if Path(filename).suffix.lower() not in SCAN_EXTENSIONS:
            shutil.rmtree(job_dir, ignore_errors=True)
            return render_template_string(ERROR_HTML, error="This file type is not supported. Upload source or configuration files listed on the scan page."), 400
        scan_path = save_path

    jobs[job_id] = {
        "status": "queued",
        "filename": filename,
        "scan_path": str(scan_path),
        "started_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    t = threading.Thread(target=scan_worker, args=(job_id, scan_path), daemon=True)
    t.start()

    return render_template_string(WAIT_HTML, job_id=job_id)

@app.route("/status/<job_id>")
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"status": "error", "error": "Job not found"})
    return jsonify({"status": job["status"]})

@app.route("/report/<job_id>")
def report(job_id):
    job = jobs.get(job_id)
    if not job or job["status"] != "done":
        return redirect(url_for("index"))
    return render_template_string(
        REPORT_HTML,
        filename=job["filename"],
        file_count=job["file_count"],
        findings=job["findings"],
        summary=job["summary"],
        finished_at=job["finished_at"],
    )

@app.route("/error/<job_id>")
def error_page(job_id):
    job = jobs.get(job_id, {})
    return render_template_string(ERROR_HTML, error=job.get("error", "Unknown scan error.")), 500


@app.errorhandler(413)
def upload_too_large(_error):
    return render_template_string(ERROR_HTML, error="The upload exceeds the 50 MB limit."), 413

if __name__ == "__main__":
    print("\n  VulnDetect Web App")
    print("  Open your browser at:  http://127.0.0.1:5000\n")
    app.run(debug=False, port=5000)
