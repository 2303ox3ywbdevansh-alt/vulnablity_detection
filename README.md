# VulnDetect

A local Flask application for scanning source files and ZIP project archives with heuristic static-analysis rules.

## Run

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Upload one supported source/configuration file or a project ZIP (up to 50 MB). ZIP contents are extracted with path checks and per-file, file-count, and total expanded-size limits.

## Detection coverage

The scanner checks common risky code patterns across Python, JavaScript/TypeScript, PHP, Java, Ruby, Go, C#, C/C++, and configuration files. It reports severity, file, line, matching code, and suggested remediation. Findings can be filtered/searched and exported as JSON.

This is a pattern-based SAST helper. It does not resolve data flow, understand all language syntax, audit dependency versions, or prove exploitability. Review each finding in its code context; a clean scan does not guarantee that software is secure.
