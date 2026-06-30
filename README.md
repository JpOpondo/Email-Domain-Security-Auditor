# Email Domain Security Auditor

**CNS 3104 — Strathmore University | John Paul Opondo (193309)**

Audits SPF, DKIM, DMARC, and MX DNS records for any domain, flags misconfigurations against RFC standards, assigns four-tier risk ratings, and provides actionable remediation guidance. Includes a CLI for system administrators and a Flask web dashboard for non-technical users, with full audit history logged to SQLite.

---

## Project Structure
```
email-domain-security-auditor/
├── auditor/
│   ├── __init__.py
│   ├── dns_resolver.py      # dnspython-based DNS retrieval engine
│   ├── spf_analyzer.py      # SPF rule checks (RFC 7208)
│   ├── dkim_analyzer.py     # DKIM rule checks (RFC 6376)
│   ├── dmarc_analyzer.py    # DMARC rule checks (RFC 7489)
│   ├── mx_analyzer.py       # MX rule checks (RFC 1034/1035)
│   ├── report.py            # Audit orchestrator
│   └── logger.py            # SQLite database (Audit_Session, Protocol_Record)
├── templates/
│   └── index.html           # Flask web UI template
├── auditor.py                # CLI entry point
├── cli.py                    # CLI logic
├── app.py                    # Flask web application
└── requirements.txt
```

---

## Installation

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Requires Python 3.10+.

---

## Usage

### CLI

```powershell
python auditor.py --domain example.com
python auditor.py --domain example.com --dkim-selectors google mail selector1
python auditor.py --domain example.com --json
python auditor.py --domain example.com --no-log
python auditor.py --history
python auditor.py --history --domain example.com
```

### Web Interface

```powershell
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## Risk Rating Scheme

| Rating   | Meaning                                                       |
|----------|-----------------------------------------------------------------|
| Secure   | Record is present and correctly configured                    |
| Warning  | Record exists but has weaknesses (e.g. ~all, p=quarantine)   |
| Critical | Record is dangerously misconfigured or effectively useless    |
| Missing  | No record found; domain is unprotected                        |

Overall domain risk = worst individual record risk.

---

## Database Schema

**Audit_Session** — one row per audit session
- `session_id` (PK), `target_domain`, `timestamp`, `overall_risk_score`, `report_json`

**Protocol_Record** — one row per protocol per session
- `record_id` (PK), `session_id` (FK), `protocol_type`, `raw_dns_value`, `risk_rating`, `remediation_guidance`

---

## RFC References

- RFC 7208 — Sender Policy Framework (SPF)
- RFC 6376 — DomainKeys Identified Mail (DKIM)
- RFC 7489 — DMARC
- RFC 1034/1035 — DNS (MX records)
Step 2 — Commit it
powershellgit add README.md
git commit -m "docs: project README — setup, usage, architecture, RFC references"
git push

That completes the full build. Once you've pushed this, refresh your GitHub repo page and confirm the README renders nicely on the front page with all phases visible in your commit history.
Show me your final GitHub repo view once that's pushed — we can then talk about what's next: domain sampling for your validation study, or any refinements to Chapter 4.what type of file is README.md in the root?README.md is a plain text file written in Markdown — a lightweight markup language using symbols like # for headers, **bold**, backticks for code blocks, and | for tables (all of which the content I gave you uses).
It goes directly in your project root (same level as auditor.py, app.py, requirements.txt) — not inside any folder.
In PyCharm: right-click the project root → New → File → type README.md (you have to type the .md extension explicitly, since there's no "Markdown File" template by default — unless you have a Markdown plugin installed, which PyCharm sometimes prompts you to install when it detects the extension).
The reason .md matters: GitHub automatically detects a file named exactly README.md in the repo root and renders it as formatted, styled documentation directly on your repository's homepage — headers become bold titles, code blocks get syntax highlighting, tables render as actual tables. That's why this is the standard convention for project documentation, rather than a .txt file.