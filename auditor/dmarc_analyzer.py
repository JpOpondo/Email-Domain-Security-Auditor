"""
dmarc_analyzer.py
Rule-based analysis of DMARC records per RFC 7489.
"""

import re

RISK_SECURE   = "Secure"
RISK_WARNING  = "Warning"
RISK_CRITICAL = "Critical"
RISK_MISSING  = "Missing"


def _tag(record: str, tag: str) -> str | None:
    m = re.search(rf'(?:^|;)\s*{re.escape(tag)}\s*=\s*([^;]+)', record, re.IGNORECASE)
    return m.group(1).strip() if m else None


def analyze_dmarc(dmarc_result: dict) -> dict:
    record = dmarc_result.get("record")
    error  = dmarc_result.get("error")

    if record is None:
        return {
            "risk": RISK_MISSING,
            "findings": [f"No DMARC record detected. ({error})"],
            "remediation": [
                "Publish a TXT record at _dmarc.<domain> to enable DMARC.",
                "Start with p=none and an rua= reporting address to monitor traffic "
                "before moving to enforcement:",
                'Example: v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com; ruf=mailto:dmarc-failures@yourdomain.com',
                "Once legitimate mail sources are confirmed, escalate to p=quarantine "
                "then p=reject.",
            ],
            "record": None,
            "tags": {},
        }

    findings    = []
    remediation = []
    tags        = {}

    tags["p"]     = _tag(record, "p")
    tags["sp"]    = _tag(record, "sp")
    tags["pct"]   = _tag(record, "pct")
    tags["rua"]   = _tag(record, "rua")
    tags["ruf"]   = _tag(record, "ruf")
    tags["adkim"] = _tag(record, "adkim")
    tags["aspf"]  = _tag(record, "aspf")
    tags["fo"]    = _tag(record, "fo")

    policy = (tags["p"] or "").lower()
    if not policy:
        findings.append(
            "No policy tag (p=) found — DMARC record is malformed and will not be enforced."
        )
        remediation.append("Add a p= tag: 'p=none', 'p=quarantine', or 'p=reject'.")
    elif policy == "none":
        findings.append(
            "DMARC policy is set to 'p=none' (monitor only). No action is taken on "
            "messages that fail DMARC. This provides visibility but no spoofing protection."
        )
        remediation.append(
            "After reviewing aggregate reports (rua=), escalate to 'p=quarantine' to "
            "divert failing mail to spam, then to 'p=reject' to block it entirely."
        )
    elif policy == "quarantine":
        findings.append(
            "DMARC policy is 'p=quarantine'. Failing messages are diverted to spam. "
            "Consider escalating to 'p=reject' for full enforcement."
        )
        remediation.append(
            "Escalate to 'p=reject' once you have confirmed all legitimate senders pass "
            "DMARC alignment checks."
        )

    sp = (tags["sp"] or "").lower()
    if not sp:
        if policy in ("none", "quarantine"):
            findings.append(
                "No subdomain policy (sp=) specified. Subdomains inherit the weak "
                f"parent policy (p={policy}). Attackers can spoof subdomains."
            )
            remediation.append(
                "Add 'sp=reject' to explicitly enforce DMARC on all subdomains, "
                "independent of the parent domain policy."
            )
    elif sp == "none":
        findings.append("'sp=none' explicitly allows DMARC to be bypassed from subdomains.")
        remediation.append("Change 'sp=none' to 'sp=reject' to cover subdomain spoofing.")

    pct = tags["pct"]
    if pct is not None:
        try:
            pct_val = int(pct)
            if pct_val < 100:
                findings.append(
                    f"'pct={pct_val}' applies the DMARC policy to only {pct_val}% of "
                    "non-compliant messages. The remaining messages are treated as if "
                    "the policy is one level lower."
                )
                remediation.append(
                    "Increase pct= to 100 (or remove it — 100 is the default) to apply "
                    "the policy to all failing messages."
                )
        except ValueError:
            findings.append(f"'pct={pct}' is not a valid integer (must be 0–100).")

    rua = tags["rua"]
    if not rua:
        findings.append(
            "No aggregate reporting address (rua=) configured. Without reports, "
            "domain owners receive no visibility into DMARC pass/fail activity."
        )
        remediation.append(
            "Add 'rua=mailto:dmarc-reports@yourdomain.com' to receive aggregate XML reports."
        )

    adkim = (tags["adkim"] or "r").lower()
    aspf  = (tags["aspf"]  or "r").lower()
    if adkim == "r":
        findings.append(
            "DKIM alignment is 'relaxed' (adkim=r or default). "
            "Consider 'adkim=s' (strict) to require exact domain match."
        )
    if aspf == "r":
        findings.append(
            "SPF alignment is 'relaxed' (aspf=r or default). "
            "Consider 'aspf=s' (strict) for tighter alignment."
        )

    critical_findings = [
        f for f in findings
        if any(w in f for w in ["p=none", "malformed", "pct=", "No aggregate"])
    ]

    if not any(f for f in findings if "p=none" in f or "malformed" in f or "No DMARC" in f):
        risk = RISK_WARNING if (critical_findings or findings) else RISK_SECURE
    else:
        risk = RISK_CRITICAL

    if policy == "none":
        risk = RISK_CRITICAL

    if not findings:
        findings.append(
            "DMARC policy is set to 'p=reject' with reporting configured. "
            "Strong enforcement is in place."
        )

    return {
        "risk": risk,
        "findings": findings,
        "remediation": remediation,
        "record": record,
        "tags": tags,
    }