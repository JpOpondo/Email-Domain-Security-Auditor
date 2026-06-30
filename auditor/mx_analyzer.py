"""
mx_analyzer.py
Rule-based analysis of MX records per RFC 1034/1035.
"""

RISK_SECURE   = "Secure"
RISK_WARNING  = "Warning"
RISK_CRITICAL = "Critical"
RISK_MISSING  = "Missing"


def analyze_mx(mx_result: dict) -> dict:
    records     = mx_result.get("records", [])
    error       = mx_result.get("error")
    findings    = []
    remediation = []

    if not records:
        return {
            "risk": RISK_MISSING,
            "findings": [f"No MX records found. ({error or 'No MX records in DNS'})"],
            "remediation": [
                "Publish at least one MX record at your domain root pointing to your "
                "mail server hostname.",
                "Example: @ IN MX 10 mail.yourdomain.com.",
                "Ensure the MX hostname has a corresponding A or AAAA record.",
            ],
            "records": [],
        }

    unresolvable = [r for r in records if not r["resolves"]]
    if unresolvable:
        for r in unresolvable:
            findings.append(
                f"MX host '{r['host']}' (priority {r['priority']}) does not resolve "
                "to an A or AAAA record. Mail delivery to this host will fail."
            )
        remediation.append(
            "Ensure every MX hostname has a valid A or AAAA record in DNS. "
            "Remove or correct any stale MX entries."
        )

    if len(records) == 1:
        findings.append(
            "Only one MX record is configured. This creates a single point of failure "
            "— if the mail server is unreachable, inbound mail will be rejected."
        )
        remediation.append(
            "Add a secondary MX record with a higher priority number (e.g., priority 20) "
            "pointing to a backup mail server or relay."
        )

    priorities = [r["priority"] for r in records]
    if len(priorities) != len(set(priorities)):
        findings.append(
            "Multiple MX records share the same priority value. "
            "Mail will be load-balanced across them; ensure this is intentional."
        )
        remediation.append(
            "Assign distinct priority values to MX records unless load-balancing is "
            "specifically intended."
        )

    for r in records:
        if r["host"] in (".", "") and r["priority"] == 0:
            findings.append(
                "Null MX record (priority 0, host '.') detected per RFC 7505. "
                "This domain explicitly does not accept inbound email."
            )
            break

    if not findings:
        risk = RISK_SECURE
        findings.append(
            f"MX records are present ({len(records)} host(s)) and all hostnames resolve correctly."
        )
    elif unresolvable:
        risk = RISK_CRITICAL
    else:
        risk = RISK_WARNING

    return {
        "risk": risk,
        "findings": findings,
        "remediation": remediation,
        "records": records,
    }