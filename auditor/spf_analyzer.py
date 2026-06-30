"""
spf_analyzer.py
Rule-based analysis of SPF records per RFC 7208.
Risk ratings: Secure | Warning | Critical | Missing
"""

import re

RISK_SECURE   = "Secure"
RISK_WARNING  = "Warning"
RISK_CRITICAL = "Critical"
RISK_MISSING  = "Missing"


def analyze_spf(spf_result: dict) -> dict:
    record = spf_result.get("record")
    error  = spf_result.get("error")

    if record is None:
        return {
            "risk": RISK_MISSING,
            "findings": [f"No SPF record detected. ({error})"],
            "remediation": [
                "Publish a TXT record at your domain root containing an SPF policy.",
                'Example: v=spf1 include:_spf.google.com ~all',
                "Use -all (hard fail) for maximum enforcement once all sending sources are listed.",
            ],
            "record": None,
        }

    findings = []
    remediation = []

    if not record.lower().startswith("v=spf1"):
        findings.append("Record does not begin with 'v=spf1' — invalid SPF syntax.")
        remediation.append("Ensure the record begins exactly with 'v=spf1'.")

    all_match = re.search(r'([~?+-]all)', record, re.IGNORECASE)
    if not all_match:
        findings.append("No 'all' mechanism found — SPF policy is incomplete.")
        remediation.append(
            "Append an 'all' qualifier. Use '-all' (hard fail) for strict enforcement "
            "or '~all' (soft fail) as a transitional step."
        )
    else:
        qualifier = all_match.group(1)[0]
        if qualifier == "+":
            findings.append(
                "'+all' allows any host to send mail on behalf of this domain — "
                "effectively disables SPF protection."
            )
            remediation.append(
                "Replace '+all' with '-all' (hard fail) to block unauthorised senders. "
                "Never use +all in production."
            )
        elif qualifier == "?":
            findings.append(
                "'?all' (neutral) provides no spoofing protection — receivers take no action "
                "on unauthorised senders."
            )
            remediation.append(
                "Upgrade '?all' to '~all' (soft fail) or '-all' (hard fail) once all "
                "legitimate senders are listed in the record."
            )
        elif qualifier == "~":
            findings.append(
                "'~all' (soft fail) is in use. Mail from unlisted hosts is accepted but "
                "may be tagged as spam. Consider upgrading to '-all' for strict enforcement."
            )
            remediation.append(
                "When confident that all legitimate senders are enumerated, change '~all' "
                "to '-all' for full enforcement."
            )

    lookup_mechanisms = re.findall(
        r'\b(include|a|mx|ptr|exists|redirect):', record, re.IGNORECASE
    )
    if len(lookup_mechanisms) > 10:
        findings.append(
            f"SPF record contains {len(lookup_mechanisms)} DNS-lookup mechanisms, "
            "exceeding the RFC 7208 limit of 10. This causes a PermError at evaluation time."
        )
        remediation.append(
            "Flatten the SPF record by replacing nested 'include:' chains with their "
            "constituent IP ranges, or use an SPF flattening service."
        )
    elif len(lookup_mechanisms) > 7:
        findings.append(
            f"SPF record has {len(lookup_mechanisms)} DNS-lookup mechanisms — close to the "
            "RFC 7208 limit of 10. Risk of PermError if additional mechanisms are added."
        )
        remediation.append(
            "Audit and consolidate SPF includes to stay comfortably below the 10-lookup limit."
        )

    if re.search(r'\bptr\b', record, re.IGNORECASE):
        findings.append(
            "'ptr' mechanism is deprecated in RFC 7208 (§5.5) due to performance and "
            "reliability issues."
        )
        remediation.append(
            "Replace the 'ptr' mechanism with 'ip4:', 'ip6:', or 'include:' mechanisms."
        )

    if record.lower().count("v=spf1") > 1:
        findings.append(
            "Multiple 'v=spf1' strings detected — only one SPF record is permitted per "
            "domain (RFC 7208 §3.2). Having multiple records causes a PermError."
        )
        remediation.append("Merge all SPF mechanisms into a single TXT record.")

    all_text = " ".join(findings)
    if not findings:
        risk = RISK_SECURE
    elif "+all" in all_text or "PermError" in all_text or "invalid SPF syntax" in all_text:
        risk = RISK_CRITICAL
    else:
        risk = RISK_WARNING

    if not findings:
        findings.append("SPF record is correctly configured with a hard fail (-all) policy.")

    return {
        "risk": risk,
        "findings": findings,
        "remediation": remediation,
        "record": record,
    }