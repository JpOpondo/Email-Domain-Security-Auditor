"""
dkim_analyzer.py
Rule-based analysis of DKIM records per RFC 6376.
Evaluates selector discoverability, key presence, and record validity.
"""

import re

RISK_SECURE   = "Secure"
RISK_WARNING  = "Warning"
RISK_CRITICAL = "Critical"
RISK_MISSING  = "Missing"


def analyze_dkim(dkim_results: dict) -> dict:
    findings    = []
    remediation = []
    selector_detail = {}

    found_selectors = {
        sel: data
        for sel, data in dkim_results.items()
        if data.get("record") is not None
    }

    if not found_selectors:
        findings.append(
            "No DKIM records were discovered across all probed selectors. "
            "Selector discoverability failed — the domain may not have DKIM configured, "
            "or non-standard selectors are in use."
        )
        remediation.append(
            "Configure DKIM signing on your mail server and publish the public key as a "
            "TXT record at <selector>._domainkey.<domain>. Common selectors include "
            "'default', 'google', 'mail', 'selector1', and 'selector2'."
        )
        remediation.append(
            "If non-standard selectors are in use, supply them explicitly via --dkim-selectors "
            "on the CLI or the selector field in the web UI."
        )
        for sel in dkim_results:
            selector_detail[sel] = {
                "record": None,
                "risk": RISK_MISSING,
                "note": dkim_results[sel].get("error", "Not found"),
            }
        return {
            "risk": RISK_MISSING,
            "findings": findings,
            "remediation": remediation,
            "selectors": selector_detail,
        }

    overall_risks = []
    for sel, data in dkim_results.items():
        record = data.get("record")
        if record is None:
            selector_detail[sel] = {
                "record": None,
                "risk": RISK_MISSING,
                "note": data.get("error", "Not found"),
            }
            continue

        sel_findings = []
        sel_risk = RISK_SECURE

        p_match = re.search(r'p=([^;]*)', record)
        if p_match:
            key_value = p_match.group(1).strip()
            if key_value == "":
                sel_findings.append(
                    f"Selector '{sel}': Public key (p=) is empty — this DKIM key has been "
                    "revoked per RFC 6376 §3.6.1. Legitimate mail signed with this selector "
                    "will fail DKIM verification."
                )
                sel_risk = RISK_CRITICAL
            else:
                key_len = len(key_value.replace(" ", ""))
                if key_len < 216:
                    sel_findings.append(
                        f"Selector '{sel}': Public key appears shorter than 1024 bits. "
                        "RFC 6376 §3.3.3 recommends a minimum of 1024 bits; 2048 bits is "
                        "current best practice."
                    )
                    sel_risk = RISK_WARNING
                elif key_len < 392:
                    sel_findings.append(
                        f"Selector '{sel}': Public key is likely 1024-bit. "
                        "Upgrading to a 2048-bit RSA key is recommended for stronger security."
                    )
                    if sel_risk == RISK_SECURE:
                        sel_risk = RISK_WARNING
        else:
            sel_findings.append(
                f"Selector '{sel}': No public key (p=) tag found — record is malformed."
            )
            sel_risk = RISK_CRITICAL

        h_match = re.search(r'h=([^;]+)', record)
        if h_match:
            algos = h_match.group(1).lower()
            if "sha1" in algos and "sha256" not in algos:
                sel_findings.append(
                    f"Selector '{sel}': Only sha1 is listed in the h= tag. "
                    "SHA-1 is deprecated for DKIM; use sha256."
                )
                if sel_risk == RISK_SECURE:
                    sel_risk = RISK_WARNING

        s_match = re.search(r'\bs=([^;]+)', record)
        if s_match:
            svc = s_match.group(1).strip()
            if "email" not in svc and "*" not in svc:
                sel_findings.append(
                    f"Selector '{sel}': Service type (s={svc}) does not include 'email' or '*'. "
                    "This may prevent DKIM verification for email messages."
                )
                if sel_risk == RISK_SECURE:
                    sel_risk = RISK_WARNING

        if not sel_findings:
            note = "Record is valid and key is present."
        else:
            note = " | ".join(sel_findings)
            findings.extend(sel_findings)

        overall_risks.append(sel_risk)
        selector_detail[sel] = {
            "record": record,
            "risk": sel_risk,
            "note": note,
        }

    for sel in dkim_results:
        if sel not in selector_detail:
            selector_detail[sel] = {
                "record": None,
                "risk": RISK_MISSING,
                "note": dkim_results[sel].get("error", "Not found"),
            }

    if RISK_CRITICAL in overall_risks:
        risk = RISK_CRITICAL
    elif RISK_WARNING in overall_risks:
        risk = RISK_WARNING
    else:
        risk = RISK_SECURE

    if not findings:
        findings.append(
            f"DKIM records found at {len(found_selectors)} selector(s). "
            "Keys are present and records appear valid."
        )

    if risk in (RISK_CRITICAL, RISK_WARNING) and not any("Upgrade" in r or "2048" in r for r in remediation):
        remediation.append(
            "Rotate any weak or revoked DKIM keys. Generate a 2048-bit RSA key pair and "
            "update the TXT record at <selector>._domainkey.<domain> with the new public key."
        )

    return {
        "risk": risk,
        "findings": findings,
        "remediation": remediation,
        "selectors": selector_detail,
    }