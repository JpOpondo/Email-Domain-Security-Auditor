"""
report.py
Orchestrates a full domain audit and produces a structured report dict.
"""

from .dns_resolver   import get_spf, get_dkim, get_dmarc, get_mx
from .spf_analyzer   import analyze_spf
from .dkim_analyzer  import analyze_dkim
from .dmarc_analyzer import analyze_dmarc
from .mx_analyzer    import analyze_mx

RISK_ORDER = {"Secure": 0, "Warning": 1, "Critical": 2, "Missing": 3}


def audit_domain(domain: str, dkim_selectors: list[str] | None = None) -> dict:
    domain = domain.strip().lower()

    spf_raw   = get_spf(domain)
    dkim_raw  = get_dkim(domain, selectors=dkim_selectors)
    dmarc_raw = get_dmarc(domain)
    mx_raw    = get_mx(domain)

    spf_result   = analyze_spf(spf_raw)
    dkim_result  = analyze_dkim(dkim_raw)
    dmarc_result = analyze_dmarc(dmarc_raw)
    mx_result    = analyze_mx(mx_raw)

    risks = [spf_result["risk"], dkim_result["risk"], dmarc_result["risk"], mx_result["risk"]]
    overall_risk = max(risks, key=lambda r: RISK_ORDER.get(r, 0))

    summary = _build_summary(domain, overall_risk, spf_result, dkim_result, dmarc_result, mx_result)

    return {
        "domain":       domain,
        "overall_risk": overall_risk,
        "summary":      summary,
        "spf":          spf_result,
        "dkim":         dkim_result,
        "dmarc":        dmarc_result,
        "mx":           mx_result,
    }


def _build_summary(domain, overall_risk, spf, dkim, dmarc, mx) -> str:
    parts = []
    if spf["risk"] != "Secure":
        parts.append(f"SPF ({spf['risk'].lower()})")
    if dkim["risk"] != "Secure":
        parts.append(f"DKIM ({dkim['risk'].lower()})")
    if dmarc["risk"] != "Secure":
        parts.append(f"DMARC ({dmarc['risk'].lower()})")
    if mx["risk"] != "Secure":
        parts.append(f"MX ({mx['risk'].lower()})")

    if not parts:
        return f"{domain}: All email authentication records are correctly configured."
    return f"{domain}: Issues detected in {', '.join(parts)}. Overall risk: {overall_risk}."