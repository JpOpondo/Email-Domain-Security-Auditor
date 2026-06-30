"""
dns_resolver.py
Retrieves SPF, DKIM, DMARC, and MX DNS records for a given domain.
Uses dnspython with Google (8.8.8.8) and Cloudflare (1.1.1.1) resolvers.
"""

import dns.resolver
import dns.exception


RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]

DEFAULT_DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2",
    "selector1", "selector2", "smtp", "email", "s1", "s2",
]


def _build_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.nameservers = RESOLVERS
    r.timeout = 5
    r.lifetime = 10
    return r


resolver = _build_resolver()


def get_spf(domain: str) -> dict:
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=spf1"):
                return {"record": txt, "error": None}
        return {"record": None, "error": "No SPF record found"}
    except dns.resolver.NXDOMAIN:
        return {"record": None, "error": f"Domain '{domain}' does not exist"}
    except dns.resolver.NoAnswer:
        return {"record": None, "error": "No TXT records returned"}
    except dns.exception.DNSException as exc:
        return {"record": None, "error": str(exc)}


def get_dkim(domain: str, selectors: list[str] | None = None) -> dict:
    if selectors is None:
        selectors = DEFAULT_DKIM_SELECTORS

    results = {}
    for sel in selectors:
        qname = f"{sel}._domainkey.{domain}"
        try:
            answers = resolver.resolve(qname, "TXT")
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                if "v=DKIM1" in txt or "p=" in txt:
                    results[sel] = {"record": txt, "error": None}
                    break
            else:
                results[sel] = {"record": None, "error": "No valid DKIM record at selector"}
        except dns.resolver.NXDOMAIN:
            results[sel] = {"record": None, "error": "Selector not found"}
        except dns.resolver.NoAnswer:
            results[sel] = {"record": None, "error": "No TXT record at selector"}
        except dns.exception.DNSException as exc:
            results[sel] = {"record": None, "error": str(exc)}

    return results


def get_dmarc(domain: str) -> dict:
    qname = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(qname, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=dmarc1"):
                return {"record": txt, "error": None}
        return {"record": None, "error": "No DMARC record found at _dmarc." + domain}
    except dns.resolver.NXDOMAIN:
        return {"record": None, "error": "No DMARC record (NXDOMAIN)"}
    except dns.resolver.NoAnswer:
        return {"record": None, "error": "No TXT records at _dmarc." + domain}
    except dns.exception.DNSException as exc:
        return {"record": None, "error": str(exc)}


def get_mx(domain: str) -> dict:
    try:
        answers = resolver.resolve(domain, "MX")
        records = []
        for rdata in sorted(answers, key=lambda r: r.preference):
            host = str(rdata.exchange).rstrip(".")
            resolves = _host_resolves(host)
            records.append({
                "priority": rdata.preference,
                "host": host,
                "resolves": resolves,
            })
        if not records:
            return {"records": [], "error": "No MX records found"}
        return {"records": records, "error": None}
    except dns.resolver.NXDOMAIN:
        return {"records": [], "error": f"Domain '{domain}' does not exist"}
    except dns.resolver.NoAnswer:
        return {"records": [], "error": "No MX records found"}
    except dns.exception.DNSException as exc:
        return {"records": [], "error": str(exc)}


def _host_resolves(host: str) -> bool:
    for qtype in ("A", "AAAA"):
        try:
            resolver.resolve(host, qtype)
            return True
        except dns.exception.DNSException:
            pass
    return False