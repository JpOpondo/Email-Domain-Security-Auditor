#!/usr/bin/env python3
"""
cli.py  —  Email Domain Security Auditor
CNS 3104 | John Paul Opondo (193309)
"""

import argparse
import datetime
import json
import sys
from auditor import audit_domain
from auditor.logger import log_audit, get_recent_audits, get_audits_for_domain

COLOURS = {
    "Secure":   "\033[92m",
    "Warning":  "\033[93m",
    "Critical": "\033[91m",
    "Missing":  "\033[95m",
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
    "cyan":     "\033[96m",
    "white":    "\033[97m",
}

RISK_ICON = {"Secure": "✅", "Warning": "⚠️ ", "Critical": "🔴", "Missing": "❌"}


def print_banner():
    print(f"\n{COLOURS['bold']}{COLOURS['cyan']}"
          "╔══════════════════════════════════════════════════════╗\n"
          "║       Email Domain Security Auditor  v1.0            ║\n"
          "║       CNS 3104 — Strathmore University               ║\n"
          "╚══════════════════════════════════════════════════════╝"
          f"{COLOURS['reset']}\n")


def print_section(title: str, result: dict):
    risk = result["risk"]
    icon = RISK_ICON.get(risk, "")
    colour = COLOURS.get(risk, "")
    print(f"{COLOURS['bold']}── {title} {'─' * (46 - len(title))}{COLOURS['reset']}")
    print(f"  Risk : {colour}{icon} {risk}{COLOURS['reset']}")

    record = result.get("record")
    if record:
        print(f"  Record : {COLOURS['dim']}{record[:120]}{'...' if len(record) > 120 else ''}{COLOURS['reset']}")

    selectors = result.get("selectors")
    if selectors:
        for sel, detail in selectors.items():
            if detail["record"]:
                sel_risk = detail["risk"]
                print(f"  [{COLOURS.get(sel_risk,'')}{sel_risk}{COLOURS['reset']}] "
                      f"Selector '{sel}': {detail['note'][:80]}")

    mx_records = result.get("records")
    if mx_records:
        for r in mx_records:
            status = "✓" if r["resolves"] else "✗"
            print(f"  [{status}] MX {r['priority']:3d}  {r['host']}")

    print(f"  {COLOURS['bold']}Findings:{COLOURS['reset']}")
    for f in result["findings"]:
        print(f"    • {f}")

    if result.get("remediation"):
        print(f"  {COLOURS['bold']}Remediation:{COLOURS['reset']}")
        for r in result["remediation"]:
            print(f"    → {r}")
    print()


def print_history(rows: list[dict]):
    if not rows:
        print("  No audit history found.")
        return
    print(f"\n  {'ID':<5} {'Domain':<35} {'Overall':<10} {'Date'}")
    print(f"  {'─'*5} {'─'*35} {'─'*10} {'─'*20}")
    for r in rows:
        dt = datetime.datetime.fromtimestamp(r["timestamp"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        risk = r["overall_risk_score"]
        colour = COLOURS.get(risk, "")
        print(f"  {r['session_id']:<5} {r['target_domain']:<35} {colour}{risk:<10}{COLOURS['reset']} {dt}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="auditor.py",
        description="Audit email authentication DNS records for a domain.",
        epilog="Example: python auditor.py --domain example.com",
    )
    parser.add_argument("--domain", metavar="DOMAIN", help="Domain to audit (e.g. example.com)")
    parser.add_argument("--dkim-selectors", nargs="+", metavar="SELECTOR",
                         help="DKIM selectors to probe (e.g. google mail selector1)")
    parser.add_argument("--json", action="store_true", help="Output full report as JSON")
    parser.add_argument("--no-log", action="store_true", help="Skip saving to SQLite log")
    parser.add_argument("--history", action="store_true", help="Show audit history")
    args = parser.parse_args()

    if args.history:
        print_banner()
        if args.domain:
            rows = get_audits_for_domain(args.domain)
            print(f"  Audit history for: {COLOURS['white']}{COLOURS['bold']}{args.domain}{COLOURS['reset']}")
        else:
            rows = get_recent_audits(limit=20)
            print(f"  {COLOURS['bold']}Recent audits (last 20){COLOURS['reset']}")
        print_history(rows)
        sys.exit(0)

    if not args.domain:
        parser.error("--domain is required unless --history is used")

    report = audit_domain(args.domain, dkim_selectors=args.dkim_selectors)

    session_id = None
    if not args.no_log:
        try:
            session_id = log_audit(report)
        except Exception as exc:
            print(f"  {COLOURS['Warning']}⚠ Could not save to log: {exc}{COLOURS['reset']}")

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0)

    print_banner()
    domain  = report["domain"]
    overall = report["overall_risk"]
    print(f"  Domain  : {COLOURS['white']}{COLOURS['bold']}{domain}{COLOURS['reset']}")
    print(f"  Overall : {COLOURS.get(overall,'')}{COLOURS['bold']}{RISK_ICON.get(overall,'')} {overall}{COLOURS['reset']}")
    print(f"  Summary : {report['summary']}")
    if session_id:
        print(f"  Logged  : {COLOURS['dim']}session #{session_id} saved to audit_log.db{COLOURS['reset']}")
    elif args.no_log:
        print(f"  Logged  : {COLOURS['dim']}skipped (--no-log){COLOURS['reset']}")
    print()

    print_section("SPF   (RFC 7208)", report["spf"])
    print_section("DKIM  (RFC 6376)", report["dkim"])
    print_section("DMARC (RFC 7489)", report["dmarc"])
    print_section("MX    (RFC 1034)", report["mx"])


if __name__ == "__main__":
    main()