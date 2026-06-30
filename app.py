"""
app.py  —  Flask web interface for the Email Domain Security Auditor
CNS 3104 | John Paul Opondo (193309)
"""

from flask import Flask, render_template, request, jsonify
from auditor import audit_domain
from auditor.logger import log_audit, get_recent_audits, get_audits_for_domain, get_audit_by_id

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/audit", methods=["POST"])
def audit():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    selectors_raw = data.get("selectors", "")
    selectors = [s.strip() for s in selectors_raw.split(",") if s.strip()] or None

    try:
        report = audit_domain(domain, dkim_selectors=selectors)
        try:
            session_id = log_audit(report)
            report["session_id"] = session_id
        except Exception as log_exc:
            report["log_warning"] = str(log_exc)
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/history", methods=["GET"])
def history():
    domain = request.args.get("domain", "").strip()
    rows = get_audits_for_domain(domain) if domain else get_recent_audits(limit=20)
    return jsonify(rows)


@app.route("/history/<int:session_id>", methods=["GET"])
def history_detail(session_id: int):
    report = get_audit_by_id(session_id)
    if report is None:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True, port=5000)