"""
Report generation module for the GRC Tool.
Outputs HTML, JSON, and CSV reports.
"""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .database import Database
from .risk_manager import RiskManager
from .control_manager import ControlManager
from .policy_manager import PolicyManager
from .assessment_manager import AssessmentManager


# ──────────────────────────────────────────────────────────────────────────────
# HTML template
# ──────────────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GRC Report – {generated_at}</title>
  <style>
    :root {{
      --primary: #1a56db;
      --critical: #e02424;
      --high: #ff5a1f;
      --medium: #c27803;
      --low: #057a55;
      --bg: #f9fafb;
      --card: #ffffff;
      --border: #e5e7eb;
      --text: #111827;
      --muted: #6b7280;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg); color: var(--text); padding: 24px; }}
    h1 {{ font-size: 1.75rem; color: var(--primary); margin-bottom: 4px; }}
    h2 {{ font-size: 1.2rem; margin: 24px 0 12px; border-bottom: 2px solid var(--border);
          padding-bottom: 6px; color: var(--primary); }}
    .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
             gap: 16px; margin-bottom: 24px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
             padding: 16px; text-align: center; }}
    .card .value {{ font-size: 2rem; font-weight: 700; }}
    .card .label {{ font-size: 0.8rem; color: var(--muted); margin-top: 4px; }}
    .critical {{ color: var(--critical); }}
    .high     {{ color: var(--high); }}
    .medium   {{ color: var(--medium); }}
    .low      {{ color: var(--low); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem;
             background: var(--card); border-radius: 8px; overflow: hidden; }}
    th {{ background: #f3f4f6; text-align: left; padding: 10px 12px;
          font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
          color: var(--muted); }}
    td {{ padding: 10px 12px; border-top: 1px solid var(--border); vertical-align: top; }}
    tr:hover {{ background: #f9fafb; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
              font-size: 0.75rem; font-weight: 600; }}
    .badge-critical {{ background: #fde8e8; color: var(--critical); }}
    .badge-high     {{ background: #feecdc; color: var(--high); }}
    .badge-medium   {{ background: #fdf6b2; color: var(--medium); }}
    .badge-low      {{ background: #def7ec; color: var(--low); }}
    .badge-implemented  {{ background: #def7ec; color: var(--low); }}
    .badge-partial      {{ background: #fdf6b2; color: var(--medium); }}
    .badge-planned      {{ background: #e1effe; color: var(--primary); }}
    .badge-not-impl     {{ background: #fde8e8; color: var(--critical); }}
    .score-bar-wrap {{ background: #e5e7eb; border-radius: 4px; height: 8px;
                       width: 100%; min-width: 80px; }}
    .score-bar {{ height: 8px; border-radius: 4px; background: var(--primary); }}
    footer {{ margin-top: 32px; font-size: 0.75rem; color: var(--muted); text-align: center; }}
  </style>
</head>
<body>
  <h1>🛡 GRC Status Report</h1>
  <p class="meta">Generated: {generated_at} | Organisation: {org_name}</p>

  <h2>Risk Summary</h2>
  <div class="grid">
    <div class="card"><div class="value">{risk_total}</div><div class="label">Total Risks</div></div>
    <div class="card"><div class="value critical">{risk_critical}</div><div class="label">Critical</div></div>
    <div class="card"><div class="value high">{risk_high}</div><div class="label">High</div></div>
    <div class="card"><div class="value medium">{risk_medium}</div><div class="label">Medium</div></div>
    <div class="card"><div class="value low">{risk_low}</div><div class="label">Low</div></div>
    <div class="card"><div class="value">{risk_open}</div><div class="label">Open</div></div>
  </div>

  <h2>Top Risks</h2>
  <table>
    <thead><tr>
      <th>#</th><th>Title</th><th>Category</th>
      <th>Score</th><th>Level</th><th>Status</th><th>Owner</th>
    </tr></thead>
    <tbody>{top_risks_rows}</tbody>
  </table>

  <h2>Compliance Scores</h2>
  <table>
    <thead><tr>
      <th>Framework</th><th>Score</th><th>Progress</th>
      <th>Implemented</th><th>Partial</th><th>Not Implemented</th><th>Total</th>
    </tr></thead>
    <tbody>{compliance_rows}</tbody>
  </table>

  <h2>Policy Summary</h2>
  <table>
    <thead><tr>
      <th>Title</th><th>Policy ID</th><th>Category</th>
      <th>Version</th><th>Status</th><th>Owner</th><th>Review Date</th>
    </tr></thead>
    <tbody>{policy_rows}</tbody>
  </table>

  <footer>GRC Tool v1.0 | Cloud &amp; AI Governance Platform</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# Generator
# ──────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generate GRC reports in HTML, JSON, and CSV formats."""

    def __init__(self, db: Database, org_name: str = "Your Organisation"):
        self.db = db
        self.org_name = org_name
        self.risk_mgr = RiskManager(db)
        self.ctrl_mgr = ControlManager(db)
        self.policy_mgr = PolicyManager(db)
        self.assessment_mgr = AssessmentManager(db)

    # ------------------------------------------------------------------
    # Data gathering
    # ------------------------------------------------------------------

    def _gather(self) -> dict:
        risk_summary = self.risk_mgr.risk_summary()
        compliance_scores = self.ctrl_mgr.compliance_score()
        policy_summary = self.policy_mgr.policy_summary()
        top_risks = self.risk_mgr.top_risks(10)
        all_policies = self.policy_mgr.list_policies()
        return {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "org_name": self.org_name,
            "risk_summary": risk_summary,
            "compliance_scores": compliance_scores,
            "policy_summary": policy_summary,
            "top_risks": [
                {
                    "id": r.id, "title": r.title, "category": r.category,
                    "risk_score": r.risk_score, "risk_level": r.risk_level,
                    "status": r.status, "owner": r.owner,
                    "likelihood": r.likelihood, "impact": r.impact,
                }
                for r in top_risks
            ],
            "policies": [
                {
                    "id": p.id, "title": p.title, "policy_id": p.policy_id,
                    "category": p.category, "version": p.version,
                    "status": p.status, "owner": p.owner,
                    "review_date": p.review_date,
                }
                for p in all_policies
            ],
        }

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def generate_json(self, output_path: str | None = None) -> str:
        data = self._gather()
        json_str = json.dumps(data, indent=2)
        if output_path:
            Path(output_path).write_text(json_str, encoding="utf-8")
        return json_str

    # ------------------------------------------------------------------
    # CSV (risks only)
    # ------------------------------------------------------------------

    def generate_risk_csv(self, output_path: str | None = None) -> str:
        risks = self.risk_mgr.list_risks()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "ID", "Title", "Category", "Likelihood", "Impact",
            "Risk Score", "Risk Level", "Status", "Treatment",
            "Owner", "Due Date", "Created At",
        ])
        for r in risks:
            writer.writerow([
                r.id, r.title, r.category, r.likelihood, r.impact,
                r.risk_score, r.risk_level, r.status, r.treatment,
                r.owner, r.due_date, r.created_at,
            ])
        csv_str = buf.getvalue()
        if output_path:
            Path(output_path).write_text(csv_str, encoding="utf-8")
        return csv_str

    def generate_controls_csv(self, output_path: str | None = None) -> str:
        controls = self.ctrl_mgr.list_controls()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "ID", "Control ID", "Framework", "Domain", "Title",
            "Status", "Owner", "Last Reviewed",
        ])
        for c in controls:
            writer.writerow([
                c.id, c.control_id, c.framework, c.domain, c.title,
                c.status, c.owner, c.last_reviewed,
            ])
        csv_str = buf.getvalue()
        if output_path:
            Path(output_path).write_text(csv_str, encoding="utf-8")
        return csv_str

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def generate_html(self, output_path: str | None = None) -> str:
        data = self._gather()
        rs = data["risk_summary"]

        # Top risks table rows
        risk_rows = ""
        for r in data["top_risks"]:
            lvl = r["risk_level"].lower()
            risk_rows += (
                f"<tr>"
                f"<td>{r['id']}</td>"
                f"<td>{r['title']}</td>"
                f"<td>{r['category']}</td>"
                f"<td><strong>{r['risk_score']}</strong>/25</td>"
                f"<td><span class='badge badge-{lvl}'>{r['risk_level']}</span></td>"
                f"<td>{r['status']}</td>"
                f"<td>{r['owner'] or '—'}</td>"
                f"</tr>"
            )

        # Compliance rows
        comp_rows = ""
        for fw, info in data["compliance_scores"].items():
            score = info["score"]
            bar_color = (
                "#057a55" if score >= 75 else
                "#c27803" if score >= 50 else
                "#e02424"
            )
            not_impl = info["by_status"].get("Not Implemented", 0)
            comp_rows += (
                f"<tr>"
                f"<td>{fw}</td>"
                f"<td><strong>{score}%</strong></td>"
                f"<td><div class='score-bar-wrap'>"
                f"<div class='score-bar' style='width:{score}%;background:{bar_color}'></div>"
                f"</div></td>"
                f"<td>{info['implemented']}</td>"
                f"<td>{info['partial']}</td>"
                f"<td>{not_impl}</td>"
                f"<td>{info['total_applicable']}</td>"
                f"</tr>"
            )

        # Policy rows
        pol_rows = ""
        for p in data["policies"]:
            status_cls = {
                "Approved": "badge-implemented",
                "Draft": "badge-not-impl",
                "Under Review": "badge-planned",
                "Deprecated": "badge-medium",
            }.get(p["status"], "")
            pol_rows += (
                f"<tr>"
                f"<td>{p['title']}</td>"
                f"<td><code>{p['policy_id']}</code></td>"
                f"<td>{p['category']}</td>"
                f"<td>{p['version']}</td>"
                f"<td><span class='badge {status_cls}'>{p['status']}</span></td>"
                f"<td>{p['owner'] or '—'}</td>"
                f"<td>{p['review_date'] or '—'}</td>"
                f"</tr>"
            )

        html = _HTML_TEMPLATE.format(
            generated_at=data["generated_at"],
            org_name=data["org_name"],
            risk_total=rs["total"],
            risk_critical=rs["by_level"].get("Critical", 0),
            risk_high=rs["by_level"].get("High", 0),
            risk_medium=rs["by_level"].get("Medium", 0),
            risk_low=rs["by_level"].get("Low", 0),
            risk_open=rs["by_status"].get("Open", 0),
            top_risks_rows=risk_rows or "<tr><td colspan='7'>No risks recorded.</td></tr>",
            compliance_rows=comp_rows or "<tr><td colspan='7'>No compliance data.</td></tr>",
            policy_rows=pol_rows or "<tr><td colspan='7'>No policies recorded.</td></tr>",
        )

        if output_path:
            Path(output_path).write_text(html, encoding="utf-8")
        return html
