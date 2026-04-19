"""
Command-line interface for the GRC Tool.
Uses `rich` for beautiful terminal output (falls back to plain text if unavailable).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional

# ── Try to import rich; fall back to plain output ─────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
    from rich.columns import Columns
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .database import Database
from .risk_manager import RiskManager
from .control_manager import ControlManager
from .policy_manager import PolicyManager
from .assessment_manager import AssessmentManager
from .report_generator import ReportGenerator
from .ai_advisor import AIAdvisor
from .frameworks import available_frameworks


# ──────────────────────────────────────────────────────────────────────────────
# Console helpers
# ──────────────────────────────────────────────────────────────────────────────

console = Console() if RICH_AVAILABLE else None


def _print(msg: str, style: str = ""):
    if RICH_AVAILABLE:
        console.print(msg, style=style)
    else:
        print(msg)


def _print_panel(title: str, content: str, style: str = "blue"):
    if RICH_AVAILABLE:
        console.print(Panel(content, title=title, border_style=style))
    else:
        print(f"\n{'='*60}\n{title}\n{'='*60}\n{content}\n")


def _error(msg: str):
    _print(f"[bold red]✗ Error:[/] {msg}" if RICH_AVAILABLE else f"ERROR: {msg}")


def _success(msg: str):
    _print(f"[bold green]✓[/] {msg}" if RICH_AVAILABLE else f"OK: {msg}")


def _warn(msg: str):
    _print(f"[bold yellow]⚠[/] {msg}" if RICH_AVAILABLE else f"WARNING: {msg}")


def _level_style(level: str) -> str:
    return {
        "Critical": "bold red",
        "High": "bold orange3",
        "Medium": "bold yellow",
        "Low": "bold green",
    }.get(level, "")


def _status_style(status: str) -> str:
    return {
        "Open": "red",
        "In Progress": "yellow",
        "Mitigated": "green",
        "Accepted": "cyan",
        "Closed": "dim",
        "Implemented": "green",
        "Partially Implemented": "yellow",
        "Planned": "blue",
        "Not Implemented": "red",
        "Not Applicable": "dim",
        "Approved": "green",
        "Draft": "yellow",
        "Under Review": "blue",
        "Deprecated": "dim",
    }.get(status, "")


# ──────────────────────────────────────────────────────────────────────────────
# App entry point
# ──────────────────────────────────────────────────────────────────────────────

class GRCApp:
    """Main GRC Tool application."""

    def __init__(self, db_path: Optional[str] = None):
        self.db = Database(db_path)
        self.db.initialize()
        self.risk_mgr = RiskManager(self.db)
        self.ctrl_mgr = ControlManager(self.db)
        self.policy_mgr = PolicyManager(self.db)
        self.assessment_mgr = AssessmentManager(self.db)
        self.report_gen = ReportGenerator(self.db)
        self.ai = AIAdvisor()

    # ── Dashboard ────────────────────────────────────────────────────────────

    def cmd_dashboard(self, _args):
        """Display the GRC dashboard."""
        rs = self.risk_mgr.risk_summary()
        cs = self.ctrl_mgr.compliance_score()
        ps = self.policy_mgr.policy_summary()

        if RICH_AVAILABLE:
            console.rule("[bold blue]🛡 GRC Dashboard[/]")
            console.print(
                f"  [dim]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/]\n"
            )

            # Risk summary cards
            risk_table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
            risk_table.add_column(justify="center")
            risk_table.add_column(justify="center")
            risk_table.add_column(justify="center")
            risk_table.add_column(justify="center")
            risk_table.add_column(justify="center")
            risk_table.add_row(
                f"[bold]{rs['total']}[/]\n[dim]Total Risks[/]",
                f"[bold red]{rs['by_level'].get('Critical',0)}[/]\n[dim]Critical[/]",
                f"[bold orange3]{rs['by_level'].get('High',0)}[/]\n[dim]High[/]",
                f"[bold yellow]{rs['by_level'].get('Medium',0)}[/]\n[dim]Medium[/]",
                f"[bold green]{rs['by_level'].get('Low',0)}[/]\n[dim]Low[/]",
            )
            console.print(Panel(risk_table, title="Risk Posture", border_style="red"))

            # Compliance scores
            comp_table = Table(box=box.ROUNDED)
            comp_table.add_column("Framework", style="bold")
            comp_table.add_column("Score", justify="right")
            comp_table.add_column("Implemented", justify="right")
            comp_table.add_column("Partial", justify="right")
            comp_table.add_column("Not Implemented", justify="right")
            for fw, info in cs.items():
                score = info["score"]
                colour = "green" if score >= 75 else "yellow" if score >= 50 else "red"
                comp_table.add_row(
                    fw,
                    f"[{colour}]{score}%[/]",
                    str(info["implemented"]),
                    str(info["partial"]),
                    str(info["by_status"].get("Not Implemented", 0)),
                )
            console.print(Panel(comp_table, title="Compliance Scores", border_style="blue"))

            # Policy summary
            pol_parts = "  ".join(
                f"[bold]{v}[/] {k}" for k, v in ps.items() if k != "total"
            )
            console.print(Panel(
                f"Total: [bold]{ps.get('total',0)}[/]   {pol_parts}",
                title="Policy Status",
                border_style="green",
            ))

            # Top risks
            top = self.risk_mgr.top_risks(5)
            if top:
                tbl = Table(box=box.SIMPLE, title="Top Open Risks")
                tbl.add_column("ID",    style="dim",   width=4)
                tbl.add_column("Title", style="bold",  max_width=40)
                tbl.add_column("Level", width=10)
                tbl.add_column("Score", justify="right", width=6)
                tbl.add_column("Owner", width=15)
                for r in top:
                    tbl.add_row(
                        str(r.id), r.title,
                        f"[{_level_style(r.risk_level)}]{r.risk_level}[/]",
                        str(r.risk_score), r.owner or "—",
                    )
                console.print(tbl)
        else:
            print("\n=== GRC Dashboard ===")
            print(f"\nRisks  Total:{rs['total']}  Critical:{rs['by_level'].get('Critical',0)}"
                  f"  High:{rs['by_level'].get('High',0)}")
            print("\nCompliance Scores:")
            for fw, info in cs.items():
                print(f"  {fw}: {info['score']}%")
            print(f"\nPolicies: {ps}")

    # ── Risks ────────────────────────────────────────────────────────────────

    def cmd_risk_list(self, args):
        risks = self.risk_mgr.list_risks(
            status=getattr(args, "status", None),
            category=getattr(args, "category", None),
            level=getattr(args, "level", None),
        )
        if not risks:
            _warn("No risks found.")
            return
        if RICH_AVAILABLE:
            tbl = Table(box=box.ROUNDED, title=f"Risks ({len(risks)} total)")
            tbl.add_column("ID",       style="dim",  width=4)
            tbl.add_column("Title",    style="bold", max_width=35)
            tbl.add_column("Category", max_width=20)
            tbl.add_column("Score",    justify="right", width=6)
            tbl.add_column("Level",    width=10)
            tbl.add_column("Status",   width=14)
            tbl.add_column("Owner",    width=15)
            for r in risks:
                tbl.add_row(
                    str(r.id), r.title, r.category, str(r.risk_score),
                    f"[{_level_style(r.risk_level)}]{r.risk_level}[/]",
                    f"[{_status_style(r.status)}]{r.status}[/]",
                    r.owner or "—",
                )
            console.print(tbl)
        else:
            print(f"\n{'ID':>4}  {'Title':<35}  {'Score':>5}  {'Level':<10}  {'Status'}")
            print("-" * 70)
            for r in risks:
                print(f"{r.id:>4}  {r.title:<35}  {r.risk_score:>5}  {r.risk_level:<10}  {r.status}")

    def cmd_risk_add(self, args):
        if RICH_AVAILABLE:
            title = Prompt.ask("Risk title")
            description = Prompt.ask("Description", default="")
            category = Prompt.ask(
                "Category",
                choices=RiskManager.CATEGORIES,
                default="Cloud Security",
            )
            likelihood = IntPrompt.ask("Likelihood (1-5)", default=3)
            impact = IntPrompt.ask("Impact (1-5)", default=3)
            owner = Prompt.ask("Owner", default="")
            treatment = Prompt.ask(
                "Treatment strategy",
                choices=RiskManager.TREATMENTS,
                default="Mitigate",
            )
            due_date = Prompt.ask("Due date (YYYY-MM-DD)", default="")
        else:
            title = input("Risk title: ")
            description = input("Description: ")
            category = input(f"Category {RiskManager.CATEGORIES}: ") or "Cloud Security"
            likelihood = int(input("Likelihood (1-5): ") or "3")
            impact = int(input("Impact (1-5): ") or "3")
            owner = input("Owner: ")
            treatment = input("Treatment (Mitigate/Accept/Transfer/Avoid): ") or "Mitigate"
            due_date = input("Due date (YYYY-MM-DD): ")

        from .models import Risk
        risk = Risk(
            title=title, description=description, category=category,
            likelihood=likelihood, impact=impact, owner=owner,
            treatment=treatment, due_date=due_date,
        )
        risk_id = self.risk_mgr.add_risk(risk)
        _success(f"Risk created with ID {risk_id} (Score: {risk.risk_score}, Level: {risk.risk_level})")

    def cmd_risk_view(self, args):
        risk = self.risk_mgr.get_risk(args.id)
        if not risk:
            _error(f"Risk {args.id} not found.")
            return
        if RICH_AVAILABLE:
            details = (
                f"[bold]ID:[/]          {risk.id}\n"
                f"[bold]Title:[/]       {risk.title}\n"
                f"[bold]Description:[/] {risk.description or '—'}\n"
                f"[bold]Category:[/]    {risk.category}\n"
                f"[bold]Likelihood:[/]  {risk.likelihood}/5\n"
                f"[bold]Impact:[/]      {risk.impact}/5\n"
                f"[bold]Risk Score:[/]  {risk.risk_score}/25\n"
                f"[bold]Risk Level:[/]  [{_level_style(risk.risk_level)}]{risk.risk_level}[/]\n"
                f"[bold]Status:[/]      [{_status_style(risk.status)}]{risk.status}[/]\n"
                f"[bold]Treatment:[/]   {risk.treatment}\n"
                f"[bold]Owner:[/]       {risk.owner or '—'}\n"
                f"[bold]Due Date:[/]    {risk.due_date or '—'}\n"
                f"[bold]Created:[/]     {risk.created_at}\n"
            )
            console.print(Panel(details, title=f"Risk #{risk.id}", border_style="blue"))
        else:
            print(f"\nRisk #{risk.id}: {risk.title}")
            print(f"  Level: {risk.risk_level} (Score: {risk.risk_score})")
            print(f"  Status: {risk.status}  Treatment: {risk.treatment}")

    def cmd_risk_update(self, args):
        updates: dict = {}
        if args.status:
            updates["status"] = args.status
        if args.owner:
            updates["owner"] = args.owner
        if args.likelihood:
            updates["likelihood"] = args.likelihood
        if args.impact:
            updates["impact"] = args.impact
        if not updates:
            _warn("No updates provided. Use --status, --owner, --likelihood, --impact.")
            return
        self.risk_mgr.update_risk(args.id, updates)
        _success(f"Risk {args.id} updated.")

    def cmd_risk_ai(self, args):
        risk = self.risk_mgr.get_risk(args.id)
        if not risk:
            _error(f"Risk {args.id} not found.")
            return
        _print(f"\n[bold blue]🤖 Requesting AI analysis for risk: {risk.title}[/]" if RICH_AVAILABLE
               else f"\nAI analysis for: {risk.title}")
        if not self.ai.is_available():
            _warn("Ollama is not running. Start it with: ollama serve")
            return
        with (Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                       console=console) if RICH_AVAILABLE else _NullContext()) as progress:
            if RICH_AVAILABLE:
                task = progress.add_task("Analysing with AI...", total=None)
            result = self.ai.analyse_risk(
                risk.title, risk.description, risk.category,
                risk.likelihood, risk.impact,
            )
            if RICH_AVAILABLE:
                progress.remove_task(task)
        _print_panel("🤖 AI Risk Analysis", result, "green")

    # ── Controls ─────────────────────────────────────────────────────────────

    def cmd_control_import(self, args):
        fw = args.framework
        if fw == "all":
            results = self.ctrl_mgr.import_all_frameworks()
            for f, count in results.items():
                _success(f"Imported {count} controls from {f}")
        else:
            count = self.ctrl_mgr.import_framework(fw)
            _success(f"Imported {count} controls from {fw}")

    def cmd_control_list(self, args):
        controls = self.ctrl_mgr.list_controls(
            framework=getattr(args, "framework", None),
            status=getattr(args, "status", None),
        )
        if not controls:
            _warn("No controls found.")
            return
        if RICH_AVAILABLE:
            tbl = Table(box=box.ROUNDED, title=f"Controls ({len(controls)} total)")
            tbl.add_column("ID",         style="dim", width=4)
            tbl.add_column("Control ID", style="bold", width=14)
            tbl.add_column("Framework",  width=14)
            tbl.add_column("Domain",     max_width=30)
            tbl.add_column("Title",      max_width=35)
            tbl.add_column("Status",     width=22)
            tbl.add_column("Owner",      width=12)
            for c in controls:
                tbl.add_row(
                    str(c.id), c.control_id, c.framework,
                    c.domain, c.title,
                    f"[{_status_style(c.status)}]{c.status}[/]",
                    c.owner or "—",
                )
            console.print(tbl)
        else:
            print(f"\n{'ID':>4}  {'Ctrl ID':<14}  {'Framework':<14}  {'Title':<35}  {'Status'}")
            for c in controls:
                print(f"{c.id:>4}  {c.control_id:<14}  {c.framework:<14}  {c.title:<35}  {c.status}")

    def cmd_control_update(self, args):
        ok = self.ctrl_mgr.update_control_status(
            args.control_id, args.status,
            implementation=getattr(args, "implementation", "") or "",
            evidence=getattr(args, "evidence", "") or "",
            owner=getattr(args, "owner", "") or "",
        )
        if ok:
            _success(f"Control {args.control_id} updated to '{args.status}'.")
        else:
            _error(f"Control '{args.control_id}' not found.")

    def cmd_control_score(self, args):
        scores = self.ctrl_mgr.compliance_score(
            framework=getattr(args, "framework", None)
        )
        if RICH_AVAILABLE:
            tbl = Table(box=box.ROUNDED, title="Compliance Scores")
            tbl.add_column("Framework",       style="bold")
            tbl.add_column("Score",           justify="right")
            tbl.add_column("Implemented",     justify="right")
            tbl.add_column("Partial",         justify="right")
            tbl.add_column("Not Implemented", justify="right")
            tbl.add_column("N/A",             justify="right")
            tbl.add_column("Total",           justify="right")
            for fw, info in scores.items():
                score = info["score"]
                colour = "green" if score >= 75 else "yellow" if score >= 50 else "red"
                tbl.add_row(
                    fw,
                    f"[{colour}]{score}%[/]",
                    str(info["implemented"]),
                    str(info["partial"]),
                    str(info["by_status"].get("Not Implemented", 0)),
                    str(info["by_status"].get("Not Applicable", 0)),
                    str(info["total_applicable"]),
                )
            console.print(tbl)
        else:
            for fw, info in scores.items():
                print(f"{fw}: {info['score']}% ({info['implemented']} implemented)")

    # ── Policies ──────────────────────────────────────────────────────────────

    def cmd_policy_list(self, args):
        policies = self.policy_mgr.list_policies(
            status=getattr(args, "status", None),
        )
        if not policies:
            _warn("No policies found.")
            return
        if RICH_AVAILABLE:
            tbl = Table(box=box.ROUNDED, title=f"Policies ({len(policies)} total)")
            tbl.add_column("ID",          style="dim",  width=4)
            tbl.add_column("Policy ID",   style="bold", width=15)
            tbl.add_column("Title",       max_width=35)
            tbl.add_column("Category",    width=18)
            tbl.add_column("Version",     width=8)
            tbl.add_column("Status",      width=14)
            tbl.add_column("Owner",       width=12)
            for p in policies:
                tbl.add_row(
                    str(p.id), p.policy_id, p.title, p.category, p.version,
                    f"[{_status_style(p.status)}]{p.status}[/]",
                    p.owner or "—",
                )
            console.print(tbl)
        else:
            for p in policies:
                print(f"{p.id:>4}  {p.policy_id:<15}  {p.title:<35}  {p.status}")

    def cmd_policy_create(self, args):
        if args.template:
            if RICH_AVAILABLE:
                pid = Prompt.ask("Policy ID (e.g. POL-001)")
                owner = Prompt.ask("Owner", default="")
            else:
                pid = input("Policy ID: ")
                owner = input("Owner: ")
            db_id = self.policy_mgr.create_from_template(args.template, pid, owner)
            _success(f"Policy created from template '{args.template}' with ID {db_id}.")
        else:
            _warn(f"Available templates: {self.policy_mgr.available_templates()}")
            _warn("Use --template <name> to create from template.")

    def cmd_policy_approve(self, args):
        ok = self.policy_mgr.approve_policy(args.policy_id, args.approver)
        if ok:
            _success(f"Policy '{args.policy_id}' approved by {args.approver}.")
        else:
            _error(f"Policy '{args.policy_id}' not found.")

    def cmd_policy_view(self, args):
        policy = self.policy_mgr.get_policy(args.policy_id)
        if not policy:
            _error(f"Policy '{args.policy_id}' not found.")
            return
        if RICH_AVAILABLE:
            meta = (
                f"[bold]ID:[/]       {policy.policy_id}\n"
                f"[bold]Category:[/] {policy.category}\n"
                f"[bold]Version:[/]  {policy.version}\n"
                f"[bold]Status:[/]   [{_status_style(policy.status)}]{policy.status}[/]\n"
                f"[bold]Owner:[/]    {policy.owner or '—'}\n"
                f"[bold]Approver:[/] {policy.approver or '—'}\n"
                f"[bold]Effective:[/] {policy.effective_date or '—'}\n"
                f"[bold]Review:[/]   {policy.review_date or '—'}\n"
            )
            console.print(Panel(meta, title=policy.title, border_style="blue"))
            if policy.content:
                console.print(Markdown(policy.content))
        else:
            print(f"\n{policy.title} [{policy.status}]")
            print(policy.content or "(no content)")

    # ── Assessments ───────────────────────────────────────────────────────────

    def cmd_assess_create(self, args):
        from .models import Assessment
        fw = args.framework
        if RICH_AVAILABLE:
            name = Prompt.ask("Assessment name", default=f"{fw} Assessment")
            scope = Prompt.ask("Scope", default="")
            assessor = Prompt.ask("Assessor", default="")
        else:
            name = input("Assessment name: ") or f"{fw} Assessment"
            scope = input("Scope: ")
            assessor = input("Assessor: ")

        assessment = Assessment(
            name=name, framework=fw, scope=scope, assessor=assessor,
            start_date=datetime.now(timezone.utc).date().isoformat(),
        )
        aid = self.assessment_mgr.create_assessment(assessment)
        _success(f"Assessment created with ID {aid}.")

        if RICH_AVAILABLE:
            auto = Confirm.ask("Auto-score from current control statuses?", default=True)
        else:
            auto = input("Auto-score from controls? (y/n): ").lower() == "y"
        if auto:
            score = self.assessment_mgr.score_from_controls(aid)
            _success(f"Assessment scored: {score:.1f}%")

    def cmd_assess_list(self, args):
        assessments = self.assessment_mgr.list_assessments()
        if not assessments:
            _warn("No assessments found.")
            return
        if RICH_AVAILABLE:
            tbl = Table(box=box.ROUNDED, title="Assessments")
            tbl.add_column("ID",        style="dim", width=4)
            tbl.add_column("Name",      max_width=30)
            tbl.add_column("Framework", width=14)
            tbl.add_column("Score",     justify="right", width=8)
            tbl.add_column("Status",    width=14)
            tbl.add_column("Assessor",  width=15)
            tbl.add_column("Date",      width=12)
            for a in assessments:
                score_str = f"{a.score:.1f}%" if a.score is not None else "—"
                tbl.add_row(
                    str(a.id), a.name, a.framework, score_str,
                    f"[{_status_style(a.status)}]{a.status}[/]",
                    a.assessor or "—", a.start_date or "—",
                )
            console.print(tbl)
        else:
            for a in assessments:
                score_str = f"{a.score:.1f}%" if a.score is not None else "N/A"
                print(f"{a.id:>4}  {a.name:<30}  {a.framework:<14}  {score_str:>7}  {a.status}")

    # ── Reports ───────────────────────────────────────────────────────────────

    def cmd_report(self, args):
        fmt = args.format
        out = args.output or f"grc_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        if fmt == "html":
            path = out if out.endswith(".html") else f"{out}.html"
            self.report_gen.generate_html(path)
            _success(f"HTML report saved to: {path}")
        elif fmt == "json":
            path = out if out.endswith(".json") else f"{out}.json"
            self.report_gen.generate_json(path)
            _success(f"JSON report saved to: {path}")
        elif fmt == "csv":
            path_risks    = f"{out}_risks.csv"
            path_controls = f"{out}_controls.csv"
            self.report_gen.generate_risk_csv(path_risks)
            self.report_gen.generate_controls_csv(path_controls)
            _success(f"CSV reports saved to: {path_risks}, {path_controls}")
        else:
            _error(f"Unknown format '{fmt}'. Choose: html, json, csv")

    # ── AI ────────────────────────────────────────────────────────────────────

    def cmd_ai_status(self, _args):
        available = self.ai.is_available()
        if available:
            models = self.ai.list_models()
            _success(f"Ollama is available. Models: {', '.join(models) or 'none pulled'}")
        else:
            _warn("Ollama is not running.")
            _print("  Start Ollama:    [bold]ollama serve[/]" if RICH_AVAILABLE else
                   "  Start Ollama:    ollama serve")
            _print("  Pull a model:    [bold]ollama pull llama3[/]" if RICH_AVAILABLE else
                   "  Pull a model:    ollama pull llama3")

    def cmd_ai_ask(self, args):
        topic = args.topic
        mode = getattr(args, "mode", "cloud")
        if not self.ai.is_available():
            _warn("Ollama is not running. See: grc ai status")
            return
        if mode == "ai-governance":
            result = self.ai.ai_governance_advice(topic)
        else:
            result = self.ai.cloud_security_advice(topic)
        _print_panel(f"🤖 AI Advisor – {topic}", result, "green")

    def cmd_ai_exec_summary(self, _args):
        if not self.ai.is_available():
            _warn("Ollama is not running. See: grc ai status")
            return
        rs = self.risk_mgr.risk_summary()
        cs = {fw: info["score"] for fw, info in self.ctrl_mgr.compliance_score().items()}
        ps = self.policy_mgr.policy_summary()
        result = self.ai.generate_executive_summary(rs, cs, ps)
        _print_panel("📊 AI Executive Summary", result, "blue")

    # ── Audit log ─────────────────────────────────────────────────────────────

    def cmd_audit(self, args):
        limit = getattr(args, "limit", 50)
        rows = self.db.fetchall(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        if RICH_AVAILABLE:
            tbl = Table(box=box.SIMPLE, title=f"Audit Log (last {limit})")
            tbl.add_column("Timestamp",   width=20)
            tbl.add_column("Actor",       width=12)
            tbl.add_column("Action",      width=10)
            tbl.add_column("Entity",      width=12)
            tbl.add_column("Entity ID",   width=10)
            tbl.add_column("Details",     max_width=40)
            for r in rows:
                tbl.add_row(
                    r["timestamp"], r["actor"], r["action"],
                    r["entity_type"], str(r["entity_id"] or ""),
                    r["details"],
                )
            console.print(tbl)
        else:
            for r in rows:
                print(f"{r['timestamp']}  {r['action']:10}  {r['entity_type']:12}  {r['entity_id']}")


# ──────────────────────────────────────────────────────────────────────────────
# Null context manager (used when rich is unavailable)
# ──────────────────────────────────────────────────────────────────────────────

class _NullContext:
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def add_task(self, *a, **kw): return None
    def remove_task(self, *a): pass


# ──────────────────────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grc",
        description="🛡 GRC Tool – Cloud & AI Governance, Risk & Compliance Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  grc dashboard
  grc risk list
  grc risk add
  grc risk view 1
  grc risk update 1 --status "In Progress" --owner alice
  grc risk ai 1

  grc control import --framework "NIST CSF"
  grc control import --framework all
  grc control list --framework "ISO 27001"
  grc control update CC6.1 --status "Implemented" --owner "IT Security"
  grc control score

  grc policy list
  grc policy create --template "Cloud Security Policy"
  grc policy approve POL-001 --approver "CISO"
  grc policy view POL-001

  grc assess create --framework "NIST CSF"
  grc assess list

  grc report --format html --output grc_report
  grc report --format json
  grc report --format csv

  grc ai status
  grc ai ask "S3 bucket security best practices" --mode cloud
  grc ai ask "AI model bias risks" --mode ai-governance
  grc ai exec-summary

  grc audit --limit 20
""",
    )
    parser.add_argument("--db", metavar="PATH", help="Path to SQLite database file")

    sub = parser.add_subparsers(dest="command")

    # dashboard
    sub.add_parser("dashboard", help="Show GRC dashboard")

    # ── risk ──────────────────────────────────────────────────────────────────
    risk_p = sub.add_parser("risk", help="Risk management")
    risk_sub = risk_p.add_subparsers(dest="subcommand")

    risk_list = risk_sub.add_parser("list", help="List risks")
    risk_list.add_argument("--status",   choices=RiskManager.STATUSES)
    risk_list.add_argument("--category")
    risk_list.add_argument("--level",    choices=["Critical","High","Medium","Low"])

    risk_sub.add_parser("add", help="Add a new risk (interactive)")

    risk_view = risk_sub.add_parser("view", help="View risk details")
    risk_view.add_argument("id", type=int)

    risk_upd = risk_sub.add_parser("update", help="Update a risk")
    risk_upd.add_argument("id", type=int)
    risk_upd.add_argument("--status",     choices=RiskManager.STATUSES)
    risk_upd.add_argument("--owner")
    risk_upd.add_argument("--likelihood", type=int, choices=range(1, 6))
    risk_upd.add_argument("--impact",     type=int, choices=range(1, 6))

    risk_ai = risk_sub.add_parser("ai", help="Get AI analysis for a risk")
    risk_ai.add_argument("id", type=int)

    risk_del = risk_sub.add_parser("delete", help="Delete a risk")
    risk_del.add_argument("id", type=int)

    # ── control ───────────────────────────────────────────────────────────────
    ctrl_p = sub.add_parser("control", help="Control management")
    ctrl_sub = ctrl_p.add_subparsers(dest="subcommand")

    ctrl_import = ctrl_sub.add_parser("import", help="Import framework controls")
    ctrl_import.add_argument(
        "--framework",
        default="all",
        choices=available_frameworks() + ["all"],
        help="Framework to import (default: all)",
    )

    ctrl_list = ctrl_sub.add_parser("list", help="List controls")
    ctrl_list.add_argument("--framework", choices=available_frameworks())
    ctrl_list.add_argument("--status",    choices=ControlManager.STATUSES)

    ctrl_upd = ctrl_sub.add_parser("update", help="Update control status")
    ctrl_upd.add_argument("control_id", help="Control ID string (e.g. CC6.1)")
    ctrl_upd.add_argument("--status", required=True, choices=ControlManager.STATUSES)
    ctrl_upd.add_argument("--implementation", default="")
    ctrl_upd.add_argument("--evidence",       default="")
    ctrl_upd.add_argument("--owner",          default="")

    ctrl_sub.add_parser("score", help="Show compliance scores")

    # ── policy ────────────────────────────────────────────────────────────────
    pol_p = sub.add_parser("policy", help="Policy management")
    pol_sub = pol_p.add_subparsers(dest="subcommand")

    pol_list = pol_sub.add_parser("list", help="List policies")
    pol_list.add_argument("--status", choices=PolicyManager.STATUSES)

    pol_templates = pol_sub.add_parser("templates", help="List available policy templates")

    pol_create = pol_sub.add_parser("create", help="Create policy from template")
    pol_create.add_argument("--template", required=True, metavar="TEMPLATE_NAME")

    pol_approve = pol_sub.add_parser("approve", help="Approve a policy")
    pol_approve.add_argument("policy_id")
    pol_approve.add_argument("--approver", required=True)

    pol_view = pol_sub.add_parser("view", help="View policy content")
    pol_view.add_argument("policy_id")

    # ── assess ────────────────────────────────────────────────────────────────
    assess_p = sub.add_parser("assess", help="Compliance assessments")
    assess_sub = assess_p.add_subparsers(dest="subcommand")

    assess_create = assess_sub.add_parser("create", help="Create a new assessment")
    assess_create.add_argument("--framework", required=True, choices=available_frameworks())

    assess_sub.add_parser("list", help="List assessments")

    # ── report ────────────────────────────────────────────────────────────────
    report_p = sub.add_parser("report", help="Generate reports")
    report_p.add_argument("--format", default="html", choices=["html", "json", "csv"])
    report_p.add_argument("--output", default="", help="Output file path (no extension)")

    # ── ai ────────────────────────────────────────────────────────────────────
    ai_p = sub.add_parser("ai", help="AI advisor (requires Ollama)")
    ai_sub = ai_p.add_subparsers(dest="subcommand")

    ai_sub.add_parser("status", help="Check Ollama availability")

    ai_ask = ai_sub.add_parser("ask", help="Ask the AI advisor a question")
    ai_ask.add_argument("topic", help="Topic to ask about")
    ai_ask.add_argument(
        "--mode",
        choices=["cloud", "ai-governance"],
        default="cloud",
    )

    ai_sub.add_parser("exec-summary", help="Generate AI executive summary")

    # ── audit ─────────────────────────────────────────────────────────────────
    audit_p = sub.add_parser("audit", help="View audit log")
    audit_p.add_argument("--limit", type=int, default=50)

    return parser


# ──────────────────────────────────────────────────────────────────────────────
# Dispatch
# ──────────────────────────────────────────────────────────────────────────────

_DISPATCH = {
    ("dashboard",  None):             "cmd_dashboard",
    ("risk",       "list"):           "cmd_risk_list",
    ("risk",       "add"):            "cmd_risk_add",
    ("risk",       "view"):           "cmd_risk_view",
    ("risk",       "update"):         "cmd_risk_update",
    ("risk",       "ai"):             "cmd_risk_ai",
    ("risk",       "delete"):         lambda app, args: (
        app.risk_mgr.delete_risk(args.id) or _success(f"Risk {args.id} deleted.")
    ),
    ("control",    "import"):         "cmd_control_import",
    ("control",    "list"):           "cmd_control_list",
    ("control",    "update"):         "cmd_control_update",
    ("control",    "score"):          "cmd_control_score",
    ("policy",     "list"):           "cmd_policy_list",
    ("policy",     "templates"):      lambda app, _: _print(
        "\n".join(f"  • {t}" for t in app.policy_mgr.available_templates())
    ),
    ("policy",     "create"):         "cmd_policy_create",
    ("policy",     "approve"):        "cmd_policy_approve",
    ("policy",     "view"):           "cmd_policy_view",
    ("assess",     "create"):         "cmd_assess_create",
    ("assess",     "list"):           "cmd_assess_list",
    ("report",     None):             "cmd_report",
    ("ai",         "status"):         "cmd_ai_status",
    ("ai",         "ask"):            "cmd_ai_ask",
    ("ai",         "exec-summary"):   "cmd_ai_exec_summary",
    ("audit",      None):             "cmd_audit",
}


def main(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return

    app = GRCApp(db_path=getattr(args, "db", None))

    sub = getattr(args, "subcommand", None)
    key = (args.command, sub)

    handler = _DISPATCH.get(key)
    if handler is None:
        # Try without subcommand
        handler = _DISPATCH.get((args.command, None))

    if handler is None:
        # Print sub-help
        parser.parse_args([args.command, "--help"])
        return

    if callable(handler) and not isinstance(handler, str):
        handler(app, args)
    else:
        getattr(app, handler)(args)


if __name__ == "__main__":
    main()
