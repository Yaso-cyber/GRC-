"""
Risk management module for the GRC Tool.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .database import Database
from .models import Risk


class RiskManager:
    """CRUD operations and analytics for risks."""

    CATEGORIES = [
        "Cloud Security", "AI/ML", "Operational", "Compliance",
        "Third-Party / Supply Chain", "Data Privacy", "Financial",
        "Strategic", "Reputational",
    ]

    STATUSES = ["Open", "In Progress", "Mitigated", "Accepted", "Closed"]
    TREATMENTS = ["Mitigate", "Accept", "Transfer", "Avoid"]

    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def add_risk(self, risk: Risk, actor: str = "system") -> int:
        """Insert a new risk and return its ID."""
        d = risk.to_dict()
        self.db.connect()
        cur = self.db.execute(
            """INSERT INTO risks
               (title, description, category, likelihood, impact, risk_level,
                owner, status, treatment, due_date, tags)
               VALUES (:title,:description,:category,:likelihood,:impact,
                       :risk_level,:owner,:status,:treatment,:due_date,:tags)""",
            d,
        )
        self.db.commit()
        risk_id = cur.lastrowid
        self.db.log_action("CREATE", "risk", risk_id,
                           {"title": risk.title, "level": risk.risk_level}, actor)
        return risk_id

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_risk(self, risk_id: int) -> Optional[Risk]:
        row = self.db.fetchone("SELECT * FROM risks WHERE id = ?", (risk_id,))
        return Risk.from_row(row) if row else None

    def list_risks(
        self,
        status: str | None = None,
        category: str | None = None,
        owner: str | None = None,
        level: str | None = None,
    ) -> list[Risk]:
        clauses, params = [], []
        if status:
            clauses.append("status = ?"); params.append(status)
        if category:
            clauses.append("category = ?"); params.append(category)
        if owner:
            clauses.append("owner = ?"); params.append(owner)
        if level:
            clauses.append("risk_level = ?"); params.append(level)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM risks {where} ORDER BY risk_score DESC", params
        )
        return [Risk.from_row(r) for r in rows]

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_risk(self, risk_id: int, updates: dict, actor: str = "system") -> bool:
        """Update fields on an existing risk."""
        allowed = {
            "title", "description", "category", "likelihood", "impact",
            "risk_level", "owner", "status", "treatment", "due_date", "tags",
        }
        updates = {k: v for k, v in updates.items() if k in allowed}
        if "tags" in updates and isinstance(updates["tags"], list):
            updates["tags"] = json.dumps(updates["tags"])
        # Recalculate risk_level if likelihood or impact changed
        if "likelihood" in updates or "impact" in updates:
            current = self.get_risk(risk_id)
            if current:
                lh = int(updates.get("likelihood", current.likelihood))
                im = int(updates.get("impact", current.impact))
                from .models import _risk_level
                updates["risk_level"] = _risk_level(lh * im)
        updates["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [risk_id]
        self.db.execute(f"UPDATE risks SET {set_clause} WHERE id = ?", values)
        self.db.commit()
        self.db.log_action("UPDATE", "risk", risk_id, updates, actor)
        return True

    def close_risk(self, risk_id: int, actor: str = "system"):
        self.update_risk(risk_id, {"status": "Closed"}, actor)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_risk(self, risk_id: int, actor: str = "system") -> bool:
        self.db.execute("DELETE FROM risks WHERE id = ?", (risk_id,))
        self.db.commit()
        self.db.log_action("DELETE", "risk", risk_id, {}, actor)
        return True

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def risk_summary(self) -> dict:
        """Return a summary dict useful for dashboard display."""
        rows = self.db.fetchall(
            """SELECT risk_level, status, COUNT(*) as cnt
               FROM risks GROUP BY risk_level, status"""
        )
        summary: dict = {
            "total": 0,
            "by_level": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "by_status": {s: 0 for s in self.STATUSES},
            "open_critical": 0,
            "open_high": 0,
        }
        for r in rows:
            summary["total"] += r["cnt"]
            summary["by_level"][r["risk_level"]] = (
                summary["by_level"].get(r["risk_level"], 0) + r["cnt"]
            )
            summary["by_status"][r["status"]] = (
                summary["by_status"].get(r["status"], 0) + r["cnt"]
            )
        # open critical/high
        for r in self.db.fetchall(
            "SELECT COUNT(*) as c FROM risks WHERE risk_level='Critical' AND status='Open'"
        ):
            summary["open_critical"] = r["c"]
        for r in self.db.fetchall(
            "SELECT COUNT(*) as c FROM risks WHERE risk_level='High' AND status='Open'"
        ):
            summary["open_high"] = r["c"]
        return summary

    def top_risks(self, n: int = 5) -> list[Risk]:
        """Return the n highest-scored open risks."""
        rows = self.db.fetchall(
            "SELECT * FROM risks WHERE status != 'Closed' "
            "ORDER BY risk_score DESC LIMIT ?", (n,)
        )
        return [Risk.from_row(r) for r in rows]
