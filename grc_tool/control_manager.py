"""
Control management module for the GRC Tool.
Handles importing framework controls and tracking implementation status.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .database import Database
from .models import Control
from .frameworks import get_framework_controls, available_frameworks


class ControlManager:
    """CRUD and analytics for security controls."""

    STATUSES = [
        "Not Implemented",
        "Planned",
        "Partially Implemented",
        "Implemented",
        "Not Applicable",
    ]

    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------
    # Framework import
    # ------------------------------------------------------------------

    def import_framework(self, framework: str, actor: str = "system") -> int:
        """Load framework controls into the database. Returns count imported."""
        controls = get_framework_controls(framework)
        imported = 0
        for c in controls:
            existing = self.db.fetchone(
                "SELECT id FROM controls WHERE control_id = ?", (c["control_id"],)
            )
            if existing:
                continue  # already loaded – skip to avoid duplicates
            self.db.execute(
                """INSERT INTO controls
                   (control_id, framework, domain, title, description, guidance)
                   VALUES (:control_id,:framework,:domain,:title,
                           :description,:guidance)""",
                {
                    "control_id": c["control_id"],
                    "framework": framework,
                    "domain": c.get("domain", ""),
                    "title": c.get("title", ""),
                    "description": c.get("description", ""),
                    "guidance": c.get("guidance", ""),
                },
            )
            imported += 1
        self.db.commit()
        self.db.log_action("IMPORT", "controls", None,
                           {"framework": framework, "count": imported}, actor)
        return imported

    def import_all_frameworks(self, actor: str = "system") -> dict[str, int]:
        results = {}
        for fw in available_frameworks():
            results[fw] = self.import_framework(fw, actor)
        return results

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def get_control(self, control_id: int | str) -> Optional[Control]:
        """Fetch by primary key (int) or control_id string."""
        if isinstance(control_id, int):
            row = self.db.fetchone("SELECT * FROM controls WHERE id = ?", (control_id,))
        else:
            row = self.db.fetchone(
                "SELECT * FROM controls WHERE control_id = ?", (control_id,)
            )
        return Control.from_row(row) if row else None

    def list_controls(
        self,
        framework: str | None = None,
        status: str | None = None,
        domain: str | None = None,
    ) -> list[Control]:
        clauses, params = [], []
        if framework:
            clauses.append("framework = ?"); params.append(framework)
        if status:
            clauses.append("status = ?"); params.append(status)
        if domain:
            clauses.append("domain LIKE ?"); params.append(f"%{domain}%")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM controls {where} ORDER BY framework, control_id", params
        )
        return [Control.from_row(r) for r in rows]

    def update_control_status(
        self,
        control_id: int | str,
        status: str,
        implementation: str = "",
        evidence: str = "",
        owner: str = "",
        actor: str = "system",
    ) -> bool:
        """Update the implementation status of a control."""
        if status not in self.STATUSES:
            raise ValueError(f"Invalid status '{status}'. Choose from: {self.STATUSES}")
        ctrl = self.get_control(control_id)
        if ctrl is None:
            return False
        self.db.execute(
            """UPDATE controls
               SET status=?, implementation=?, evidence=?, owner=?,
                   last_reviewed=?, updated_at=?
               WHERE id=?""",
            (
                status, implementation or ctrl.implementation,
                evidence or ctrl.evidence, owner or ctrl.owner,
                datetime.now(timezone.utc).date().isoformat(),
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ctrl.id,
            ),
        )
        self.db.commit()
        self.db.log_action("UPDATE", "control", ctrl.id,
                           {"status": status, "control_id": ctrl.control_id}, actor)
        return True

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def compliance_score(self, framework: str | None = None) -> dict:
        """
        Return per-framework (or overall) compliance score as a percentage
        of Implemented controls out of non-N/A controls.
        """
        query = "SELECT framework, status, COUNT(*) as cnt FROM controls"
        params: list = []
        if framework:
            query += " WHERE framework = ?"
            params.append(framework)
        query += " GROUP BY framework, status"
        rows = self.db.fetchall(query, params)

        scores: dict[str, dict] = {}
        for r in rows:
            fw = r["framework"]
            if fw not in scores:
                scores[fw] = {s: 0 for s in self.STATUSES}
            scores[fw][r["status"]] = r["cnt"]

        result = {}
        for fw, counts in scores.items():
            total = sum(v for k, v in counts.items() if k != "Not Applicable")
            implemented = counts.get("Implemented", 0)
            partial = counts.get("Partially Implemented", 0)
            pct = round(((implemented + 0.5 * partial) / total * 100), 1) if total else 0
            result[fw] = {
                "score": pct,
                "implemented": implemented,
                "partial": partial,
                "total_applicable": total,
                "by_status": counts,
            }
        return result

    def control_summary(self) -> dict:
        rows = self.db.fetchall(
            "SELECT status, COUNT(*) as cnt FROM controls GROUP BY status"
        )
        summary = {s: 0 for s in self.STATUSES}
        total = 0
        for r in rows:
            summary[r["status"]] = r["cnt"]
            total += r["cnt"]
        summary["total"] = total
        return summary
