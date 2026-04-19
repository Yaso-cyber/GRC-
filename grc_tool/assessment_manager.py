"""
Compliance assessment module for the GRC Tool.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .database import Database
from .models import Assessment
from .control_manager import ControlManager


class AssessmentManager:
    """Manage compliance assessments against security frameworks."""

    STATUSES = ["Draft", "In Progress", "Completed", "Archived"]

    def __init__(self, db: Database):
        self.db = db
        self.ctrl_mgr = ControlManager(db)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_assessment(self, assessment: Assessment, actor: str = "system") -> int:
        d = assessment.to_dict()
        cur = self.db.execute(
            """INSERT INTO assessments
               (name, framework, scope, assessor, status, findings,
                recommendations, start_date, end_date)
               VALUES (:name,:framework,:scope,:assessor,:status,
                       :findings,:recommendations,:start_date,:end_date)""",
            d,
        )
        self.db.commit()
        aid = cur.lastrowid
        self.db.log_action("CREATE", "assessment", aid,
                           {"name": assessment.name, "framework": assessment.framework}, actor)
        return aid

    def get_assessment(self, assessment_id: int) -> Optional[Assessment]:
        row = self.db.fetchone(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        )
        return Assessment.from_row(row) if row else None

    def list_assessments(
        self,
        framework: str | None = None,
        status: str | None = None,
    ) -> list[Assessment]:
        clauses, params = [], []
        if framework:
            clauses.append("framework = ?"); params.append(framework)
        if status:
            clauses.append("status = ?"); params.append(status)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM assessments {where} ORDER BY created_at DESC", params
        )
        return [Assessment.from_row(r) for r in rows]

    def update_assessment(
        self, assessment_id: int, updates: dict, actor: str = "system"
    ) -> bool:
        allowed = {
            "name", "scope", "assessor", "status", "score",
            "findings", "recommendations", "start_date", "end_date",
        }
        updates = {k: v for k, v in updates.items() if k in allowed}
        for list_field in ("findings", "recommendations"):
            if list_field in updates and isinstance(updates[list_field], list):
                updates[list_field] = json.dumps(updates[list_field])
        updates["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        self.db.execute(
            f"UPDATE assessments SET {set_clause} WHERE id = ?",
            list(updates.values()) + [assessment_id],
        )
        self.db.commit()
        self.db.log_action("UPDATE", "assessment", assessment_id, updates, actor)
        return True

    # ------------------------------------------------------------------
    # Auto-score from control statuses
    # ------------------------------------------------------------------

    def score_from_controls(self, assessment_id: int, actor: str = "system") -> float:
        """
        Derive an assessment score automatically from the current
        implementation status of controls for the assessment's framework.
        """
        assessment = self.get_assessment(assessment_id)
        if assessment is None:
            raise ValueError(f"Assessment {assessment_id} not found.")

        scores = self.ctrl_mgr.compliance_score(assessment.framework)
        fw_score = scores.get(assessment.framework, {}).get("score", 0.0)

        # Build findings list based on non-implemented controls
        not_impl = self.ctrl_mgr.list_controls(
            framework=assessment.framework, status="Not Implemented"
        )
        planned = self.ctrl_mgr.list_controls(
            framework=assessment.framework, status="Planned"
        )
        partial = self.ctrl_mgr.list_controls(
            framework=assessment.framework, status="Partially Implemented"
        )

        findings = []
        for c in not_impl:
            findings.append({
                "control_id": c.control_id,
                "title": c.title,
                "gap": "Not Implemented",
                "recommendation": c.guidance or "Implement this control.",
            })
        for c in partial:
            findings.append({
                "control_id": c.control_id,
                "title": c.title,
                "gap": "Partially Implemented",
                "recommendation": c.guidance or "Complete implementation of this control.",
            })

        recommendations = [
            f"Implement {c.control_id} ({c.title})." for c in not_impl[:5]
        ]

        self.update_assessment(
            assessment_id,
            {
                "score": fw_score,
                "status": "Completed",
                "findings": findings,
                "recommendations": recommendations,
                "end_date": datetime.now(timezone.utc).date().isoformat(),
            },
            actor,
        )
        return fw_score

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def assessment_summary(self) -> dict:
        rows = self.db.fetchall(
            "SELECT framework, score FROM assessments WHERE status='Completed'"
        )
        by_fw: dict[str, list[float]] = {}
        for r in rows:
            by_fw.setdefault(r["framework"], []).append(r["score"] or 0.0)
        return {
            fw: round(sum(scores) / len(scores), 1)
            for fw, scores in by_fw.items()
        }
