"""
Policy management module for the GRC Tool.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .database import Database
from .models import Policy


# Starter policy templates useful for Cloud / AI programmes
POLICY_TEMPLATES: dict[str, dict] = {
    "Cloud Security Policy": {
        "category": "Cloud Security",
        "content": """1. PURPOSE
This policy establishes requirements for securing cloud computing resources and services.

2. SCOPE
All cloud services (IaaS, PaaS, SaaS) used by the organisation.

3. POLICY STATEMENTS
3.1 All cloud resources must be provisioned through approved, organisation-managed accounts.
3.2 Multi-factor authentication (MFA) is mandatory for all cloud console access.
3.3 Encryption must be enabled for all cloud storage resources containing sensitive data.
3.4 Public access to cloud storage buckets/blobs is prohibited unless approved.
3.5 Cloud workloads must be deployed in accordance with the principle of least privilege.
3.6 All cloud infrastructure changes must be managed via Infrastructure-as-Code (IaC).
3.7 Cloud security posture management (CSPM) tooling must be deployed in all cloud accounts.
3.8 Cloud resource costs and anomalies must be monitored continuously.

4. ROLES AND RESPONSIBILITIES
- Cloud Security Team: Define standards, review configurations, respond to alerts.
- DevOps / Platform Team: Implement controls, maintain IaC, respond to drift.
- Business Unit Owners: Approve cloud service usage within their scope.

5. REVIEW
This policy shall be reviewed annually or following a significant cloud security incident.
""",
    },
    "AI Governance Policy": {
        "category": "AI Governance",
        "content": """1. PURPOSE
This policy governs the responsible development, deployment, and use of artificial intelligence
systems within the organisation.

2. SCOPE
All AI/ML systems developed or procured by the organisation, including generative AI tools.

3. PRINCIPLES
3.1 Fairness: AI systems must not produce discriminatory outcomes.
3.2 Transparency: AI decision-making must be explainable to affected parties.
3.3 Accountability: A human must be accountable for every AI system.
3.4 Safety: AI systems must be tested against adversarial inputs before deployment.
3.5 Privacy: AI systems must comply with applicable data protection regulations.

4. POLICY STATEMENTS
4.1 All AI systems must undergo a risk assessment before deployment.
4.2 High-risk AI systems require board-level approval.
4.3 Training data must be reviewed for bias and privacy compliance.
4.4 Model performance must be monitored continuously post-deployment.
4.5 AI-generated outputs used in regulated decisions must be reviewed by a human.
4.6 Third-party AI models must be assessed under the AI supply chain risk process.

5. PROHIBITED USES
- AI systems that make final decisions on employment, credit, or health without human review.
- Use of personal data for AI training without a lawful basis.
- Deployment of AI systems with known significant bias without remediation.

6. REVIEW
This policy shall be reviewed bi-annually or when significant AI regulatory changes occur.
""",
    },
    "Data Classification Policy": {
        "category": "Data Governance",
        "content": """1. PURPOSE
Define how organisational data is classified and protected based on sensitivity.

2. CLASSIFICATION TIERS

PUBLIC
  Definition: Information approved for public release.
  Controls:   No special handling required.

INTERNAL
  Definition: Information for internal use only; disclosure would cause minor harm.
  Controls:   Access restricted to employees; basic access controls.

CONFIDENTIAL
  Definition: Sensitive business or personal data; disclosure would cause significant harm.
  Controls:   Encrypted at rest and in transit; need-to-know access; logged access.

RESTRICTED
  Definition: Highly sensitive data (PII, PHI, credentials); disclosure would cause severe harm.
  Controls:   Encrypted (AES-256); MFA required; DLP controls; annual access review.

3. HANDLING REQUIREMENTS
3.1 All new data stores must be classified before deployment.
3.2 Data owners are responsible for applying and maintaining classifications.
3.3 Classification labels must be applied in cloud storage, databases, and documents.

4. REVIEW
This policy shall be reviewed annually.
""",
    },
    "Incident Response Policy": {
        "category": "Security Operations",
        "content": """1. PURPOSE
Establish a consistent and effective approach to managing security incidents.

2. INCIDENT SEVERITY LEVELS

CRITICAL (P1): Active breach, data exfiltration, ransomware. Respond within 15 minutes.
HIGH     (P2): Compromised account, malware infection. Respond within 1 hour.
MEDIUM   (P3): Policy violation, phishing attempt. Respond within 4 hours.
LOW      (P4): Minor anomaly, failed login. Respond within 24 hours.

3. INCIDENT RESPONSE PHASES
3.1 Preparation:  Maintain IRP; train responders; deploy detection tooling.
3.2 Detection:    Monitor SIEM alerts; accept reports via security@[org].
3.3 Containment:  Isolate affected systems; preserve evidence; notify stakeholders.
3.4 Eradication:  Remove malware; patch vulnerabilities; reset credentials.
3.5 Recovery:     Restore from clean backups; validate integrity; resume operations.
3.6 Lessons Learned: Conduct PIR within 5 business days; update runbooks.

4. NOTIFICATION REQUIREMENTS
- Internal: CISO notified within 1 hour of P1/P2 incidents.
- Regulator: Within 72 hours if personal data is involved (GDPR Article 33).
- Customers:  As required by contract or regulation.

5. REVIEW
This policy shall be reviewed annually and after every P1/P2 incident.
""",
    },
}


class PolicyManager:
    """CRUD and template management for security policies."""

    STATUSES = ["Draft", "Under Review", "Approved", "Deprecated"]
    CATEGORIES = [
        "Cloud Security", "AI Governance", "Data Governance",
        "Security Operations", "Access Management", "Business Continuity",
        "Vendor Management", "Privacy",
    ]

    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------
    # Template helpers
    # ------------------------------------------------------------------

    def available_templates(self) -> list[str]:
        return list(POLICY_TEMPLATES.keys())

    def create_from_template(
        self,
        template_name: str,
        policy_id: str,
        owner: str = "",
        actor: str = "system",
    ) -> int:
        """Create a new policy from a built-in template."""
        tmpl = POLICY_TEMPLATES.get(template_name)
        if not tmpl:
            raise ValueError(f"Unknown template '{template_name}'. "
                             f"Available: {self.available_templates()}")
        policy = Policy(
            title=template_name,
            policy_id=policy_id,
            category=tmpl["category"],
            content=tmpl["content"],
            owner=owner,
        )
        return self.add_policy(policy, actor=actor)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_policy(self, policy: Policy, actor: str = "system") -> int:
        d = policy.to_dict()
        cur = self.db.execute(
            """INSERT INTO policies
               (title, policy_id, version, category, content, owner, approver,
                status, effective_date, review_date, tags)
               VALUES (:title,:policy_id,:version,:category,:content,:owner,
                       :approver,:status,:effective_date,:review_date,:tags)""",
            d,
        )
        self.db.commit()
        pid = cur.lastrowid
        self.db.log_action("CREATE", "policy", pid,
                           {"title": policy.title, "policy_id": policy.policy_id}, actor)
        return pid

    def get_policy(self, policy_id: int | str) -> Optional[Policy]:
        if isinstance(policy_id, int):
            row = self.db.fetchone("SELECT * FROM policies WHERE id = ?", (policy_id,))
        else:
            row = self.db.fetchone(
                "SELECT * FROM policies WHERE policy_id = ?", (policy_id,)
            )
        return Policy.from_row(row) if row else None

    def list_policies(
        self,
        status: str | None = None,
        category: str | None = None,
    ) -> list[Policy]:
        clauses, params = [], []
        if status:
            clauses.append("status = ?"); params.append(status)
        if category:
            clauses.append("category = ?"); params.append(category)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.db.fetchall(
            f"SELECT * FROM policies {where} ORDER BY category, title", params
        )
        return [Policy.from_row(r) for r in rows]

    def update_policy(
        self, policy_id: int | str, updates: dict, actor: str = "system"
    ) -> bool:
        allowed = {
            "title", "version", "content", "owner", "approver",
            "status", "effective_date", "review_date", "tags",
        }
        updates = {k: v for k, v in updates.items() if k in allowed}
        if "tags" in updates and isinstance(updates["tags"], list):
            updates["tags"] = json.dumps(updates["tags"])
        updates["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

        policy = self.get_policy(policy_id)
        if policy is None:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        self.db.execute(
            f"UPDATE policies SET {set_clause} WHERE id = ?",
            list(updates.values()) + [policy.id],
        )
        self.db.commit()
        self.db.log_action("UPDATE", "policy", policy.id, updates, actor)
        return True

    def approve_policy(
        self, policy_id: int | str, approver: str, effective_date: str = "",
        actor: str = "system"
    ) -> bool:
        return self.update_policy(
            policy_id,
            {
                "status": "Approved",
                "approver": approver,
                "effective_date": effective_date or datetime.now(timezone.utc).date().isoformat(),
            },
            actor,
        )

    def policy_summary(self) -> dict:
        rows = self.db.fetchall(
            "SELECT status, COUNT(*) as cnt FROM policies GROUP BY status"
        )
        summary = {s: 0 for s in self.STATUSES}
        total = 0
        for r in rows:
            summary[r["status"]] = r["cnt"]
            total += r["cnt"]
        summary["total"] = total
        return summary
