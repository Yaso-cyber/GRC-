"""
Data models for the GRC Tool.
Plain Python dataclasses – no external dependencies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _risk_level(score: int) -> str:
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


# ──────────────────────────────────────────────────────────────────────────────
# Risk
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Risk:
    title: str
    description: str = ""
    category: str = "Operational"
    likelihood: int = 3          # 1-5
    impact: int = 3              # 1-5
    owner: str = ""
    status: str = "Open"
    treatment: str = "Mitigate"
    due_date: str = ""
    tags: list[str] = field(default_factory=list)
    id: Optional[int] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def risk_level(self) -> str:
        return _risk_level(self.risk_score)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_score"] = self.risk_score
        d["risk_level"] = self.risk_level
        d["tags"] = json.dumps(self.tags)
        return d

    @classmethod
    def from_row(cls, row) -> "Risk":
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        d.pop("risk_score", None)
        d.pop("risk_level", None)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ──────────────────────────────────────────────────────────────────────────────
# Control
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Control:
    control_id: str
    framework: str
    domain: str
    title: str
    description: str = ""
    guidance: str = ""
    implementation: str = ""
    status: str = "Not Implemented"
    evidence: str = ""
    owner: str = ""
    last_reviewed: str = ""
    tags: list[str] = field(default_factory=list)
    id: Optional[int] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tags"] = json.dumps(self.tags)
        return d

    @classmethod
    def from_row(cls, row) -> "Control":
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ──────────────────────────────────────────────────────────────────────────────
# Assessment
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Assessment:
    name: str
    framework: str
    scope: str = ""
    assessor: str = ""
    status: str = "Draft"
    score: Optional[float] = None
    findings: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    start_date: str = ""
    end_date: str = ""
    id: Optional[int] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = json.dumps(self.findings)
        d["recommendations"] = json.dumps(self.recommendations)
        return d

    @classmethod
    def from_row(cls, row) -> "Assessment":
        d = dict(row)
        d["findings"] = json.loads(d.get("findings") or "[]")
        d["recommendations"] = json.loads(d.get("recommendations") or "[]")
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ──────────────────────────────────────────────────────────────────────────────
# Policy
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Policy:
    title: str
    policy_id: str
    category: str
    version: str = "1.0"
    content: str = ""
    owner: str = ""
    approver: str = ""
    status: str = "Draft"
    effective_date: str = ""
    review_date: str = ""
    tags: list[str] = field(default_factory=list)
    id: Optional[int] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tags"] = json.dumps(self.tags)
        return d

    @classmethod
    def from_row(cls, row) -> "Policy":
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
