"""
AI Advisor module – provides risk and compliance guidance via Ollama (local LLM).
Falls back gracefully if Ollama is not available.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional


OLLAMA_DEFAULT_URL = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "llama3"

SYSTEM_PROMPT = """You are an expert GRC (Governance, Risk & Compliance) analyst specialising
in Cloud Security and AI Governance. You have deep knowledge of NIST CSF, NIST AI RMF,
ISO 27001, SOC 2, CSA CCM, GDPR, and cloud security best practices (AWS, Azure, GCP).

Provide concise, actionable, professional advice. Format responses with clear headings and
bullet points where helpful. Focus on practical implementation guidance."""


class AIAdvisor:
    """
    Wraps the Ollama local-LLM API.
    All methods gracefully degrade if Ollama is unavailable.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_DEFAULT_URL,
        model: str = OLLAMA_DEFAULT_MODEL,
        timeout: int = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the Ollama server is reachable."""
        try:
            req = urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=3)
            return req.status == 200
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return available Ollama models."""
        try:
            req = urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=5)
            data = json.loads(req.read())
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Core LLM call
    # ------------------------------------------------------------------

    def _chat(self, user_message: str, system: str = SYSTEM_PROMPT) -> str:
        """Send a message to Ollama and return the response text."""
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())
            return data["message"]["content"].strip()

    def _safe_chat(self, user_message: str, fallback: str = "") -> str:
        """_chat with a graceful fallback if Ollama is unavailable."""
        try:
            return self._chat(user_message)
        except urllib.error.URLError:
            return (
                fallback or
                "⚠ Ollama is not available. Start Ollama with `ollama serve` and "
                f"ensure the model '{self.model}' is pulled (`ollama pull {self.model}`)."
            )
        except Exception as exc:
            return f"⚠ AI Advisor error: {exc}"

    # ------------------------------------------------------------------
    # High-level advisory methods
    # ------------------------------------------------------------------

    def analyse_risk(self, risk_title: str, description: str, category: str,
                     likelihood: int, impact: int) -> str:
        """Get AI-generated analysis and mitigation advice for a risk."""
        prompt = f"""Analyse the following GRC risk and provide:
1. A brief risk analysis (2-3 sentences)
2. Top 3 mitigation recommendations
3. Relevant security controls from NIST CSF, ISO 27001, or CSA CCM

Risk Title: {risk_title}
Category: {category}
Description: {description}
Likelihood: {likelihood}/5
Impact: {impact}/5
Risk Score: {likelihood * impact}/25
"""
        return self._safe_chat(prompt)

    def assess_control_gap(self, control_id: str, title: str, framework: str,
                           description: str, current_status: str) -> str:
        """Get guidance on implementing a specific control."""
        prompt = f"""Provide implementation guidance for this security control:

Control ID: {control_id}
Framework: {framework}
Title: {title}
Description: {description}
Current Status: {current_status}

Please provide:
1. A brief explanation of why this control matters for Cloud/AI environments
2. Step-by-step implementation approach (3-5 steps)
3. Common pitfalls to avoid
4. Evidence artefacts to collect for audit purposes
"""
        return self._safe_chat(prompt)

    def review_policy(self, policy_title: str, content: str) -> str:
        """Get AI feedback on a security policy."""
        prompt = f"""Review the following information security policy and provide:
1. Strengths (2-3 points)
2. Gaps or weaknesses (2-3 points)
3. Recommended improvements
4. Compliance alignment (NIST, ISO 27001, SOC 2)

Policy Title: {policy_title}

Policy Content:
{content[:3000]}  # limit to avoid token overflow
"""
        return self._safe_chat(prompt)

    def generate_risk_treatment_plan(
        self,
        risk_title: str,
        risk_description: str,
        risk_level: str,
        treatment: str,
    ) -> str:
        """Generate a risk treatment plan."""
        prompt = f"""Generate a detailed risk treatment plan for the following risk:

Risk: {risk_title}
Description: {risk_description}
Risk Level: {risk_level}
Treatment Strategy: {treatment}

Include:
1. Specific actions to implement
2. Responsible parties (roles)
3. Timeline recommendations
4. Success metrics / KRIs
5. Residual risk expectation after treatment
"""
        return self._safe_chat(prompt)

    def cloud_security_advice(self, topic: str) -> str:
        """Get cloud security best-practice advice on a topic."""
        prompt = f"""Provide cloud security best-practice advice on: {topic}

Focus on:
- AWS / Azure / GCP specific controls where applicable
- Relevant compliance frameworks (CSA CCM, NIST CSF, ISO 27001)
- Practical implementation steps
- Common misconfigurations to avoid
"""
        return self._safe_chat(prompt)

    def ai_governance_advice(self, topic: str) -> str:
        """Get AI governance advice on a topic."""
        prompt = f"""Provide AI governance and risk management advice on: {topic}

Reference:
- NIST AI RMF 1.0
- EU AI Act (where relevant)
- MITRE ATLAS for adversarial ML threats
- Practical controls for AI/ML pipelines
"""
        return self._safe_chat(prompt)

    def generate_executive_summary(
        self,
        risk_summary: dict,
        compliance_scores: dict,
        policy_summary: dict,
    ) -> str:
        """Generate an executive-level GRC summary."""
        prompt = f"""Generate a professional executive summary for a GRC status report.

Risk Posture:
{json.dumps(risk_summary, indent=2)}

Compliance Scores (% implemented):
{json.dumps(compliance_scores, indent=2)}

Policy Status:
{json.dumps(policy_summary, indent=2)}

Write a 3-4 paragraph executive summary covering:
1. Overall security posture assessment
2. Top 3 risks requiring executive attention
3. Compliance status and gaps
4. Recommended priority actions for the next 90 days
"""
        return self._safe_chat(prompt)
