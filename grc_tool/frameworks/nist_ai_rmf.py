"""
NIST AI Risk Management Framework (AI RMF 1.0) – control catalogue.
Functions: GOVERN, MAP, MEASURE, MANAGE
"""

from __future__ import annotations


def get_controls() -> list[dict]:
    return [
        # ── GOVERN ───────────────────────────────────────────────────────────
        {
            "control_id": "GOVERN-1.1",
            "framework": "NIST AI RMF",
            "domain": "GOVERN – Policies & Processes",
            "title": "AI Risk Management Policy",
            "description": "Policies, processes, procedures, and practices across the organization "
                           "related to the mapping, measuring, and managing of AI risks are in place, "
                           "transparent, and implemented effectively.",
            "guidance": "Establish an AI governance policy endorsed by senior leadership. Define roles "
                        "(CAIO, AI risk owner). Include human oversight requirements.",
        },
        {
            "control_id": "GOVERN-1.2",
            "framework": "NIST AI RMF",
            "domain": "GOVERN – Policies & Processes",
            "title": "AI Risk Appetite & Tolerances",
            "description": "Organizational risk tolerances are determined and communicated through "
                           "policies and guidelines.",
            "guidance": "Define acceptable AI risk thresholds per business unit. Include bias, "
                        "fairness, and safety tolerance levels.",
        },
        {
            "control_id": "GOVERN-1.3",
            "framework": "NIST AI RMF",
            "domain": "GOVERN – Policies & Processes",
            "title": "AI Transparency & Explainability",
            "description": "Organizational teams document the limits of AI transparency and "
                           "explainability and evaluate where greater transparency and explainability "
                           "are needed.",
            "guidance": "Use explainable AI (XAI) techniques. Document model cards. Define disclosure "
                        "requirements for AI-generated decisions.",
        },
        {
            "control_id": "GOVERN-2.1",
            "framework": "NIST AI RMF",
            "domain": "GOVERN – Accountability",
            "title": "Roles & Responsibilities",
            "description": "Roles and responsibilities and organizational accountability are "
                           "established for teams that design, develop, deploy, evaluate, and acquire "
                           "AI systems.",
            "guidance": "Assign RACI matrix for AI lifecycle. Include data scientists, MLOps, legal, "
                        "and compliance stakeholders.",
        },
        {
            "control_id": "GOVERN-5.1",
            "framework": "NIST AI RMF",
            "domain": "GOVERN – Workforce & Culture",
            "title": "AI Risk Awareness Training",
            "description": "Organizational teams involved with AI system design, development, "
                           "deployment, and evaluation have documented guidance about risk, including "
                           "roles and responsibilities.",
            "guidance": "Deliver annual AI ethics and risk training. Include bias, fairness, and "
                        "regulatory topics (EU AI Act, NIST AI RMF).",
        },
        # ── MAP ──────────────────────────────────────────────────────────────
        {
            "control_id": "MAP-1.1",
            "framework": "NIST AI RMF",
            "domain": "MAP – Context",
            "title": "AI System Intended Purpose",
            "description": "Context is established for the AI risk assessment. Intended purpose, "
                           "potentially beneficial uses, context-specific laws and regulations, "
                           "and organizational risk tolerances are understood.",
            "guidance": "Document AI system purpose, use case, beneficiaries, and potential harms. "
                        "Perform stakeholder impact analysis.",
        },
        {
            "control_id": "MAP-2.1",
            "framework": "NIST AI RMF",
            "domain": "MAP – Categorization",
            "title": "AI System Categorization",
            "description": "Scientific findings and established or emerging best practices are used "
                           "to identify and categorize AI risk.",
            "guidance": "Classify AI systems by risk tier (high, limited, minimal). Reference EU AI "
                        "Act Annex III for prohibited/high-risk categories.",
        },
        {
            "control_id": "MAP-3.1",
            "framework": "NIST AI RMF",
            "domain": "MAP – AI Risks",
            "title": "Benefits & Costs Assessment",
            "description": "AI risks and benefits — including harms — are identified with input from "
                           "relevant AI actors.",
            "guidance": "Conduct red-teaming exercises. Assess adversarial attacks, model poisoning, "
                        "and data privacy risks.",
        },
        {
            "control_id": "MAP-5.1",
            "framework": "NIST AI RMF",
            "domain": "MAP – Impacts",
            "title": "Likelihood & Magnitude of Harms",
            "description": "Likelihood and magnitude of each identified impact are estimated and "
                           "documented.",
            "guidance": "Use risk scoring matrices. Consider second-order effects and societal impact.",
        },
        # ── MEASURE ──────────────────────────────────────────────────────────
        {
            "control_id": "MEASURE-1.1",
            "framework": "NIST AI RMF",
            "domain": "MEASURE – Assessment Methods",
            "title": "AI Risk Measurement Approaches",
            "description": "Approaches and metrics for measuring AI risks are selected and applied.",
            "guidance": "Define KRIs for AI systems: model drift, bias metrics (demographic parity, "
                        "equalized odds), accuracy degradation thresholds.",
        },
        {
            "control_id": "MEASURE-2.1",
            "framework": "NIST AI RMF",
            "domain": "MEASURE – AI Trustworthiness",
            "title": "Trustworthiness Testing",
            "description": "Test sets, metrics, and details about the tools used during test, "
                           "evaluation, verification, and validation (TEVV) are documented.",
            "guidance": "Implement TEVV pipeline. Test for fairness, robustness, and reliability. "
                        "Document test datasets and results.",
        },
        {
            "control_id": "MEASURE-2.5",
            "framework": "NIST AI RMF",
            "domain": "MEASURE – AI Trustworthiness",
            "title": "Privacy Risk Measurement",
            "description": "Privacy risks of the AI system are examined.",
            "guidance": "Conduct Privacy Impact Assessment (PIA). Check for membership inference "
                        "attacks and training data leakage.",
        },
        {
            "control_id": "MEASURE-2.6",
            "framework": "NIST AI RMF",
            "domain": "MEASURE – AI Trustworthiness",
            "title": "Security Risks Measurement",
            "description": "Practices and personnel for supporting AI security are in place.",
            "guidance": "Assess adversarial ML risks (evasion, poisoning, extraction). Test model "
                        "robustness against adversarial inputs.",
        },
        {
            "control_id": "MEASURE-4.1",
            "framework": "NIST AI RMF",
            "domain": "MEASURE – Feedback",
            "title": "AI Risk Metrics Review",
            "description": "AI risk management is integrated into broader enterprise risk management.",
            "guidance": "Report AI risk metrics to risk committee. Review quarterly; update tolerances "
                        "based on performance data.",
        },
        # ── MANAGE ───────────────────────────────────────────────────────────
        {
            "control_id": "MANAGE-1.1",
            "framework": "NIST AI RMF",
            "domain": "MANAGE – Risk Treatment",
            "title": "AI Risks Prioritized & Addressed",
            "description": "A determination is made as to whether the AI system achieves its intended "
                           "purpose and stated objectives and whether its development or deployment "
                           "should proceed, be modified, monitored with additional controls, or "
                           "discontinued.",
            "guidance": "Define go/no-go criteria for AI deployment. Implement kill-switch mechanisms "
                        "for high-risk AI systems.",
        },
        {
            "control_id": "MANAGE-2.2",
            "framework": "NIST AI RMF",
            "domain": "MANAGE – Risk Treatment",
            "title": "AI System Monitoring & Feedback",
            "description": "Mechanisms are in place and applied to sustain the value of deployed AI "
                           "systems and apply any identified risk controls.",
            "guidance": "Implement model monitoring (drift detection, performance degradation). "
                        "Establish feedback loops from end users.",
        },
        {
            "control_id": "MANAGE-3.1",
            "framework": "NIST AI RMF",
            "domain": "MANAGE – Responses",
            "title": "AI Incident Response",
            "description": "Responses to the AI risks deemed high priority are developed, planned, "
                           "and documented.",
            "guidance": "Create AI-specific incident response playbooks. Define escalation paths for "
                        "AI system failures and bias incidents.",
        },
        {
            "control_id": "MANAGE-4.1",
            "framework": "NIST AI RMF",
            "domain": "MANAGE – Residual Risks",
            "title": "Residual Risk Management",
            "description": "Residual risks not addressed are documented.",
            "guidance": "Maintain risk register for accepted AI residual risks. Obtain formal sign-off "
                        "from risk owner and CISO.",
        },
    ]
