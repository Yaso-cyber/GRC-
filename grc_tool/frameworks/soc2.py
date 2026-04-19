"""
SOC 2 Trust Service Criteria (TSC) – control catalogue.
Categories: Security (CC), Availability (A), Confidentiality (C),
            Processing Integrity (PI), Privacy (P)
"""

from __future__ import annotations


def get_controls() -> list[dict]:
    return [
        # ── CC1 Control Environment ───────────────────────────────────────────
        {
            "control_id": "CC1.1",
            "framework": "SOC 2",
            "domain": "CC1 – Control Environment",
            "title": "COSO Principle 1: Commitment to Integrity and Ethics",
            "description": "The entity demonstrates a commitment to integrity and ethical values.",
            "guidance": "Publish a code of ethics; conduct annual ethics training; track policy "
                        "acknowledgements.",
        },
        {
            "control_id": "CC1.2",
            "framework": "SOC 2",
            "domain": "CC1 – Control Environment",
            "title": "Board Oversight",
            "description": "The board of directors demonstrates independence from management and "
                           "exercises oversight of the development and performance of internal control.",
            "guidance": "Establish audit committee; schedule quarterly security reviews with board.",
        },
        # ── CC2 Communication & Information ───────────────────────────────────
        {
            "control_id": "CC2.1",
            "framework": "SOC 2",
            "domain": "CC2 – Communication & Information",
            "title": "Risk Information Usage",
            "description": "The entity obtains or generates and uses relevant, quality information to "
                           "support the functioning of internal control.",
            "guidance": "Establish data quality controls; document information flows; review logs.",
        },
        # ── CC3 Risk Assessment ────────────────────────────────────────────────
        {
            "control_id": "CC3.1",
            "framework": "SOC 2",
            "domain": "CC3 – Risk Assessment",
            "title": "Specify Objectives",
            "description": "The entity specifies objectives with sufficient clarity to enable the "
                           "identification and assessment of risks relating to objectives.",
            "guidance": "Document service commitments and system requirements. Map to risk categories.",
        },
        {
            "control_id": "CC3.2",
            "framework": "SOC 2",
            "domain": "CC3 – Risk Assessment",
            "title": "Risk Identification & Analysis",
            "description": "The entity identifies risks to the achievement of its objectives across "
                           "the entity and analyses risks as a basis for determining how risks should "
                           "be managed.",
            "guidance": "Conduct formal risk assessment annually. Score by likelihood and impact.",
        },
        # ── CC6 Logical Access Controls ───────────────────────────────────────
        {
            "control_id": "CC6.1",
            "framework": "SOC 2",
            "domain": "CC6 – Logical & Physical Access",
            "title": "Logical Access Security Measures",
            "description": "The entity implements logical access security software, infrastructure, "
                           "and architectures over protected information assets.",
            "guidance": "Enforce RBAC; implement MFA; log all privileged access; review quarterly.",
        },
        {
            "control_id": "CC6.2",
            "framework": "SOC 2",
            "domain": "CC6 – Logical & Physical Access",
            "title": "Provisioning & Deprovisioning",
            "description": "Prior to issuing system credentials and granting system access, the entity "
                           "registers and authorizes new internal and external users.",
            "guidance": "Automate user provisioning via IdP; deactivate accounts within 24h of "
                        "termination; review access quarterly.",
        },
        {
            "control_id": "CC6.7",
            "framework": "SOC 2",
            "domain": "CC6 – Logical & Physical Access",
            "title": "Data Transmission & Disclosure Restrictions",
            "description": "The entity restricts the transmission, movement, and removal of "
                           "information to authorised users.",
            "guidance": "Encrypt data in transit (TLS 1.2+); implement DLP; audit bulk data exports.",
        },
        # ── CC7 System Operations ─────────────────────────────────────────────
        {
            "control_id": "CC7.1",
            "framework": "SOC 2",
            "domain": "CC7 – System Operations",
            "title": "Vulnerability Detection",
            "description": "To meet its objectives, the entity uses detection and monitoring procedures "
                           "to identify changes to configurations, new vulnerabilities, and signs of "
                           "unauthorized activities.",
            "guidance": "Perform weekly vulnerability scans; monitor configuration drift; use IDS.",
        },
        {
            "control_id": "CC7.2",
            "framework": "SOC 2",
            "domain": "CC7 – System Operations",
            "title": "Monitoring",
            "description": "The entity monitors system components and the operation of those controls "
                           "for anomalies.",
            "guidance": "Deploy SIEM; define alert rules; establish on-call response procedures.",
        },
        {
            "control_id": "CC7.3",
            "framework": "SOC 2",
            "domain": "CC7 – System Operations",
            "title": "Incident Evaluation",
            "description": "The entity evaluates security events to determine whether they could or "
                           "have resulted in a failure of the entity to meet its objectives.",
            "guidance": "Triage all security alerts within defined SLA; escalate incidents per IRP.",
        },
        # ── CC8 Change Management ──────────────────────────────────────────────
        {
            "control_id": "CC8.1",
            "framework": "SOC 2",
            "domain": "CC8 – Change Management",
            "title": "Change Management Process",
            "description": "The entity authorizes, designs, develops or acquires, configures, "
                           "documents, tests, approves, and implements changes to infrastructure, "
                           "data, software, and procedures to meet its objectives.",
            "guidance": "Implement formal change management process; require approval for production "
                        "changes; maintain change log.",
        },
        # ── A Availability ─────────────────────────────────────────────────────
        {
            "control_id": "A1.1",
            "framework": "SOC 2",
            "domain": "A – Availability",
            "title": "Availability Commitments & Requirements",
            "description": "The entity maintains, monitors, and evaluates current processing capacity "
                           "and use of system components to manage capacity demand.",
            "guidance": "Define SLA uptime targets; implement auto-scaling; monitor capacity metrics.",
        },
        {
            "control_id": "A1.2",
            "framework": "SOC 2",
            "domain": "A – Availability",
            "title": "Environmental Threats & Resilience",
            "description": "The entity authorizes, designs, develops or acquires, implements, "
                           "operates, approves, maintains, and monitors environmental controls.",
            "guidance": "Deploy across multiple AZs; implement health checks; test failover quarterly.",
        },
    ]
