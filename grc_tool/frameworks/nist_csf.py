"""
NIST Cybersecurity Framework (CSF) 2.0 – control catalogue.
Covers: Govern, Identify, Protect, Detect, Respond, Recover
"""

from __future__ import annotations


def get_controls() -> list[dict]:
    return [
        # ── GOVERN ───────────────────────────────────────────────────────────
        {
            "control_id": "GV.OC-01",
            "framework": "NIST CSF",
            "domain": "Govern – Organizational Context",
            "title": "Mission, Stakeholders & Legal Requirements",
            "description": "The organizational mission is understood and informs cybersecurity risk management. "
                           "Stakeholders are identified and their cybersecurity needs are incorporated.",
            "guidance": "Document organizational mission, identify internal/external stakeholders, "
                        "review applicable laws and regulations (e.g., GDPR, HIPAA, CCPA).",
        },
        {
            "control_id": "GV.OC-02",
            "framework": "NIST CSF",
            "domain": "Govern – Organizational Context",
            "title": "Internal & External Dependencies",
            "description": "Internal and external dependencies are identified and their cybersecurity "
                           "implications are understood.",
            "guidance": "Map supply chain and third-party dependencies; assess their security posture.",
        },
        {
            "control_id": "GV.RM-01",
            "framework": "NIST CSF",
            "domain": "Govern – Risk Management Strategy",
            "title": "Risk Appetite & Tolerance",
            "description": "Risk appetite and risk tolerance statements are established, communicated, "
                           "and maintained.",
            "guidance": "Document risk appetite in a board-approved statement; define quantitative "
                        "tolerances per risk category.",
        },
        {
            "control_id": "GV.RM-02",
            "framework": "NIST CSF",
            "domain": "Govern – Risk Management Strategy",
            "title": "Cybersecurity Risk Strategy",
            "description": "Cybersecurity risk management objectives are established and maintained.",
            "guidance": "Align cybersecurity risk strategy with enterprise risk management (ERM) program.",
        },
        {
            "control_id": "GV.SC-01",
            "framework": "NIST CSF",
            "domain": "Govern – Supply Chain Risk",
            "title": "Supply Chain Risk Management Program",
            "description": "A cybersecurity supply chain risk management program, strategy, objectives, "
                           "policies, and processes are established.",
            "guidance": "Implement SCRM policy; conduct third-party risk assessments; include security "
                        "clauses in vendor contracts.",
        },
        # ── IDENTIFY ─────────────────────────────────────────────────────────
        {
            "control_id": "ID.AM-01",
            "framework": "NIST CSF",
            "domain": "Identify – Asset Management",
            "title": "Hardware Asset Inventory",
            "description": "Physical devices and systems within the organization are inventoried.",
            "guidance": "Maintain a CMDB; conduct regular asset discovery scans; include cloud assets.",
        },
        {
            "control_id": "ID.AM-02",
            "framework": "NIST CSF",
            "domain": "Identify – Asset Management",
            "title": "Software Asset Inventory",
            "description": "Software platforms and applications within the organization are inventoried.",
            "guidance": "Use software composition analysis (SCA) tools; track SaaS subscriptions.",
        },
        {
            "control_id": "ID.AM-03",
            "framework": "NIST CSF",
            "domain": "Identify – Asset Management",
            "title": "Data Asset Inventory",
            "description": "Data and its associated processing and storage locations are identified "
                           "and recorded.",
            "guidance": "Classify data by sensitivity; map data flows; document cloud storage locations.",
        },
        {
            "control_id": "ID.RA-01",
            "framework": "NIST CSF",
            "domain": "Identify – Risk Assessment",
            "title": "Asset Vulnerability Identification",
            "description": "Vulnerabilities in assets are identified, validated, and recorded.",
            "guidance": "Run regular vulnerability scans (CVSS scoring); integrate with CVE feeds.",
        },
        {
            "control_id": "ID.RA-02",
            "framework": "NIST CSF",
            "domain": "Identify – Risk Assessment",
            "title": "Cyber Threat Intelligence",
            "description": "Cyber threat intelligence is received from information-sharing forums and sources.",
            "guidance": "Subscribe to ISACs, CISA alerts, and vendor threat feeds.",
        },
        {
            "control_id": "ID.RA-03",
            "framework": "NIST CSF",
            "domain": "Identify – Risk Assessment",
            "title": "Internal Threat Identification",
            "description": "Internal and external threats to the organization are identified and recorded.",
            "guidance": "Conduct threat modelling (STRIDE/PASTA); include insider threat scenarios.",
        },
        # ── PROTECT ──────────────────────────────────────────────────────────
        {
            "control_id": "PR.AA-01",
            "framework": "NIST CSF",
            "domain": "Protect – Identity & Access Management",
            "title": "Identity Management",
            "description": "Identities and credentials for authorized users, services, and hardware "
                           "are managed.",
            "guidance": "Implement MFA; enforce least-privilege; use privileged access management (PAM).",
        },
        {
            "control_id": "PR.AA-02",
            "framework": "NIST CSF",
            "domain": "Protect – Identity & Access Management",
            "title": "Remote Access Management",
            "description": "Remote access is managed.",
            "guidance": "Require VPN or Zero-Trust access; enforce device compliance checks.",
        },
        {
            "control_id": "PR.DS-01",
            "framework": "NIST CSF",
            "domain": "Protect – Data Security",
            "title": "Data at Rest Protection",
            "description": "The confidentiality, integrity, and availability of data-at-rest are protected.",
            "guidance": "Encrypt sensitive data at rest (AES-256); manage encryption keys via HSM/KMS.",
        },
        {
            "control_id": "PR.DS-02",
            "framework": "NIST CSF",
            "domain": "Protect – Data Security",
            "title": "Data in Transit Protection",
            "description": "The confidentiality, integrity, and availability of data-in-transit are protected.",
            "guidance": "Enforce TLS 1.2+; use HTTPS everywhere; inspect TLS in cloud workloads.",
        },
        {
            "control_id": "PR.PS-01",
            "framework": "NIST CSF",
            "domain": "Protect – Platform Security",
            "title": "Configuration Management",
            "description": "Configurations of hardware and software are maintained.",
            "guidance": "Use IaC (Terraform/CDK); enforce CIS Benchmarks; drift detection.",
        },
        {
            "control_id": "PR.PS-02",
            "framework": "NIST CSF",
            "domain": "Protect – Platform Security",
            "title": "Software Maintenance",
            "description": "Software is maintained.",
            "guidance": "Patch within SLA; automate patch management; track EOL software.",
        },
        # ── DETECT ───────────────────────────────────────────────────────────
        {
            "control_id": "DE.AE-02",
            "framework": "NIST CSF",
            "domain": "Detect – Adverse Event Analysis",
            "title": "Event Anomaly Analysis",
            "description": "Potentially adverse events are analyzed to better characterize them.",
            "guidance": "Correlate SIEM events; use UEBA for anomaly detection; establish baselines.",
        },
        {
            "control_id": "DE.CM-01",
            "framework": "NIST CSF",
            "domain": "Detect – Continuous Monitoring",
            "title": "Networks Monitored",
            "description": "Networks and network services are monitored to find potentially adverse events.",
            "guidance": "Deploy IDS/IPS; enable VPC Flow Logs; monitor DNS and egress traffic.",
        },
        {
            "control_id": "DE.CM-03",
            "framework": "NIST CSF",
            "domain": "Detect – Continuous Monitoring",
            "title": "Personnel Activity Monitored",
            "description": "Personnel activity and technology usage are monitored to find potentially "
                           "adverse events.",
            "guidance": "Enable CloudTrail / audit logs; monitor privileged user activity.",
        },
        # ── RESPOND ──────────────────────────────────────────────────────────
        {
            "control_id": "RS.MA-01",
            "framework": "NIST CSF",
            "domain": "Respond – Incident Management",
            "title": "Incident Response Plan",
            "description": "The potential impact of incidents is assessed.",
            "guidance": "Maintain an IRP; define severity levels; establish on-call rotation.",
        },
        {
            "control_id": "RS.CO-02",
            "framework": "NIST CSF",
            "domain": "Respond – Incident Communication",
            "title": "Internal Incident Reporting",
            "description": "Incidents are reported to appropriate internal and external stakeholders.",
            "guidance": "Define notification SLAs; prepare regulator notification templates (GDPR 72h).",
        },
        # ── RECOVER ──────────────────────────────────────────────────────────
        {
            "control_id": "RC.RP-01",
            "framework": "NIST CSF",
            "domain": "Recover – Incident Recovery Plan",
            "title": "Recovery Plan Execution",
            "description": "The recovery portion of the incident response plan is executed once "
                           "initiated by the appropriate staff.",
            "guidance": "Define RTO/RPO; test recovery playbooks quarterly; document lessons learned.",
        },
        {
            "control_id": "RC.RP-02",
            "framework": "NIST CSF",
            "domain": "Recover – Incident Recovery Plan",
            "title": "Recovery Plan Improvement",
            "description": "Recovery actions are selected, scoped, prioritized, and performed.",
            "guidance": "Conduct post-incident reviews; update runbooks; track improvement actions.",
        },
    ]
