"""
Cloud Security Alliance (CSA) Cloud Controls Matrix (CCM) v4 – control catalogue.
Selected key domains relevant to Cloud & AI GRC.
"""

from __future__ import annotations


def get_controls() -> list[dict]:
    return [
        # ── AIS – Application & Interface Security ────────────────────────────
        {
            "control_id": "AIS-01",
            "framework": "CSA CCM",
            "domain": "AIS – Application & Interface Security",
            "title": "Application Security Baseline Requirements",
            "description": "Establish, document, and maintain a baseline for application security "
                           "requirements and secure design/coding practices.",
            "guidance": "Document OWASP Top 10 controls; include API security (authentication, "
                        "rate-limiting, input validation).",
        },
        {
            "control_id": "AIS-04",
            "framework": "CSA CCM",
            "domain": "AIS – Application & Interface Security",
            "title": "Secure Application Design & Development",
            "description": "Define and implement a SDLC process for design, development, deployment, "
                           "and operation of applications.",
            "guidance": "Integrate SAST/DAST/SCA tools in CI/CD pipeline; perform threat modelling "
                        "at design phase.",
        },
        # ── BCR – Business Continuity ──────────────────────────────────────────
        {
            "control_id": "BCR-01",
            "framework": "CSA CCM",
            "domain": "BCR – Business Continuity Management",
            "title": "Business Continuity Planning",
            "description": "Establish, document, approve, and implement business continuity plans.",
            "guidance": "Define BCP scope; test annually; include cloud provider outage scenarios.",
        },
        {
            "control_id": "BCR-09",
            "framework": "CSA CCM",
            "domain": "BCR – Business Continuity Management",
            "title": "Backup & Recovery",
            "description": "Backup and recovery of business-critical data shall be implemented.",
            "guidance": "Implement 3-2-1 backup strategy; test restores quarterly; use cloud-native "
                        "backup services (AWS Backup, Azure Backup).",
        },
        # ── CEK – Cryptography & Encryption Key Management ────────────────────
        {
            "control_id": "CEK-01",
            "framework": "CSA CCM",
            "domain": "CEK – Cryptography & Key Management",
            "title": "Encryption & Key Management Policy",
            "description": "Establish, document, and review cryptography, encryption, and key "
                           "management policies and procedures.",
            "guidance": "Document encryption algorithms (AES-256, RSA-2048+); integrate with cloud "
                        "KMS; enforce key rotation.",
        },
        {
            "control_id": "CEK-03",
            "framework": "CSA CCM",
            "domain": "CEK – Cryptography & Key Management",
            "title": "Sensitive Data Encryption",
            "description": "Sensitive data shall be protected by leveraging the appropriate encryption "
                           "method.",
            "guidance": "Classify data; encrypt at rest and in transit; use envelope encryption for "
                        "cloud object storage.",
        },
        # ── CCC – Change Control & Configuration ──────────────────────────────
        {
            "control_id": "CCC-01",
            "framework": "CSA CCM",
            "domain": "CCC – Change Control & Configuration",
            "title": "Change Management Policy",
            "description": "Establish, document, approve, communicate, and enforce change management "
                           "policies and procedures.",
            "guidance": "Require CAB approval for production changes; implement IaC for all infra "
                        "changes; maintain audit trail.",
        },
        {
            "control_id": "CCC-04",
            "framework": "CSA CCM",
            "domain": "CCC – Change Control & Configuration",
            "title": "Security Impact Analysis",
            "description": "The potential security impact of proposed changes shall be evaluated.",
            "guidance": "Include security review in change request workflow; use CSPM to detect "
                        "configuration drift.",
        },
        # ── DSP – Data Security & Privacy ─────────────────────────────────────
        {
            "control_id": "DSP-01",
            "framework": "CSA CCM",
            "domain": "DSP – Data Security & Privacy Lifecycle Management",
            "title": "Data Security & Privacy Policy",
            "description": "Establish, document, approve, communicate, and enforce a data security "
                           "and privacy policy.",
            "guidance": "Align with GDPR, CCPA; document data retention, deletion, and breach "
                        "notification procedures.",
        },
        {
            "control_id": "DSP-04",
            "framework": "CSA CCM",
            "domain": "DSP – Data Security & Privacy Lifecycle Management",
            "title": "Data Classification",
            "description": "A data classification policy shall be established.",
            "guidance": "Define tiers (Public, Internal, Confidential, Restricted); apply labels in "
                        "cloud storage (S3, Blob); automate classification with DLP.",
        },
        {
            "control_id": "DSP-07",
            "framework": "CSA CCM",
            "domain": "DSP – Data Security & Privacy Lifecycle Management",
            "title": "Data Retention & Deletion",
            "description": "Data retention and secure data deletion is performed in compliance with "
                           "applicable regulations.",
            "guidance": "Implement lifecycle policies in object storage; automate deletion of PII "
                        "after retention period; log all deletions.",
        },
        # ── GRC – Governance, Risk & Compliance ────────────────────────────────
        {
            "control_id": "GRC-01",
            "framework": "CSA CCM",
            "domain": "GRC – Governance, Risk & Compliance",
            "title": "GRC Governance Framework",
            "description": "Establish and maintain a governance framework to ensure accountability "
                           "for information and physical security, privacy, and compliance.",
            "guidance": "Stand up GRC program with defined roles; integrate with enterprise risk "
                        "management; report to board.",
        },
        {
            "control_id": "GRC-04",
            "framework": "CSA CCM",
            "domain": "GRC – Governance, Risk & Compliance",
            "title": "Risk Assessment",
            "description": "Perform at least annual risk assessments.",
            "guidance": "Use quantitative risk scoring; include cloud-specific risks (misconfiguration, "
                        "shared tenancy, API exposure).",
        },
        # ── IAM – Identity & Access Management ────────────────────────────────
        {
            "control_id": "IAM-01",
            "framework": "CSA CCM",
            "domain": "IAM – Identity & Access Management",
            "title": "Identity & Access Management Policy",
            "description": "Establish, document, and maintain an IAM policy and procedures.",
            "guidance": "Cover user lifecycle, MFA, least privilege, and session management for "
                        "cloud and SaaS environments.",
        },
        {
            "control_id": "IAM-09",
            "framework": "CSA CCM",
            "domain": "IAM – Identity & Access Management",
            "title": "User Access Provisioning",
            "description": "A user access provisioning process shall be implemented.",
            "guidance": "Integrate with HR system for joiner/mover/leaver; use SCIM provisioning; "
                        "automate deprovisioning on day of termination.",
        },
        # ── IVS – Infrastructure & Virtualisation ─────────────────────────────
        {
            "control_id": "IVS-03",
            "framework": "CSA CCM",
            "domain": "IVS – Infrastructure & Virtualisation Security",
            "title": "Network Security",
            "description": "Network environments shall be designed and configured to restrict and "
                           "monitor traffic.",
            "guidance": "Implement security groups, NACLs; enable micro-segmentation; use WAF for "
                        "web-facing workloads; enable VPC Flow Logs.",
        },
        {
            "control_id": "IVS-09",
            "framework": "CSA CCM",
            "domain": "IVS – Infrastructure & Virtualisation Security",
            "title": "Network Defence",
            "description": "A network defence strategy shall be implemented.",
            "guidance": "Deploy IDS/IPS at cloud perimeter; enable DDoS protection; integrate with "
                        "threat intelligence feeds.",
        },
        # ── SEF – Security Incident Management ────────────────────────────────
        {
            "control_id": "SEF-01",
            "framework": "CSA CCM",
            "domain": "SEF – Security Incident Management",
            "title": "Security Incident Response Policy",
            "description": "Establish, document, and communicate security incident response policies.",
            "guidance": "Define incident taxonomy; establish RACI; document evidence collection "
                        "procedures for cloud environments.",
        },
        {
            "control_id": "SEF-03",
            "framework": "CSA CCM",
            "domain": "SEF – Security Incident Management",
            "title": "Incident Reporting",
            "description": "Relevant personnel and external agencies shall be informed of security "
                           "incidents.",
            "guidance": "Define notification matrix (internal, regulator, customer); adhere to GDPR "
                        "72h breach notification requirement.",
        },
    ]
