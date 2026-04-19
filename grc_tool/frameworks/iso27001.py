"""
ISO/IEC 27001:2022 – Annex A control catalogue (selected key controls).
"""

from __future__ import annotations


def get_controls() -> list[dict]:
    return [
        # ── 5 Organisational Controls ─────────────────────────────────────────
        {
            "control_id": "ISO-5.1",
            "framework": "ISO 27001",
            "domain": "5 – Organisational Controls",
            "title": "Policies for Information Security",
            "description": "Information security policies shall be defined, approved by management, "
                           "published, communicated to and acknowledged by employees and relevant "
                           "external parties.",
            "guidance": "Develop an information security policy framework. Review annually or after "
                        "significant changes.",
        },
        {
            "control_id": "ISO-5.2",
            "framework": "ISO 27001",
            "domain": "5 – Organisational Controls",
            "title": "Information Security Roles and Responsibilities",
            "description": "Information security roles and responsibilities shall be defined and "
                           "allocated according to organisation needs.",
            "guidance": "Document roles: CISO, Data Protection Officer, system owners. Publish in "
                        "the information security policy.",
        },
        {
            "control_id": "ISO-5.7",
            "framework": "ISO 27001",
            "domain": "5 – Organisational Controls",
            "title": "Threat Intelligence",
            "description": "Information relating to information security threats shall be collected "
                           "and analysed to produce threat intelligence.",
            "guidance": "Subscribe to industry threat feeds (ISAC, CISA). Feed intelligence into "
                        "risk assessment process.",
        },
        {
            "control_id": "ISO-5.23",
            "framework": "ISO 27001",
            "domain": "5 – Organisational Controls",
            "title": "Information Security for Cloud Services",
            "description": "Processes for acquisition, use, management, and exit from cloud services "
                           "shall be established.",
            "guidance": "Maintain a cloud service inventory; assess CSP shared responsibility; "
                        "negotiate security SLAs.",
        },
        {
            "control_id": "ISO-5.30",
            "framework": "ISO 27001",
            "domain": "5 – Organisational Controls",
            "title": "ICT Readiness for Business Continuity",
            "description": "ICT readiness shall be planned, implemented, maintained, and tested "
                           "based on business continuity objectives.",
            "guidance": "Define RTO/RPO; test DR plans; document failover procedures.",
        },
        # ── 6 People Controls ─────────────────────────────────────────────────
        {
            "control_id": "ISO-6.3",
            "framework": "ISO 27001",
            "domain": "6 – People Controls",
            "title": "Information Security Awareness Training",
            "description": "Personnel and relevant interested parties shall receive awareness "
                           "education and training and regular updates on the organisation's "
                           "information security policy, topic-specific policies and relevant "
                           "procedures.",
            "guidance": "Deliver role-based security training annually; test with phishing simulations.",
        },
        # ── 7 Physical Controls ───────────────────────────────────────────────
        {
            "control_id": "ISO-7.4",
            "framework": "ISO 27001",
            "domain": "7 – Physical Controls",
            "title": "Physical Security Monitoring",
            "description": "Premises shall be continuously monitored for unauthorised physical access.",
            "guidance": "Deploy CCTV; implement access control logs; review anomalies monthly.",
        },
        # ── 8 Technological Controls ──────────────────────────────────────────
        {
            "control_id": "ISO-8.2",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Privileged Access Rights",
            "description": "Allocation and use of privileged access rights shall be restricted "
                           "and managed.",
            "guidance": "Implement PAM solution; review privileged accounts quarterly; enforce JIT access.",
        },
        {
            "control_id": "ISO-8.5",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Secure Authentication",
            "description": "Secure authentication technology and procedures shall be implemented "
                           "based on information access restrictions and the topic-specific policy "
                           "on access control.",
            "guidance": "Enforce MFA; ban weak passwords; integrate with SSO/IdP; monitor failed logins.",
        },
        {
            "control_id": "ISO-8.7",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Protection Against Malware",
            "description": "Protection against malware shall be implemented and supported by "
                           "appropriate user awareness.",
            "guidance": "Deploy EDR; enable anti-malware on all endpoints; keep signatures updated.",
        },
        {
            "control_id": "ISO-8.8",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Management of Technical Vulnerabilities",
            "description": "Information about technical vulnerabilities of information systems "
                           "in use shall be obtained in a timely fashion.",
            "guidance": "Run weekly vulnerability scans; patch critical CVEs within 72h; track via "
                        "vulnerability management platform.",
        },
        {
            "control_id": "ISO-8.15",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Logging",
            "description": "Logs that record user activities, exceptions, faults and other "
                           "security-relevant events shall be produced, stored, protected and analysed.",
            "guidance": "Centralise logs in SIEM; retain for 12+ months; enable tamper protection.",
        },
        {
            "control_id": "ISO-8.24",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Use of Cryptography",
            "description": "Rules for the effective use of cryptography, including cryptographic "
                           "key management, shall be defined and implemented.",
            "guidance": "Document cryptographic standards (algorithms, key lengths); manage keys via "
                        "KMS; rotate keys annually.",
        },
        {
            "control_id": "ISO-8.25",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Secure Development Lifecycle",
            "description": "Rules for the secure development of software and systems shall be "
                           "established and applied.",
            "guidance": "Implement SAST/DAST in CI/CD; conduct code reviews; follow OWASP SDLC.",
        },
        {
            "control_id": "ISO-8.28",
            "framework": "ISO 27001",
            "domain": "8 – Technological Controls",
            "title": "Secure Coding",
            "description": "Secure coding principles shall be applied to software development.",
            "guidance": "Enforce secure coding standards (OWASP Top 10, CWE/SANS); use linters and "
                        "dependency scanners.",
        },
    ]
