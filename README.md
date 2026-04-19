# 🛡 GRC Tool — Cloud & AI Governance, Risk & Compliance Platform

A **professional, open-source GRC platform** built entirely with standard Python libraries
(SQLite3, argparse, csv, json) plus optional `rich` for beautiful terminal output and
**Ollama** for local-LLM AI advisory — **no OpenAI API key required**.

Designed for practitioners working in **Cloud Security** and **AI Governance**.

---

## ✨ Features

| Area | Capability |
|------|------------|
| 🔴 **Risk Management** | Full risk register with likelihood/impact scoring, CVSS-style levels (Critical/High/Medium/Low), treatment tracking, filtering |
| ✅ **Control Management** | Import 90+ controls from 5 frameworks; track implementation status; compliance scores |
| 📋 **Policy Management** | 4 built-in policy templates; version control; approval workflow |
| 📊 **Compliance Assessments** | Auto-score assessments from control statuses; gap analysis; findings |
| 🤖 **AI Advisor** | Ollama (local LLM) integration for risk analysis, control guidance, policy review, executive summaries |
| 📄 **Reports** | Export to HTML (styled dashboard), JSON, and CSV |
| 🔍 **Audit Log** | Full audit trail of all create/update/delete operations |

### Supported Compliance Frameworks

| Framework | Controls |
|-----------|----------|
| **NIST CSF 2.0** | Govern, Identify, Protect, Detect, Respond, Recover (24 controls) |
| **NIST AI RMF 1.0** | GOVERN, MAP, MEASURE, MANAGE (18 controls) |
| **ISO/IEC 27001:2022** | Organisational, People, Physical, Technological Controls (15 controls) |
| **SOC 2 (TSC)** | CC, Availability, Confidentiality criteria (14 controls) |
| **CSA CCM v4** | AIS, BCR, CEK, DSP, GRC, IAM, IVS, SEF domains (19 controls) |

---

## 🚀 Quick Start

### 1. Install

```bash
# Clone the repo
git clone https://github.com/Yaso-cyber/GRC-.git
cd GRC-

# Install dependencies (only `rich` for terminal formatting)
pip install -r requirements.txt

# Or install as a package (makes `grc` available as a command)
pip install -e .
```

### 2. Bootstrap your GRC programme

```bash
# Import all framework controls (90+ controls from 5 frameworks)
grc control import --framework all

# Create policies from built-in templates
grc policy create --template "Cloud Security Policy"
grc policy create --template "AI Governance Policy"

# Add your first risk
grc risk add

# View the dashboard
grc dashboard
```

### 3. Enable AI Advisory (Optional)

```bash
# Install Ollama: https://ollama.com
ollama serve          # in one terminal
ollama pull llama3    # pull a model (llama3, mistral, gemma2, etc.)

# Check status
grc ai status

# Ask the AI advisor
grc ai ask "How should I secure S3 buckets in a multi-account AWS environment?" --mode cloud
grc ai ask "What controls do I need for EU AI Act compliance?" --mode ai-governance
```

---

## 📖 CLI Reference

### Dashboard
```bash
grc dashboard
```

### Risk Management
```bash
grc risk list
grc risk list --status Open --level Critical
grc risk add
grc risk view 3
grc risk update 3 --status "In Progress" --owner "alice"
grc risk update 3 --likelihood 2 --impact 3
grc risk delete 3
grc risk ai 3      # AI analysis (requires Ollama)
```

**Risk Levels** (Likelihood × Impact):

| Score | Level |
|-------|-------|
| 20–25 | 🔴 Critical |
| 12–19 | 🟠 High |
| 6–11  | 🟡 Medium |
| 1–5   | 🟢 Low |

### Control Management
```bash
grc control import --framework all
grc control import --framework "NIST AI RMF"
grc control list --framework "NIST CSF" --status "Not Implemented"
grc control update ID.AM-01 --status "Implemented" --owner "IT Ops" --evidence "cmdb.csv"
grc control update CC6.1 --status "Partially Implemented"
grc control score
```

**Control Statuses:** `Not Implemented` → `Planned` → `Partially Implemented` → `Implemented` | `Not Applicable`

### Policy Management
```bash
grc policy list
grc policy templates
grc policy create --template "Cloud Security Policy"
grc policy create --template "AI Governance Policy"
grc policy create --template "Data Classification Policy"
grc policy create --template "Incident Response Policy"
grc policy view POL-001
grc policy approve POL-001 --approver "CISO"
```

### Compliance Assessments
```bash
grc assess create --framework "NIST CSF"
grc assess create --framework "NIST AI RMF"
grc assess list
```

### Reports
```bash
grc report --format html --output grc_report_q1
grc report --format json --output grc_data
grc report --format csv --output grc_export
```

### AI Advisor (Ollama)
```bash
grc ai status
grc ai ask "IAM least-privilege in AWS" --mode cloud
grc ai ask "How to detect bias in an ML model" --mode ai-governance
grc ai exec-summary
```

### Audit Log
```bash
grc audit
grc audit --limit 100
```

---

## 🗂 Project Structure

```
grc_tool/
├── __init__.py
├── database.py           # SQLite3 persistence layer
├── models.py             # Risk, Control, Policy, Assessment dataclasses
├── risk_manager.py       # Risk CRUD + analytics
├── control_manager.py    # Control CRUD + framework import + compliance scoring
├── policy_manager.py     # Policy CRUD + templates
├── assessment_manager.py # Compliance assessment engine
├── ai_advisor.py         # Ollama LLM integration
├── report_generator.py   # HTML / JSON / CSV report generation
├── cli.py                # Rich CLI interface
└── frameworks/
    ├── __init__.py       # Framework registry
    ├── nist_csf.py       # NIST Cybersecurity Framework 2.0
    ├── nist_ai_rmf.py    # NIST AI Risk Management Framework 1.0
    ├── iso27001.py       # ISO/IEC 27001:2022
    ├── soc2.py           # SOC 2 Trust Service Criteria
    └── csa_ccm.py        # CSA Cloud Controls Matrix v4
tests/
└── test_grc_tool.py      # 63 unit + integration tests
main.py
requirements.txt
pyproject.toml
```

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (rich)                           │
│              grc <command> [subcommand] [options]            │
└──────────┬──────────┬──────────┬──────────┬─────────────────┘
           │          │          │          │
    ┌──────▼──┐ ┌────▼────┐ ┌──▼──────┐ ┌─▼──────────┐
    │  Risk   │ │ Control │ │ Policy  │ │ Assessment │
    │ Manager │ │ Manager │ │ Manager │ │  Manager   │
    └──────┬──┘ └────┬────┘ └──┬──────┘ └─────┬──────┘
           └─────────┴─────────┴──────────────┘
                              │
                    ┌─────────▼─────────┐
                    │    Database        │
                    │  (SQLite3 / WAL)   │
                    └─────────┬─────────┘
                              │
              ┌───────────────┴──────────────┐
              │                              │
    ┌─────────▼─────────┐        ┌──────────▼──────────┐
    │  Report Generator │        │    AI Advisor        │
    │  HTML / JSON / CSV│        │  (Ollama local LLM)  │
    └───────────────────┘        └─────────────────────┘
```

---

## 📊 Database

- Default path: `~/.grc_tool/grc.db`
- Override: `export GRC_DB_PATH=/path/to/db`
- Per-command: `grc --db /path/to/db dashboard`

Tables: `risks`, `controls`, `risk_controls`, `assessments`, `policies`, `audit_log`

---

## 🤖 AI Advisory

Connects to a locally running [Ollama](https://ollama.com) instance.
No internet or API key needed.

| Advisory Method | Description |
|-----------------|-------------|
| Risk analysis | Analysis + top 3 mitigations + control mappings |
| Control guidance | Step-by-step implementation with evidence artefacts |
| Policy review | Strengths, gaps, improvement recommendations |
| Treatment plans | Actions, owners, timelines, KRIs |
| Cloud security | AWS/Azure/GCP best practices |
| AI governance | NIST AI RMF, EU AI Act guidance |
| Executive summary | Board-level GRC narrative |

Recommended models: `llama3`, `mistral`, `gemma2`, `phi3`

---

## 🧪 Tests

```bash
pip install pytest
pytest tests/ -v     # 63 tests
```

---

## 🗺 Roadmap

- [ ] Web UI (Flask/FastAPI)
- [ ] OSCAL export
- [ ] Cloud scanner integrations (Prowler, ScoutSuite)
- [ ] Custom framework definitions (YAML)
- [ ] Evidence file attachments
- [ ] Multi-user / RBAC

---

## 📄 License

MIT — free to use, modify, and distribute.

---

*Built for Cloud Security and AI Governance professionals.*  
*No OpenAI key. No vendor lock-in. Your data stays local.*
