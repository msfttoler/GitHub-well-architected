# GitHub Well-Architected Framework Assessment

A comprehensive tool for evaluating GitHub repositories and organizations against the [GitHub Well-Architected Framework](https://wellarchitected.github.com). Combines automated repository scanning with interactive organizational policy questions to produce detailed compliance reports in Markdown, HTML, and Excel formats.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## Overview

The Well-Architected Framework organizes best practices into five pillars:

| Pillar | What It Covers |
|--------|---------------|
| **Security** | Dependabot, CodeQL, secret scanning, OIDC, SECURITY.md, least-privilege tokens |
| **Reliability** | Branch protection, CI/CD, deployment environments, rollback strategies |
| **Operational Excellence** | CONTRIBUTING.md, PR templates, reusable workflows, release automation |
| **Performance Efficiency** | Dependency caching, concurrency groups, narrow triggers, matrix strategies |
| **Collaboration** | CODEOWNERS, Copilot instructions, issue templates, Discussions |

This tool checks **23 items automatically** by scanning your repo's files and workflows, then asks **16 interactive questions** about organizational policies that can't be detected from files alone (secret scanning, branch protection settings, SSO/MFA, etc.).

## Output

The assessment generates three report formats from a single run:

| Format | Description |
|--------|-------------|
| **Markdown** (`.md`) | Full compliance report with tables, priority actions, and gap analysis |
| **HTML** (`.html`) | Modern, self-contained dashboard with dark/light theme, animated gauges, and color-coded findings |
| **Excel** (`.xlsx`) | 8-sheet workbook with Summary, All Findings, Priority Actions, and per-pillar detail sheets |

Each report includes:
- Per-pillar scores (0–10) and overall score (0–50)
- COMPLIANT / PARTIAL / NON-COMPLIANT compliance ratings
- Severity levels (Critical, High, Medium, Low)
- Specific evidence and actionable recommendations
- Acceptable risk callouts and alternative approach notes
- Prioritized action items sorted by severity

## Quick Start

### Prerequisites

- Python 3.10 or later
- (Optional) `openpyxl` for Excel output — falls back to CSV if not installed

### Installation

```bash
# Clone the repository
git clone https://github.com/msfttoler/GitHub-well-architected.git
cd GitHub-well-architected

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Full interactive assessment (automated checks + org policy questions)
python agent_builder/well_architected_assessment.py

# Automated checks only (skip interactive questions)
python agent_builder/well_architected_assessment.py --no-interactive

# Assess a different repository
python agent_builder/well_architected_assessment.py --repo-path /path/to/repo

# Custom output location
python agent_builder/well_architected_assessment.py --output reports/my-report

# Skip specific output formats
python agent_builder/well_architected_assessment.py --no-html --no-excel
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--repo-path PATH` | Path to the repository to assess (default: current directory) |
| `--output PATH` | Base name for output files — extensions added automatically (default: `well-architected-report`) |
| `--no-interactive` | Skip interactive organizational policy questions |
| `--no-html` | Skip HTML dashboard generation |
| `--no-excel` | Skip Excel workbook generation |

## What Gets Checked

### Automated Repository Scans (23 checks)

| Pillar | Check | What It Looks For |
|--------|-------|-------------------|
| Security | Dependabot | `.github/dependabot.yml` with package ecosystems |
| Security | CodeQL / SAST | CodeQL action or alternative tools (Semgrep, SonarQube, Snyk, Checkmarx) |
| Security | SECURITY.md | Vulnerability disclosure policy |
| Security | Token permissions | `permissions:` blocks in workflows |
| Security | Action pinning | Full SHA pinning vs. tag references |
| Security | OIDC | OIDC auth vs. long-lived secrets for cloud deployments |
| Reliability | CI workflows | Test/lint workflows on `pull_request` |
| Reliability | Rollback strategy | Rollback/revert/canary patterns in deploy workflows |
| Reliability | Environments | GitHub Environment references with protection rules |
| Ops Excellence | CONTRIBUTING.md | Contributing guidelines |
| Ops Excellence | PR template | Pull request templates |
| Ops Excellence | Reusable workflows | `workflow_call` patterns |
| Ops Excellence | README quality | Sections for install, usage, badges, license, substance |
| Ops Excellence | Stale automation | `actions/stale` or Probot stale config |
| Ops Excellence | Release automation | semantic-release, release-please, changesets |
| Performance | Dependency caching | `actions/cache` or language-specific caching |
| Performance | Concurrency | `concurrency:` with `cancel-in-progress` |
| Performance | Narrow triggers | `paths:` and `branches:` filters |
| Performance | Matrix strategies | `strategy: matrix:` for parallel testing |
| Collaboration | CODEOWNERS | Ownership rules |
| Collaboration | Copilot instructions | `.github/copilot-instructions.md` or instructions directory |
| Collaboration | Issue templates | `.github/ISSUE_TEMPLATE/` |
| Collaboration | License | LICENSE file |

### Interactive Organizational Questions (16 questions)

These cover settings that can't be detected from files:

- Secret scanning and push protection (org-level)
- Private vulnerability reporting
- Branch protection / rulesets configuration
- Signed commits policy
- Required reviewer count
- SSO / MFA enforcement
- GHAS licensing
- Disaster recovery / backup strategy
- Work tracking tool (GitHub Projects, Jira, etc.)
- InnerSource practices
- CI/CD performance monitoring
- Runner configuration
- GitHub Discussions
- Branch naming conventions
- Onboarding automation

## Copilot Integration

This repository includes custom [GitHub Copilot agents and prompts](https://docs.github.com/en/copilot/customizing-copilot) for use in VS Code:

### Agents (`.github/agents/`)

| Agent | Purpose |
|-------|---------|
| **WellArchitected** | Read-only compliance auditor — scans repos against the framework and produces drift reports |
| **AgentBuilder** | Scaffolds new Copilot agents, instructions, prompts, and skills from natural language descriptions |

### Prompts (`.github/prompts/`)

| Prompt | Purpose |
|--------|---------|
| **compliance-check** | Run a quick full compliance audit on the current repo |
| **framework-updates** | Fetch and summarize latest framework changes |

### Instructions (`.github/instructions/`)

| File | Purpose |
|------|---------|
| **well-architected.instructions.md** | Auto-applied guardrails when editing `.github/**` files — ensures new workflows and configs follow the framework |

## Scoring

Each pillar is scored 0–10 based on the ratio of passing checks:

| Score | Compliance Level |
|------:|-----------------|
| 8–10 | **COMPLIANT** |
| 5–7.9 | **PARTIAL** |
| 0–4.9 | **NON-COMPLIANT** |

Findings use these statuses:

| Status | Meaning |
|--------|---------|
| ✅ PASS | Meets the framework recommendation |
| 🟡 PARTIAL | Partially implemented — needs improvement |
| ❌ FAIL | Not implemented — gap identified |
| ⚡ ACCEPTABLE RISK | Known gap with documented justification |
| ↔️ ALTERNATIVE | Using a different tool/approach that achieves the same goal |
| ➖ N/A | Not applicable to this repository |

## Project Structure

```
├── .github/
│   ├── agents/
│   │   ├── AgentBuilder.agent.md      # Agent scaffolding agent
│   │   └── WellArchitected.agent.md   # Compliance auditor agent
│   ├── instructions/
│   │   └── well-architected.instructions.md  # Auto-applied framework guardrails
│   └── prompts/
│       ├── compliance-check.prompt.md  # Quick audit prompt
│       └── framework-updates.prompt.md # Framework change tracker prompt
├── agent_builder/
│   └── well_architected_assessment.py  # Main assessment script
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, coding standards, and the pull request process.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Links

- [GitHub Well-Architected Framework](https://wellarchitected.github.com)
- [GitHub Advanced Security documentation](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
- [GitHub Actions security best practices](https://docs.github.com/en/actions/security-for-github-actions)