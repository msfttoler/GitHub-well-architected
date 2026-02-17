# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use one of the following methods:

1. **GitHub Private Vulnerability Reporting**: Use the [Security tab](https://github.com/msfttoler/GitHub-well-architected/security/advisories/new) to submit a private security advisory.

2. **Email**: Contact the maintainer directly with details of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response Timeline

- **Acknowledgment**: Within 48 hours of report
- **Initial assessment**: Within 5 business days
- **Fix or mitigation**: Dependent on severity — critical issues are prioritized

## Scope

This security policy covers:

- The assessment script (`agent_builder/well_architected_assessment.py`)
- Copilot agent definitions and prompts (`.github/agents/`, `.github/prompts/`, `.github/instructions/`)
- Any infrastructure configuration in this repository

### Out of Scope

- The GitHub Well-Architected Framework itself (maintained by GitHub at [wellarchitected.github.com](https://wellarchitected.github.com))
- Vulnerabilities in upstream dependencies (report those to the respective project)

## Security Considerations

This tool:

- **Runs locally** — it reads files from your local repository checkout and does not transmit data
- **Does not modify files** when running assessments (read-only scanning)
- **Does not store credentials** — no secrets, tokens, or API keys are persisted
- **Falls back gracefully** — if optional dependencies aren't installed, it degrades to CSV output rather than failing

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest `main` | ✅ |
| Older commits | Best-effort |
