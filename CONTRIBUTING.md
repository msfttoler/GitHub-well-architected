# Contributing to GitHub Well-Architected Assessment

Thank you for your interest in contributing! This guide covers everything you need to get started.

## Getting Started

### Prerequisites

- Python 3.10 or later
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/msfttoler/GitHub-well-architected.git
cd GitHub-well-architected

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Verify your setup

```bash
# Run the assessment in non-interactive mode
python agent_builder/well_architected_assessment.py --no-interactive
```

You should see the assessment run against this repository with colored terminal output and three generated report files.

## Project Structure

| Path | Purpose |
|------|---------|
| `agent_builder/well_architected_assessment.py` | Main assessment script — automated checks, interactive questions, and report generators |
| `.github/agents/` | Copilot custom agent definitions |
| `.github/instructions/` | Copilot auto-applied instructions |
| `.github/prompts/` | Copilot reusable prompts |
| `requirements.txt` | Python dependencies |

## How to Contribute

### Adding a New Automated Check

1. Add a method to the `RepoScanner` class following the existing pattern:
   ```python
   def check_your_check(self) -> Finding:
       """Describe what this checks."""
       # ... detection logic ...
       return Finding(
           pillar="Security",  # one of the 5 pillars
           principle="Descriptive principle name",
           status=Status.PASS,  # PASS, PARTIAL, FAIL, NOT_APPLICABLE, etc.
           severity=Severity.HIGH,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
           evidence="What was found",
           recommendation="What to do about it",
           acceptable_risk_note="",  # optional
           alternative_note="",  # optional
       )
   ```

2. Register it in `WellArchitectedAssessment.run_automated_checks()` under the appropriate pillar section.

3. Test it:
   ```bash
   python agent_builder/well_architected_assessment.py --no-interactive --no-html --no-excel
   ```

### Adding a New Interactive Question

Add an entry to the `ORG_QUESTIONS` list following the existing format:

```python
{
    "pillar": "Security",
    "principle": "Descriptive principle name",
    "severity": Severity.HIGH,
    "question": "Your question text?",
    "type": "choice",
    "options": ["Option 1", "Option 2", "Option 3"],
    "status_map": [Status.PASS, Status.PARTIAL, Status.FAIL],
    "recommendation": "What to do if non-compliant.",
    "acceptable_risk": "When it's OK to not meet this standard.",
    "alternative": "Alternative approaches that are also valid.",
}
```

### Modifying Copilot Agents / Prompts / Instructions

- **Agents** (`.github/agents/*.agent.md`): Follow the format defined in [AgentBuilder.agent.md](.github/agents/AgentBuilder.agent.md)
- **Instructions** (`.github/instructions/*.instructions.md`): Use YAML frontmatter with `description` and optional `applyTo` glob
- **Prompts** (`.github/prompts/*.prompt.md`): Use YAML frontmatter with `description`, optional `agent`, and `tools`

## Coding Standards

- **No external dependencies for core logic** — the assessment script uses only Python stdlib plus `openpyxl` (optional, for Excel output)
- **Graceful degradation** — if `openpyxl` isn't installed, fall back to CSV
- **Type hints** — use `from __future__ import annotations` and type all function signatures
- **Dataclasses** — use `@dataclass` for structured data (Finding, PillarScore)
- **Enums** — use `Enum` for fixed value sets (Status, Severity)

## Branching Strategy

- `main` — stable, production-ready code
- `feature/*` — new features and checks
- `bugfix/*` — bug fixes
- `docs/*` — documentation-only changes

## Pull Request Process

1. **Create a branch** from `main` using the naming convention above
2. **Make your changes** with clear, focused commits
3. **Test locally** — run the assessment and verify all three output formats generate correctly
4. **Open a pull request** with:
   - A clear description of what changed and why
   - Which pillar(s) and check(s) are affected
   - Screenshots of the HTML dashboard if UI changes were made
5. **Request a review** — at least one approval is required before merge

## Reporting Issues

Open a [GitHub Issue](https://github.com/msfttoler/GitHub-well-architected/issues) with:

- **Bug reports**: Steps to reproduce, expected vs. actual behavior, Python version, OS
- **Feature requests**: Which pillar it relates to, what gap it addresses, example implementation if possible
- **Framework updates**: If the Well-Architected Framework adds new guidance, open an issue so we can add corresponding checks

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
