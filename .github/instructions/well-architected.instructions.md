---
description: "Use when writing CI/CD workflows, configuring branch protections, setting up security scanning, managing dependencies, or designing DevOps pipelines. Provides GitHub Well-Architected Framework guardrails."
applyTo: ".github/**"
---

# GitHub Well-Architected Framework Guidelines

When creating or modifying repository configuration, CI/CD workflows, or DevOps infrastructure, follow these principles from the GitHub Well-Architected Framework (https://wellarchitected.github.com).

## Security
- Enable Dependabot for automated dependency updates
- Configure code scanning with CodeQL for supported languages
- Enable secret scanning and push protection
- Use OIDC (`aws-actions/configure-aws-credentials`, `azure/login`) instead of long-lived secrets
- Define a `SECURITY.md` with vulnerability reporting instructions
- Enforce least-privilege: scope `GITHUB_TOKEN` permissions per-job with `permissions:`

## Reliability
- Require pull request reviews before merging to protected branches
- Enforce required status checks (CI must pass before merge)
- Use deployment environments with protection rules for production
- Include rollback steps or revert workflows
- Pin action versions to full SHA (not tags) for supply chain integrity

## Operational Excellence
- Use reusable workflows (`workflow_call`) to reduce duplication
- Automate releases with semantic versioning and changelog generation
- Maintain `CONTRIBUTING.md` and pull request templates
- Use GitHub Projects for work tracking
- Configure stale issue/PR automation

## Performance Efficiency
- Cache dependencies with `actions/cache` or language-specific caching
- Use `concurrency` groups to cancel redundant workflow runs
- Scope workflow triggers narrowly (`paths:`, `branches:`) to avoid unnecessary runs
- Use matrix strategies for parallel testing
- Monitor workflow run duration and optimize slow steps

## Collaboration
- Define `CODEOWNERS` for automatic review assignment
- Use pull request templates to standardize contributions
- Configure Copilot custom instructions for the project
- Enable GitHub Discussions for async communication
