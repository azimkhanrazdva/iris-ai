# IRIS Alert AI

IRIS Alert AI is a small DFIR-IRIS worker for turning security alerts into
actionable cases. It polls alerts, asks a local model for structured triage,
correlates related alerts, and creates or updates IRIS cases with analyst-ready
summaries.

This public package contains only reusable source code and synthetic tests. It
does not include live configuration, state databases, logs, inspection dumps,
deployment backups, passwords, tokens, or private infrastructure details.

## What It Does

- Polls DFIR-IRIS alerts from the configured alert source.
- Sends a compact, redacted alert context to a local model endpoint.
- Produces structured severity, summary, entities, scenario, and recommended
  actions.
- Detects duplicate alerts with stable fingerprints.
- Correlates related alerts into the same case when evidence supports it.
- Keeps ambiguous alerts separate instead of merging them automatically.
- Updates case summaries and can trigger IRIS investigation report generation.

## Files

- `iris_alert_ai.py` - alert polling, model call, case create/merge workflow.
- `attack_correlation.py` - deterministic evidence checks and case relation logic.
- `reports_route.py` - optional DFIR-IRIS report route patch reference.
- `test_correlation.py` - synthetic regression tests for duplicate handling,
  correlation, ambiguity, and failure recovery.
- `inspection-alerts.json` - synthetic fixture used by tests.
- `.env.example` - example runtime configuration.

## Configuration

Copy `.env.example` to `config.env` and fill in local values:

```bash
cp .env.example config.env
