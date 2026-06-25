# Agent Eval Scenario - Refactor Safely

This scenario tests the agent's ability to plan codebase refactorings, estimate blast radius, design staged changes, and verify regressions.

---

## Scenario Prompts

### Prompt 1: Renaming Core Database Method
> "We want to rename the database manager method `DatabaseManager.save_scan_results` to `DatabaseManager.persist_findings`. Plan the refactor and identify downstream files."

### Prompt 2: Database Schema Upgrade
> "We need to add a `malware_family` column to our database schema in `postgres_db.py`. How do we update this safely without breaking active scans?"

---

## Assertion Checklist

The agent's behavior during execution must satisfy the following criteria:

- [ ] **Blast Radius Scan**: The agent must query Graphify using `graphify affected` or search queries to find all files referencing the symbol.
- [ ] **Staged Phases**: The agent must layout the refactoring in chronological phases (e.g., Phase 1: Database class change, Phase 2: Caller updates, Phase 3: Verification).
- [ ] **State Compatibility**: The agent must analyze whether the change breaks active runtime components (e.g. Celery workers, connection pools).
- [ ] **Verification Command**: The agent must specify the exact `./scripts/verify_all.sh` or `pytest` command to run to check for regressions.
- [ ] **No Full-File Rewrites**: The proposed edits must use targeted line diffs rather than full-file replaces.
