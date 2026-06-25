# Tooling Audit - KAVACH AI

This document provides a focused audit of the toolchains, dependencies, and CI configurations in the KAVACH AI repository, proposing safe upgrade paths that avoid breaking changes.

---

## 1. Node / Frontend

*   **Node.js Constraints**: No explicit Node version constraints are configured in `frontend/package.json` ("engines") or `.nvmrc`. The local development environment runs on Node `v22.23.0`.
*   **Active Versions**:
    *   **React**: `^19.2.7` (Current Active Version)
    *   **Next.js**: `16.2.9` (Current Active Version)
    *   **TypeScript**: `^6`
    *   **ESLint**: `^9.39.4`
*   **Outdated Packages**:
    *   `eslint` (Current: `9.39.4` | Latest: `10.5.0`)
    *   `@mui/x-data-grid` (Current: `9.6.0` | Latest: `9.7.0`)
    *   `framer-motion` (Current: `12.41.0` | Latest: `12.42.0`)
*   **Minimal Upgrade Plan**:
    *   *Upgrade now*: Align Next.js Node compilation runner on Node 24 in GitHub Actions to stop deprecation warnings.
    *   *Defer*: Do not upgrade ESLint to v10 yet, as it introduces breaking changes in flat configuration structures. Keep React and Next.js at their current pinned versions to prevent UI layout regressions.

---

## 2. Python / Backend

*   **Python Constraints**: Targets Python `3.11+` in the root `Dockerfile` and `3.12` in CI workflows.
*   **Active Versions**:
    *   **FastAPI**: `0.138.0`
    *   **Pydantic**: `^2.7.0`
    *   **Pytest**: `^8.0.0`
*   **Outdated Packages**:
    *   `androguard` (Current: `3.4.0a1` | Latest: `4.1.4`)
    *   `websockets` (Current: `13.1` | Latest: `16.0`)
    *   `mcp` (Current: `1.23.3` | Latest: `1.28.0`)
    *   `fastapi` (Current: `0.138.0` | Latest: `0.138.1`)
*   **Minimal Upgrade Plan**:
    *   *Upgrade now*: Keep dependencies locked in `requirements.txt` to guarantee compilation safety of native packages (YARA, Frida, Scikit-Learn) during CI builds.
    *   *Defer*: Do not upgrade `androguard` to `4.x` as it introduces breaking API changes in APK parsing classes used by `androguard_analyzer.py`.

---

## 3. CI & Actions

*   **CI Configuration**: All official GitHub Actions are pinned to current versions:
    *   `actions/checkout@v4`
    *   `actions/setup-node@v4`
    *   `actions/setup-python@v5`
    *   `actions/setup-java@v4`
    *   `actions/cache@v4`
*   **Node 20 Deprecation Warnings**: Resolved by opting actions in to Node 24 via the `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workflow environment flag.

---

## 4. Recommended Upgrades Now

1.  **Lowercased Docker Repository Tags**: Replaced `ghcr.io/RamNarra/` with a lowercase owner variable `ghcr.io/ramnarra/` to fix the blocked GitHub Package publishing error.
2.  **Next.js Actions Node upgrade**: Upgraded Node.js runtime for build steps in `ci-main.yml` and `ci-pr.yml` from Node 20 to Node 24.
3.  **Opt-in Node 24 flag**: Added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true` at the job/workflow level for all workflows.

---

## 5. Upgrades to Consider Later

1.  **Node Versioning**: Add a `.nvmrc` file in the root containing `24` to lock developer workstations.
2.  **Next.js Patch Upgrades**: Upgrade minor versions of Next.js and `@mui/x-data-grid` after verifying layout compatibility.
