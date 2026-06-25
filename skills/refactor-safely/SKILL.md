---
name: Refactor Safely
description: Plan refactorings, analyze downstream impact (blast radius), and run incremental verification.
---

## Triggers
- When the user asks to rename functions, classes, or module paths.
- When changing database structures in [postgres_db.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/postgres_db.py) or API responses in [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py).
- When modularizing large files (e.g., splitting [analysis_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/analysis_engine.py)).

## Step-by-Step Instructions
1. **Analyze Blast Radius**:
   - Query Graphify to find all files importing or calling the symbol you plan to modify:
     ```bash
     graphify affected "postgres_db.save_scan_results"
     ```
2. **Draft a Staged Refactor Plan**:
   - Design changes in backward-compatible stages (e.g., add new parameter as optional, migrate callers, make parameter required).
3. **Isolate edits**:
   - Perform edits using precise line replacements. Do not rewrite files from scratch.
4. **Incremental Testing**:
   - Run tests after each stage of modification using `./scripts/verify_all.sh`.

## Output Format
Your response must include:
- **Refactoring Strategy**: A detailed step-by-step list of modifications.
- **Blast Radius Report**: A markdown list of files/functions affected by this change.
- **Regression Risks**: Critical points where the system could break (e.g., database connection pooling, frontend key mismatches).
- **Verification Plan**: Exact commands to run to verify safety at each step.

## Anti-Patterns
- **Do NOT** change symbols without finding all callers first.
- **Do NOT** perform a wide-reaching refactor in a single monolithic edit.
- **Do NOT** commit changes without compiling and linting both the frontend and backend.

## Project-Specific Example
If refactoring [postgres_db.py:DatabaseManager](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/postgres_db.py):
1. Query Graphify: `graphify affected "DatabaseManager"`.
2. Note that [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py), [analysis_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/analysis_engine.py), and [celery_app.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/celery_app.py) all instantiate or depend on it.
3. Propose a staged edit starting with a deprecated decorator or safe-fallback methods.
