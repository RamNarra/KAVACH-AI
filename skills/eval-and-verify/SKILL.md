---
name: Eval & Verify
description: Execute verification tests, linters, and build audits, summarizing results cleanly.
---

## Triggers
- After making any code changes in the backend or frontend.
- When the user asks to run the test suite or verify the build.
- Before completing a task to ensure no regressions are introduced.

## Step-by-Step Instructions
1. **Trigger Consolidated Verification**:
   - Run the custom verification script:
     ```bash
     ./scripts/verify_all.sh
     ```
2. **Targeted Verification (Optional)**:
   - For backend only: Run `pytest backend/test_intelligence.py` or `pytest backend/test_certificate_forensics.py`.
   - For frontend only: Run `npm run lint` and `npm run build` inside the `frontend/` directory.
3. **Parse and Filter Output**:
   - Do not dump hundreds of lines of build noise. Extract warnings, failures, and coverage stats.
4. **Determine Pass/Fail Status**:
   - A single failed unit test or lint error constitutes a overall FAIL.

## Output Format
Your response must include:
- **Verification Status**: A big, bold **PASS** or **FAIL** indicator.
- **Summary Table**:
  | Component | Action | Status | Key Logs / Details |
  | :--- | :--- | :--- | :--- |
  | Backend | Pytest | PASS/FAIL | 12 tests passed |
  | Backend | Linting | PASS/FAIL | No errors |
  | Frontend | Next.js Build | PASS/FAIL | Compiled successfully |
- **Failure Details**: If failed, paste the exact failing lines and stack trace, and link to the file.

## Anti-Patterns
- **Do NOT** assume code works just because "it looks correct." Always run the tests.
- **Do NOT** dump the raw console log of `npm run build` if it is successful. Only show the summary.
- **Do NOT** ignore linting errors, as they often hide type mismatches and runtime issues.

## Project-Specific Example
After updating database models in [postgres_db.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/postgres_db.py):
1. Run `./scripts/verify_all.sh`.
2. Pytest passes. Frontend build passes.
3. Output the summary table indicating overall PASS.
