---
name: Bug Hunt
description: Trace and isolate runtime errors and logical bugs across KAVACH AI backend/frontend boundaries.
---

## Triggers
- When the user reports a runtime error, stack trace, or unexpected behavior.
- When an API endpoint fails, returns an incorrect status code (e.g., 500 Internal Server Error), or has broken payloads.
- When there is a mismatch between frontend React/Next.js inputs and backend FastAPI expected Pydantic models.

## Step-by-Step Instructions
1. **Isolate the Error Scope**:
   - Determine if the bug originates in the frontend (Next.js), the backend API layer ([routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py)), or the analysis engines.
   - Query Graphify to locate the files handling the affected components:
     ```bash
     graphify query "Which files handle the Pydantic models for scan uploads?"
     ```
2. **Retrieve Logs and Stack Traces**:
   - Inspect local log outputs like `backend.log` or `frontend.log` using target reading, matching lines of the error.
3. **Formulate a Minimal Reproduction Case**:
   - Write a python command, a curl request, or a test script to reproduce the bug.
4. **Inspect the Target Code**:
   - Read only the specific functions or lines identified. Do not read the entire file.
5. **Verify the Fix**:
   - Once a fix is devised, run the reproduction step to verify that it resolves the issue.

## Output Format
Your response must include:
- **Root Cause Analysis**: Detailed explanation of why the bug occurred, referencing exact line numbers.
- **Reproduction Steps**: A copy-pasteable script or curl command that triggers the bug.
- **Code Diff**: Proposed modifications represented in a clean markdown diff format.
- **Verification Result**: Output confirming the bug is resolved by the fix.

## Anti-Patterns
- **Do NOT** read multiple huge files to locate a variable definition; use Graphify or grep instead.
- **Do NOT** attempt a fix without writing down the reproduction steps first.
- **Do NOT** assume a frontend bug is purely frontend without checking the backend's response payload.

## Project-Specific Example
When debugging a `500 Server Error` on scan upload:
1. Locate the endpoint `/api/scan/upload` in [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py) using Graphify.
2. Formulate a `curl -X POST -F "file=@test.apk" http://localhost:8000/api/scan/upload` command.
3. Trace the error from `routes.py` to [analysis_engine.py:run_static_analysis](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/analysis_engine.py) using Graphify edges.
4. Apply the fix and verify with the curl command.
