---
name: Security Review
description: Audit risky code paths, subprocesses, authentication boundaries, and environment configurations.
---

## Triggers
- When the user asks for a code review or security audit of backend/frontend files.
- When creating or modifying functions that invoke subprocesses, external tools, or shell commands.
- When handling credentials, tokens, or JWT validation in [auth.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/auth.py).
- When modifying sandboxed execution boundaries in [code_interpreter.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/code_interpreter.py) or sandbox runners.

## Step-by-Step Instructions
1. **Identify Risky Functions**:
   - Query Graphify or run grep to find command execution, dynamic SQL, or eval calls:
     ```bash
     graphify query "Where is subprocess used in the backend?"
     ```
2. **Audit Input Validation**:
   - Trace inputs from route payloads down to execution sinks to ensure they are strictly sanitized or validated using Pydantic.
3. **Verify Auth Checks**:
   - Ensure routes in [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py) utilize the dependency injection authentication guards defined in [auth.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/auth.py).
4. **Scan for Hardcoded Secrets**:
   - Verify that all api keys, postgres passwords, and secret tokens are loaded via `os.getenv` and NOT committed to git.

## Output Format
Your response must include:
- **Security Assessment Summary**: A high-level overview of the component's security posture.
- **Risk Findings Table**:
  | Location | Hazard Level | Description | Recommended Remediation |
  | :--- | :--- | :--- | :--- |
  | `androguard_analyzer.py:L142` | High | Unsanitized string in subprocess call | Use list-based args |
- **Secure Code Remediation**: Before/after code blocks demonstrating the fix.

## Anti-Patterns
- **Do NOT** use `shell=True` in subprocess calls. Always pass arguments as a list.
- **Do NOT** allow raw SQL string concatenation. Use parameterized SQLAlchemy models.
- **Do NOT** store secrets in code. Use `.env` and load them via environment variables.

## Project-Specific Example
Auditing [code_interpreter.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/code_interpreter.py):
1. Note that it executes arbitrary Python code for agent tool calls.
2. Review the sandbox constraints (e.g. Docker container limits, memory caps, network disabling).
3. Ensure no local resources are exposed to the code interpreter sandbox.
4. Report finding on how sandbox isolation is maintained.
