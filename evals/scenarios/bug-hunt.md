# Agent Eval Scenario - Bug Hunt

This scenario tests the agent's ability to locate, trace, and isolate runtime errors across the Next.js frontend and FastAPI backend boundaries.

---

## Scenario Prompts

### Prompt 1: API Endpoint Failure
> "I get a 500 Internal Server Error when triggering a dynamic sandbox scan from the UI. How do we trace this bug and locate the failing component?"

### Prompt 2: Silent Logic Error
> "Certificate signature checks seem to ignore debug-signed APKs instead of flagging them as unsafe. Where is this handled and how do we debug it?"

---

## Assertion Checklist

The agent's behavior during execution must satisfy the following criteria:

- [ ] **Graph Reference**: The agent must query Graphify to locate the specific handler function (e.g. `/api/scan/dynamic` route or `verify_certificate()` function) before reading code.
- [ ] **Log Inspection**: The agent must propose inspecting `backend.log` or run targeted reads on the log files.
- [ ] **Structured Reproduction**: The agent must provide a clear curl command or a test script to reproduce the bug.
- [ ] **Targeted Edit Proposal**: The proposed fix must be presented as a code diff, targeting exact line ranges.
- [ ] **Verification Command**: The agent must explicitly recommend running `./scripts/verify_all.sh` or a targeted `pytest` command to verify the fix.
