---
name: Agent Memory
description: Capture, update, and consult persistent project learnings, design decisions, and system quirks.
---

## Triggers
- When resolving a complex configuration issue or environment quirk.
- When making an architectural design decision (e.g., choosing JWT over session cookies, choosing PostgreSQL over SQLite).
- When a coding error is fixed that was caused by a subtle codebase quirk.
- At the start of a session, to review previously recorded facts.

## Step-by-Step Instructions
1. **Locate or Initialize Memory**:
   - Check if there is an `AGENTS.md` or a `graphify-out/reflections/LESSONS.md` in the project.
   - If not, check if `skills/agent-memory/scratch/learnings.md` exists or create it.
2. **Review Memory**:
   - Read the existing facts before starting a complex task.
3. **Capture New Knowledge**:
   - When a solution is implemented, extract the core "fact" or "lesson" (e.g., "The MobSF bridge requires the `MOBSF_URL` env variable to end with `/api/v1/`").
4. **Append or Update**:
   - Record the fact in a structured format: `Date`, `Context`, `Fact/Quirk`, `Impact`.
5. **Feed Graphify Memory**:
   - Run `graphify save-result` to persist QA outcomes and feed them into Graphify reflections.

## Output Format
Your response must include:
- **Learnings Card**: A block containing:
  - **Decisions Made**: Architectural choices.
  - **Quirks & Gotchas**: Subtle errors to avoid.
  - **Impact**: How this affects coding or operation.

## Anti-Patterns
- **Do NOT** re-learn how to run the project. Check the memory file first.
- **Do NOT** write generic advice. Keep findings highly specific to KAVACH AI.
- **Do NOT** forget to update the memory file after fixing a complex environment bug.

## Project-Specific Example
When setting up MobSF bridge connection:
1. Note that MobSF bridge relies on docker container names.
2. Update the local project memory to state: "MobSF bridge runs on port 8000 internally but maps to 8081 on host. When running tests inside the docker sandbox, use `http://mobsf:8000` rather than `localhost:8081`."
3. Save this lesson to avoid resolving container name errors again.
