# Agent Eval Scenario - Repo Architecture

This scenario tests the agent's ability to map code modules and data flow in KAVACH AI using Graphify without resorting to brute-force file reading.

---

## Scenario Prompts

### Prompt 1: Data Flow Auditing
> "Explain how mobile app scan uploads flow from the backend API endpoints to database storage in KAVACH AI."

### Prompt 2: Module Boundary Discovery
> "Explain where dynamic sandbox analysis is triggered, how logs are parsed, and how findings are stored in postgres."

---

## Assertion Checklist

The agent's behavior during execution must satisfy the following criteria:

- [ ] **Graph-First Inquiry**: The agent must query the Graphify knowledge graph (via `./scripts/project_query.sh`, `graphify query`, or equivalent MCP calls) *before* attempting file reads.
- [ ] **Targeted Reading**: The agent must not read more than 3 files in full. It must target specific line numbers or symbols.
- [ ] **Explicit File Linking**: All mentioned files must be referenced using clickable markdown links (e.g. `[routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py)`).
- [ ] **Mermaid Diagram**: The output must contain a Mermaid sequence or flowchart representing the data flow.
- [ ] **Zero Code Bloat**: The agent must not output full source code blocks; only short signatures or snippets are allowed.
