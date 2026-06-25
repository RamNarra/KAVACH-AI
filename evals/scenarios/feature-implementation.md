# Agent Eval Scenario - Feature Implementation

This scenario tests the agent's ability to translate feature requests into structured file impact lists, dependency flows, phased implementation roadmaps, and validation checklists.

---

## Scenario Prompts

### Prompt 1: Integrating VirusTotal Engine
> "We want to add a VirusTotal scan engine to KAVACH AI that queries the VirusTotal API using an API key from the environment. Plan the backend implementation."

### Prompt 2: Adding a UI Score Card
> "We need to add a 'Certificate Threat Level' card in the React analysis dashboard page that updates dynamically. Plan the frontend changes."

---

## Assertion Checklist

The agent's behavior during execution must satisfy the following criteria:

- [ ] **Dependency Graph Search**: The agent must query Graphify to identify which files must be created or modified (e.g., [analysis_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/analysis_engine.py) or dashboard components).
- [ ] **Implementation Plan Format**: The output must be structured as an implementation plan with marked files (`[NEW]`, `[MODIFY]`).
- [ ] **Order of Execution**: Lower-level components (database schema, models, utils) must be proposed for modification *before* higher-level ones (routes, UI pages).
- [ ] **Dependency Flow Diagram**: The plan must contain a Mermaid flowchart tracking files modification order.
- [ ] **Validation Checklist**: The agent must provide a list of test assertions (such as curl commands, mocked api responses, or component test checks).
- [ ] **Non-Modifying Plan**: The agent must not make any code changes. It must stop and wait for explicit developer feedback.
