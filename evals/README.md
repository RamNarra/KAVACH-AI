# KAVACH AI - Agent Evals Harness

This evaluation harness provides a lightweight framework to ensure that AI agents (such as Antigravity running Gemini 3.5 Flash) maintain workflow discipline and comply with repository rules.

Evaluating agent capabilities ensures that model changes do not cause regressions in **token efficiency**, **source code safety**, and **verification quality**.

---

## Evaluation Procedure

Evals are scenario-based and map to the four core skills:
1.  **Repo Architecture** ([evals/scenarios/repo-architecture.md](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/evals/scenarios/repo-architecture.md))
2.  **Bug Hunt** ([evals/scenarios/bug-hunt.md](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/evals/scenarios/bug-hunt.md))
3.  **Refactor Safely** ([evals/scenarios/refactor-safely.md](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/evals/scenarios/refactor-safely.md))
4.  **Feature Implementation** ([evals/scenarios/feature-implementation.md](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/evals/scenarios/feature-implementation.md))

### Run Steps
1.  **Select Scenario**: Choose one of the scenario files in `evals/scenarios/`.
2.  **Execute Prompt**: Start a new chat session and paste one of the "Canned Prompts" exactly.
3.  **Audit the Response**: Check the agent's response against the **Assertion Checklist** (e.g. did it run a graph query first? Did it suggest pytest verification?).
4.  **Score**: Calculate the success rate (Assertions Met / Total Assertions).
5.  **Record Results**: Add a log entry in `evals/results_log.md` (date, model name, skill evaluated, score, regression notes).

---

## Assertions & Scoring Guide

Each scenario specifies binary properties (assertions) that the agent output must satisfy:

| Assertions Met | Status | Action Required |
| :--- | :--- | :--- |
| **100%** | **EXCELLENT** | No action. Agent is fully aligned. |
| **75% - 99%** | **PASS** | Minor deviations; remind agent of missed rules. |
| **< 75%** | **FAIL** | Serious regression. Audit system rules or update local skill prompts. |
