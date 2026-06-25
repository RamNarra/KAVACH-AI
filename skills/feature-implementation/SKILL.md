---
name: Feature Implementation
description: Translate a feature request into affected files, dependency graphs, implementation plans, and checklists.
---

## Triggers
- When the user requests a new feature, endpoint, or page.
- When expanding existing capabilities (e.g., adding dynamic hook injection into Frida analysis).
- When integrating a new external API or third-party service.

## Step-by-Step Instructions
1. **Analyze the Request**:
   - Deconstruct the goal into frontend, backend, database, and operational components.
2. **Identify Target Files**:
   - Query Graphify to find files that must be created or modified, and their dependency trees:
     ```bash
     graphify query "Where are backend routes registered and how does postgres_db connect?"
     ```
3. **Build the Dependency Graph**:
   - Map out the order of changes (e.g., database schema changes first, backend routes second, frontend components last).
4. **Draft the Implementation Plan**:
   - Detail the modifications required for each file.
5. **Establish Verification Criteria**:
   - Outline automated tests and manual visual checks.

## Output Format
Your response must include:
- **Impacted Files**: A markdown list of files to create (`[NEW]`) or modify (`[MODIFY]`) with links.
- **Dependency Flow**: A Mermaid diagram representing the flow of changes.
- **Implementation Sequence**: Staged steps describing what to edit in each file.
- **Validation Checklist**: A checklist of tests to run (e.g., specific endpoints to hit, UI elements to click).

## Anti-Patterns
- **Do NOT** start writing code before detailing the plan and obtaining approval.
- **Do NOT** modify multiple layers (e.g. frontend and backend) simultaneously without verifying each step.
- **Do NOT** skip defining the exact curl commands or tests that verify the new feature.

## Project-Specific Example
When adding a "Vulnerability Scanner" feature:
1. Locate [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py) and [analysis_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/analysis_engine.py) via Graphify.
2. Plan the backend router entry point: `POST /api/scan/vulnerabilities`.
3. Plan the database storage for results in [postgres_db.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/postgres_db.py).
4. Plan the frontend React component displaying these vulnerabilities.
5. Write the staged implementation plan.
