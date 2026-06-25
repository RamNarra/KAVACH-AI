---
name: Project Planner
description: Decompose complex user goals into logical phases, task checklists, and dependency-mapped roadmaps.
---

## Triggers
- When the user outlines a major upgrade (e.g., migrating a framework, adding multi-tenancy, or upgrading dependencies).
- When a task requires modifications across multiple modules over several sessions.
- When creating roadmap plans or defining milestone files.

## Step-by-Step Instructions
1. **Define the Scope**:
   - Clarify the user's ultimate goal and identify all components involved.
2. **Analyze Structural Dependencies**:
   - Query Graphify to map the dependency hierarchy of the files that will change. This ensures you plan changes in the correct order (lower-level first):
     ```bash
     graphify query "What modules import postgres_db and routes?"
     ```
3. **Decompose into Phases**:
   - Break down the goal into distinct, verifiable phases (e.g., Phase 1: Core engine edits, Phase 2: API routes, Phase 3: UI integration).
4. **Draft the Roadmaps**:
   - Create a task checklist for each phase, specifying which files are edited and how to test them.

## Output Format
Your response must include:
- **Project Roadmap**: An overview of the milestones.
- **Phased Implementation Checklist**:
  ```markdown
  ### Phase 1: Core Engine Edits
  - [ ] Update `backend/postgres_db.py` to support multi-tenant schemas
  - [ ] Verify using database tests
  ```
- **Dependency Flow**: A Mermaid flowchart showing task dependencies.

## Anti-Patterns
- **Do NOT** plan tasks without specifying which files are affected.
- **Do NOT** propose all changes in a single stage; always structure them in phases.
- **Do NOT** omit the verification steps for each phase.

## Project-Specific Example
When planning a migration to Celery queue-based analysis:
1. Locate [celery_app.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/celery_app.py) and [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py) using Graphify.
2. Formulate Phase 1: Setting up Celery tasks in [celery_app.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/celery_app.py) and verifying broker connection.
3. Formulate Phase 2: Updating [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py) to trigger Celery tasks asynchronously instead of running blockers.
4. Formulate Phase 3: Updating frontend to poll for task status.
5. Generate the flowchart and checklists.
