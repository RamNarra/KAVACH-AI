---
name: Repo Architecture
description: Analyze modules, boundaries, data flow, entry points, and dependencies of KAVACH AI using Graphify.
---

## Triggers
- When the user asks about the overall system design or architectural boundaries.
- When mapping dependencies between modules (e.g., how the Next.js frontend communicates with the FastAPI backend).
- When investigating the entry points of the backend (`backend/main.py`) or routing configurations (`backend/routes.py`, `frontend/src/app/`).
- When determining module ownership or data paths (e.g., how MobSF static analysis results flow through the analysis engine to the PostgreSQL database).

## Step-by-Step Instructions
1. **Consult the Code Graph**:
   - Check if `graphify-out/graph.json` or `graphify-out/GRAPH_REPORT.md` exists.
   - If they exist, query Graphify first to locate the relevant files and boundaries before reading any files:
     ```bash
     graphify query "What are the core modules and how do they interact?"
     ```
2. **Trace the Entry Points**:
   - For backend routes, consult [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py) and [main.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/main.py).
   - For frontend structure, inspect the `frontend/src/` folder tree.
3. **Map the Data Flow**:
   - Trace the flow of data from input scan requests (e.g., APK uploads) to database persistence in [postgres_db.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/postgres_db.py) and background processing via Celery in [celery_app.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/celery_app.py).
4. **Synthesize Findings**:
   - Present a concise, component-based description of the system boundaries and linkages.

## Output Format
Your response must include:
- **Architectural Diagram**: A Mermaid diagram representing the modules and their interaction.
- **Component Analysis**: A clean markdown table mapping core modules to their corresponding files and purposes.
- **Data Flow Explanation**: A concise bulleted sequence tracking a specific data path (e.g., scan request to result generation).

## Anti-Patterns
- **Do NOT** read all files in `backend/` or `frontend/` to understand the system.
- **Do NOT** list all imports of every file manually. Rely on Graphify's import extraction.
- **Do NOT** write explanations without referencing specific files using clickable links.

## Project-Specific Example
When explaining how mobile app reports are generated:
1. Consult Graphify to identify the linkage: `routes.py` -> `analysis_engine.py` -> `report_generator.py`.
2. Present a Mermaid diagram showing the request going from the Next.js frontend to [routes.py:scan_endpoint](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py), processed by [analysis_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/analysis_engine.py), formatted by [report_generator.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/report_generator.py), and saved in [postgres_db.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/postgres_db.py).
