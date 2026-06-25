---
name: Docs From Code
description: Generate accurate architectural documentation and technical notes directly from source code and Graphify outputs.
---

## Triggers
- When the user asks to document an API, database schema, or module design.
- When creating files like `ARCHITECTURE.md` or updating technical readmes.
- When generating usage instructions for a helper class or engine.

## Step-by-Step Instructions
1. **Gather Structural Context**:
   - Query Graphify to find the classes, methods, and functions that need documentation.
   - For database schemas, query Graphify postgres extraction or check [postgres_db.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/postgres_db.py) directly.
2. **Inspect Code Signatures**:
   - Read function signatures, decorators, docstrings, and typings.
3. **Draft the Document**:
   - Synthesize the code findings. Ensure every code block corresponds to actual code implementation, not placeholder patterns.
4. **Link to Code Source**:
   - Include clickable links to the files and line ranges documented.

## Output Format
Your response must include:
- **Title and Purpose**: Clear explanation of what is being documented.
- **API/Schema Specification**: Tables detailing endpoints, parameters, or database tables.
- **Code Reference Links**: Specific source references.
- **Example Usage**: A fenced code block showing a real-world call or request payload.

## Anti-Patterns
- **Do NOT** make up parameters or options. Always read the code to verify.
- **Do NOT** write outdated information; use the current state of the files.
- **Do NOT** forget to include exact types (e.g., `str`, `List[dict]`, etc.).

## Project-Specific Example
When generating API docs for `/api/scan/dynamic`:
1. Inspect the route registration in [routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/routes.py).
2. Extract the Pydantic request model.
3. Trace the call to [dynamic_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/dynamic_engine.py).
4. Create the documentation table mapping parameters to their validations and describing the dynamic scan process.
5. Provide a curl request example.
