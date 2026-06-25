---
name: Large Repo Navigation
description: Navigate and explore large codebases using Graphify structural searches instead of brute-force grep/read operations.
---

## Triggers
- When the user asks "where is X implemented?" or "what files handle Y?".
- When you need to understand the boundaries of a large, unfamiliar module.
- When trying to trace imports and connections across multiple files.

## Step-by-Step Instructions
1. **Initiate Graph Search**:
   - Query Graphify first to find candidate files. Do not use generic find/grep commands on the whole codebase:
     ```bash
     graphify query "Where is the Celery task runner defined?"
     ```
2. **Examine Connections**:
   - Trace the edges or relationships of the target node to find callers and consumers.
3. **Execute Targeted Reads**:
   - Read the exact lines using `view_file` with `StartLine` and `EndLine` constraints. Do not read the entire file.
4. **Build Context Mentally**:
   - Formulate a structural map of the related files without dumping raw files into the chat context.

## Output Format
Your response must include:
- **Graph Query Results**: The query used and the returned matching nodes.
- **Symbol Location Table**:
  | Symbol | File | Line Range | Purpose |
  | :--- | :--- | :--- | :--- |
  | `CeleryApp` | `backend/celery_app.py` | L1-L45 | Configures broker and backend |
- **Scope Navigation Walkthrough**: A concise explanation of the files linked to the symbol.

## Anti-Patterns
- **Do NOT** read more than 100 lines of code without a specific line-range target.
- **Do NOT** run broad `grep -r` commands. Utilize Graphify's query features.
- **Do NOT** list all directories recursively. Consult `graphify-out/GRAPH_REPORT.md` instead.

## Project-Specific Example
When finding where APK signature verification is done:
1. Run `graphify query "signature forensics"`.
2. Graphify points to [test_certificate_forensics.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/test_certificate_forensics.py) and [androguard_analyzer.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/androguard_analyzer.py).
3. Directly inspect [androguard_analyzer.py](file:///home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH%20AI/backend/androguard_analyzer.py) in the line range where signature check functions are located.
