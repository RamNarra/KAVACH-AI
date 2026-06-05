# KAVACH AI Forensic Audit

## Scope

- Inspected all 86 tracked files in the repository.
- Also inspected untracked backend files currently affecting runtime behavior: `backend/routes.py` and `backend/sandbox_runner.py`.
- Excluded `node_modules`, `.next`, `venv`, `.git`, and cache folders from engineering judgment as third-party/generated artifacts, but verified their presence and scale.

## Repository Reality

- This is not a world-class malware-analysis platform.
- It is a hackathon-grade prototype with some real engineering effort, some useful ideas, and a large amount of narrative inflation.
- The strongest parts are the static-analysis aggregation, the dynamic-analysis UI work, and the attempt to separate deterministic scoring from LLM narration.
- The weakest parts are runtime correctness, backend architecture integrity, test discipline, and claim-to-implementation honesty.

## Architecture Map

```mermaid
flowchart TD
    A[Next.js Frontend] --> B[FastAPI Backend]
    B --> C[Upload or URL Fetch]
    C --> D[Temp Workspace]
    D --> E[APKTool]
    D --> F[JADX]
    D --> G[APKiD]
    D --> H[Quark]
    D --> I[Androguard Subprocess]
    F --> J[Secrets Heuristics]
    F --> K[Semgrep]
    F --> L[TruffleHog]
    E --> M[Manifest + Network Security Config]
    E & F & G & H & I & J & K & L & M --> N[Deterministic Risk Engine]
    N --> O[Banking Fraud Heuristics]
    N --> P[MITRE Mapping]
    N --> Q[Gemini Narrative Synthesis]
    B --> R[Optional Dynamic Sandbox]
    R --> S[ADB + Emulator + Frida + Playbook]
    S --> T[Runtime Findings Clusterer]
    T --> O
    T --> P
    T --> Q
    Q --> U[Saved Analysis Document]
    U --> A
```

## Trust Boundaries

1. Browser to backend.
2. Backend to arbitrary APK source URL.
3. Backend host to local temp filesystem.
4. Backend host to subprocess toolchain.
5. Backend host to Android emulator / ADB / Frida.
6. Backend to Gemini.
7. Backend to local JSON pseudo-database.

## Attack Surface

- `/api/analyze`
- `/api/analyze/upload`
- `/api/analysis/{id}/dynamic`
- `/api/chat`
- APK parsing and decompilation subprocesses
- Emulator/Frida instrumentation path
- Local JSON document store
- Public static frontend talking to open backend

## Brutal Module Scores

| Module | Score /10 | Verdict |
|---|---:|---|
| Frontend UX shell | 7 | Strongest visual area, but overdesigned and operationally fragile |
| Frontend API contract | 4 | Deployment-hostile and too localhost-centric |
| Main backend pipeline | 5 | Ambitious, but tangled and partially dishonest about guarantees |
| Static analysis engines | 6 | Useful breadth, weak signal quality, duplicated logic |
| Dynamic analysis engine | 5 | Real work here, but brittle and overclaimed |
| Risk scoring | 4 | Deterministic, but mathematically biased and partially double-counted |
| Auth / access control | 4 | Better than nothing, still effectively demo-grade |
| Data persistence | 2 | Unsafe under multi-worker concurrency |
| Tests | 3 | Frontend unit tests are decent; backend suite is structurally broken |
| Infra / deployment coherence | 4 | Static hosting + Cloud Run ideas exist, but runtime modes conflict |

## Top Security and Correctness Findings

### Critical

1. `routes.py` depends on globals that are never injectable, so the dynamic-analysis route is runtime-broken.
   - Evidence: `inject_globals()` only sets names already declared in the module, but `routes.py` never declares `parse_apk_metadata_fast`, `sandbox_lock`, `select_packs_from_signals`, `cluster_runtime_findings`, `derive_dynamic_score`, `build_contributors`, `calculate_absolute_threat_score`, `build_runtime_summary_for_gemini`, `analyze_banking_fraud`, `build_risk_decomposition`, or `map_evidence_to_attack`.
   - Impact: `/api/analysis/{id}/dynamic` can crash with `NameError` once execution reaches those paths.
   - Files: `backend/routes.py`, `backend/main.py`

2. The app is effectively open for anonymous backend abuse.
   - Evidence: CORS is `*`; auth is only a client-generated session header; frontend comments explicitly call it “No-auth”; upload and analysis routes accept any caller with a syntactically valid session token.
   - Impact: Anyone can burn compute, upload samples, and hammer emulator/tooling capacity. This is not bank-grade, not SOC-grade, not even mildly production-safe.
   - Files: `backend/main.py`, `backend/auth.py`, `frontend/src/lib/api.ts`

3. Persistence is unsafe because the app uses a single JSON file as a pseudo-database while running multiple workers.
   - Evidence: `LocalDB` uses a process-local `threading.Lock`; `start.sh` launches `uvicorn` with `--workers 2`.
   - Impact: race conditions, lost updates, corrupted analysis documents, broken logs, inconsistent progress states.
   - Files: `backend/local_db.py`, `backend/start.sh`

### High

4. Claimed `gs://` support is fake.
   - Evidence: `is_safe_ingest_url()` accepts `gs://`, but `run_analysis_pipeline()` fetches every non-`file://` URL with `httpx.Client().get(apk_url)`.
   - Impact: documented ingestion path fails at runtime.
   - File: `backend/main.py`

5. Risk scoring double-counts static evidence by treating the AI score as an additional weighted component even when it is forcibly set equal to the deterministic score.
   - Evidence: `analysis_json["risk_score"] = det_score`; later `build_risk_decomposition(static_score=static_score, ai_score=gemini_score, ...)` where `gemini_score == det_score`.
   - Impact: inflated composite scoring dressed up as “explainable”.
   - Files: `backend/main.py`, `backend/risk_engine.py`

6. The Androguard path still has a false-positive problem severe enough to poison credibility.
   - Evidence: the in-pipeline `analyze_androguard()` in `analysis_engine.py` flags generic long alphanumeric descriptors as “Long Base64 Blob” without the filter present in `backend/androguard_analyzer.py`; committed sample output proves the failure mode.
   - Impact: noisy evidence, fake risk inflation, analyst distrust.
   - Files: `backend/analysis_engine.py`, `backend/androguard_result_test.json`

7. Backend test files are integration scripts with import-time side effects, not a safe test suite.
   - Evidence: `test_pipeline.py` and `test_dynamic_pipeline.py` upload live APKs and call localhost endpoints at module import time.
   - Impact: `pytest` is not trustworthy as a CI gate and can hang or mutate external state.
   - Files: `backend/test_pipeline.py`, `backend/test_dynamic_pipeline.py`

### Medium

8. Temp-file cleanup on startup can wipe pending workspaces.
   - Evidence: startup recursively deletes everything in `SCAN_TEMP_DIR`.
   - Impact: in-flight uploads or resumable work can disappear on restart.
   - File: `backend/main.py`

9. “Zipbomb prevention” is mostly theater.
   - Evidence: `MAX_UNCOMPRESSED_SIZE` is declared in upload handling and never used; only compressed input size is bounded.
   - Impact: decompression-heavy APKs can still amplify CPU/disk pressure downstream.
   - File: `backend/routes.py`

10. The frontend defaults to `http://localhost:8080` even on non-local hosts unless overrides are set.
   - Impact: deployed frontend can silently point at the wrong API and appear dead.
   - File: `frontend/src/lib/api.ts`

11. Docker frontend runtime conflicts with static export mode.
   - Evidence: `next.config.mjs` sets `output: 'export'`, while Docker runs `npm run start`.
   - Impact: deployment story is inconsistent and likely brittle.
   - Files: `frontend/next.config.mjs`, `frontend/Dockerfile`

12. Firebase client config is committed, and Firebase still appears throughout the repo despite the backend having switched to local JSON storage.
   - Impact: architectural confusion, stale trust assumptions, demo-to-prod confusion.
   - Files: `frontend/src/lib/firebase.js`, `firebase.json`, `firestore.rules`, `storage.rules`

### Low

13. `extract_static_signals()` hardwires `has_data_storage` to true.
   - Impact: hook-pack selection loses meaning and pretends to be evidence-driven when it is not.
   - File: `backend/main.py`

14. Committed empty Quark logs and bulky sample artifacts add clutter without value.
   - Impact: repo looks less disciplined than the pitch claims.
   - Files: `backend/2026-05-28.quark.log`, `backend/2026-06-03.quark.log`, `frontend/2026-05-28.quark.log`

## Malware Analysis Accuracy Review

### Static Analysis

- Better than a single-engine class project.
- Nowhere near MobSF in depth or consistency.
- Worse than a careful analyst using JADX + APKTool + Androguard directly because your aggregation layer introduces its own scoring noise.
- Semgrep and TruffleHog on decompiled Java are clever for a hackathon, but still heuristic and easy to oversell.

### Dynamic Analysis

- The Frida/ADB/emulator path is the most ambitious part of the repo.
- It is also brittle, timing-sensitive, and highly dependent on one emulator environment.
- This is not comparable to a mature emulator sandbox. It is a best-effort trigger harness.

### AI Layer

- AI adds some value in explanation and report formatting.
- AI does not materially perform reverse engineering.
- The “GenAI-powered malware analysis system” claim is inflated. The real system is “multi-engine heuristic analysis with LLM summarization and chat”.

## GenAI Verdict

- Category: partially useful
- Real value:
  - report synthesis
  - conversational explanation
  - maybe UI-field classification in the playbook
- Fake value:
  - “reverse engineering”
  - “cognitive layer”
  - “intelligent threat summarization” as if it were grounded reasoning instead of constrained restatement

## Performance Review

- Static pipeline parallelism is good in concept.
- Local JSON persistence plus multi-worker backend is a self-inflicted bottleneck.
- Dynamic analysis is expensive and low-throughput.
- Frontend polling every 2.5 seconds is fine for demo scale.
- LLM usage is not insane, but the prompts are oversized and marketing-heavy.

## Judge Simulation

| Category | Score /10 |
|---|---:|
| Innovation | 7 |
| Engineering | 5 |
| Security | 4 |
| Product Thinking | 6 |
| AI Usage | 4 |
| Banking Relevance | 7 |
| Presentation Potential | 8 |
| Demo Potential | 7 |
| Feasibility | 5 |
| Real-World Impact | 5 |

## Final Score

58 / 100

## AIR-1 Positioning

- Average student team: likely weaker than this.
- Top 10% team: competitive with this or better.
- Top 1% team: this loses unless cleaned up hard.
- AIR-1 probability in current form: low.

Verdict: **Below AIR-1**

## What Is Excellent

- UI ambition and demo readability.
- Real attempt to combine static and dynamic signals.
- Sensible instinct to keep numeric scoring deterministic.

## What Is Good

- Breadth of tooling.
- Some defensive thinking around sandboxing and SSRF.
- Dynamic-analysis helper/test coverage on the frontend.

## What Is Average

- FastAPI structure.
- Next.js app composition.
- MITRE mapping.

## What Is Weak

- Runtime correctness.
- Persistence architecture.
- Deployment coherence.
- Test discipline.
- Evidence quality calibration.

## What Is Dangerous

- Open backend abuse surface.
- Broken dynamic route dependency injection.
- Multi-worker JSON storage.

## What Is Fake Complexity

- “Tiered cognitive GenAI layer”
- “Hallucination-free scoring” while still double-counting score inputs
- “Bank-grade” positioning
- Large prompt rhetoric standing in for analytical rigor

## What Should Be Deleted

- Import-time integration scripts pretending to be tests.
- Empty committed logs.
- Stale Firebase narrative if local JSON remains the true backend.

## What Should Be Rebuilt

- Backend state/storage layer.
- Dynamic-route wiring.
- Score composition.
- Deployment contract between frontend and backend.

## What Should Be Doubled Down On

- UI polish
- deterministic evidence model
- Frida/emulator operator view
- concise analyst-facing reporting

## Estimated Rank

- Among 100 teams: 15-30
- Among 500 teams: 60-150
- Among 1000 teams: 120-300

## Fastest Path Upward

1. Fix backend correctness before adding features.
2. Replace LocalDB with a real datastore or single-worker queue model.
3. Repair dynamic route injection and test it end to end.
4. Remove score inflation and clean false-positive analyzers.
5. Tighten the public API surface and add real rate limiting.
6. Simplify the pitch so claims match reality.
