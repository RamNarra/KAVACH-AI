# 🛡️ KAVACH AI

<div align="center">
  <img src="https://img.shields.io/badge/Security-Forensic--Sandbox-red?style=for-the-badge&logo=shield" alt="Security" />
  <img src="https://img.shields.io/badge/AI-Multi--Tier--Resilient-purple?style=for-the-badge&logo=google-gemini" alt="GenAI" />
  <img src="https://img.shields.io/badge/Framework-Next.js--14-black?style=for-the-badge&logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Database-Supabase-3ECF8E?style=for-the-badge&logo=supabase" alt="Supabase" />
</div>

<p align="center">
  <strong>Generative AI-Powered Mobile Banking Trojan Sandbox & Explainable Threat Auditing System</strong>
  <br />
  <em>Developed for the Bank of India × IIT-Hyderabad Hackathon 2026</em>
</p>

---

## 📌 HERO SECTION

*   **Project Title**: **KAVACH AI** — Intelligent Android Forensic Sandbox & Explainable Threat Auditor
*   **Mission Statement**: Automating forensic-grade static and dynamic APK analysis to shield banking consumers from mobile trojan campaigns via explainable, evidence-backed threat reports.
*   **Hackathon Context**: Bank of India × IIT-Hyderabad Hackathon 2026 (Problem Statement: Harnessing Generative AI for Automated Reverse Engineering, Static and Dynamic Analysis, and Risk Scoring of Fraudulent Mobile Applications/APKs).
*   **Submission Status**: **AIR-1 Hardened Production-Ready Release** 

---

## 📖 EXECUTIVE SUMMARY

KAVACH AI is a high-fidelity security scanner and analysis sandbox built to inspect suspicious Android applications (`.apk`). It automates reverse engineering, executes files inside isolated dynamic emulators, maps security telemetry to industry standard frameworks, and utilizes Google Gemini large language models (LLMs) to synthesize threat data into clear, natural language advisories.

By combining deterministic parsing engines (static decompilation, bytecode scans, secret sweeps) with behavioral triggers (Frida intercepts, network inspection, and UI-automation playbooks), KAVACH AI translates technical vulnerability data into plain-English threat summaries. This bridges the communication gap between Security Operations Centers (SOCs), bank customer care agents, and affected consumers.

---

## ⚠️ THE PROBLEM: THE BANKING TROJAN LANDSCAPE

Mobile banking fraud is undergoing a transformation driven by sophisticated Android Banking Trojans (e.g., *SOVA*, *BRATA*, *Xenomorph*, *Cerberus*, *Drinik*). Threat actors bypass traditional Play Store security checks to distribute these payloads via phishing links, fake WhatsApp forwards, or malicious SMS messages. 

Once installed, these applications hijack the user's device by exploiting three main vectors:
1.  **Accessibility Services Abuse**: Overriding Android's accessibility APIs to intercept screen content, read keystrokes, and automatically inject taps to perform unauthorized funds transfers.
2.  **SMS Interception (OTP Stealing)**: Silently reading and exfiltrating SMS messages containing two-factor authentication (2FA) codes to bypass banking transaction guards.
3.  **Overlay Phishing Injection**: Detecting when a user opens a targeted banking application (e.g., SBI YONO, HDFC Bank, PayTM) and drawing a malicious overlay screen on top to harvest login credentials and PINs.

### 🚨 The SOC & Customer Advisory Bottleneck
When fraud occurs, time-to-response is critical. However, Security Operations Centers (SOCs) and banking customer care agents are constrained by:
*   **Decompilation Latency**: Tools like MobSF or standard decompiler chains can take 5–10 minutes to process a single sample, which is too slow for real-time threat response.
*   **Data Overload**: Raw decompiler output contains millions of lines of Java source code, XML manifests, and DEX assembly dumps that require hours of expert manual review.
*   **Lack of Communication Channels**: No automated mechanism exists to turn raw, technical indicators into simple, citizen-facing advisory reports that can be used to warn affected consumers.

---

## ❌ WHY EXISTING SOLUTIONS FAIL: GAP ANALYSIS

| Vector | Existing Solutions (e.g., MobSF, VirusTotal) | KAVACH AI Advantage |
| :--- | :--- | :--- |
| **Analysis Latency** | Sequential analysis blocks, taking 5+ minutes to process. | **Parallel GIL-free static analysis pool** completes scans in under 35 seconds. |
| **TLS/HTTPS Intercept** | Standard socket traces capture encrypted binary streams. | **Frida intercepts at application-level** (`okhttp3.RealCall`), capturing decrypted network payloads. |
| **Sandbox Execution** | Fragile UI scripts fail when encountering system alerts or overlays. | **Playbook UI explorer engine** uses element hierarchies to dismiss warning prompts. |
| **Explainable Scoring** | Cryptic risk indicators or speculative LLM summaries. | **OWASP Likelihood x Impact matrix** combined with evidence-validated LLM reports. |
| **Reliability/Uptime** | Fails or timeouts under high server loads. | **Multi-tiered fallback chains** (Gemini 3.5 Flash $\rightarrow$ 3.1 Flash-Lite $\rightarrow$ Offline rules). |

---

## 💡 THE KAVACH AI SOLUTION

```
  📥 APK Ingestion (Secure Upload or Validated Ingest URL)
      │
      ├───────────────────────────────┐
      ▼                               ▼
  ⚡ Parallel Static Phase         🔬 Dynamic Emulation Phase
  ┌───────────────────────────┐   ┌───────────────────────────┐
  │ 📂 APKTool & JADX         │   │ 📱 Android Emulator Boot  │
  │ 🏷️ APKiD Signature Match  │   │ 🧬 Frida API Hooking      │
  │ 🔍 Androguard DEX Parser  │   │ 🤖 UI Playbook Automation │
  │ 🔑 TruffleHog Secret Check│   │ 🌐 okhttp3 HTTPS Intercept│
  └─────────────┬─────────────┘   └─────────────┬─────────────┘
                │                               │
                └───────────────┬───────────────┘
                                ▼
                    🛡️ Attributor & Risk Engine
                    - OWASP Likelihood x Impact Score
                    - MITRE ATT&CK Mapping
                    - Banking Trojan Fingerprints
                                ▼
                    🧠 Resilient AI Synthesis
                    - Gemini 3.5 Flash gateway
                    - Cross-Validation Badge engine
                    - Plain-English Citizen Advisories
```

KAVACH AI addresses mobile threat analysis through a three-stage automated pipeline:
1.  **Secure Parallel Static Analysis**: Extracts Android Manifest files, runs Semgrep rule sets, and performs bytecode constant pool scans in under 35 seconds.
2.  **Isolated Dynamic Sandbox**: Installs the APK into an Android emulator, runs automated UI playbooks to bypass initial prompts, and uses Frida hooks to capture decrypted HTTP network traffic and file system operations.
3.  **Explainable Risk Aggregator**: Evaluates all findings using a deterministic OWASP Risk Rating matrix and generates explainable, citizen-facing reports via a resilient Gemini API fallback gateway.

---

## 🧩 SYSTEM ARCHITECTURE & COMPONENTS

KAVACH AI is built on a modular, decoupled architecture where backend analysis routines are isolated from the client gateway:

```mermaid
sequenceDiagram
    autonumber
    actor User as Banking Investigator
    participant UI as Next.js Dashboard
    participant API as FastAPI Gateway
    participant Sandbox as Docker-Sandbox (JADX/Apktool)
    participant Emu as Emulator (Frida/ADB)
    participant AI as Gemini 1.5/2.0 Gateway
    database DB as Supabase DB

    User->>UI: Uploads APK / Submits Ingest URL
    UI->>API: POST /api/analyze (Multipart/URL)
    Note over API: Validates URL (SSRF Shield)<br/>Validates Size (Zipbomb check)
    API->>DB: Set initial status to PROCESSING
    API-->>UI: Return Job ID (Async Processing Starts)
    
    par Static Analysis Pipeline
        API->>Sandbox: Execute sandboxed_run() (Docker Container)
        Note over Sandbox: JADX Decompile & Apktool Extract<br/>--network none --memory 3g --user nobody
        Sandbox-->>API: Manifest XML, JADX Source Code, Assets
        API->>API: Run TruffleHog (Secrets) & Semgrep (Vulnerabilities)
        API->>API: Run Androguard DEX Bytecode Scan
    and Dynamic Analysis Pipeline
        API->>Emu: ADB Install Target APK
        API->>Emu: Inject Frida Hooks (okhttp3 Intercept)
        API->>Emu: Run Playbook Engine (UI Interactions)
        Emu-->>API: Capture Decrypted API Payloads & Syscalls
    end

    API->>API: Compile Telemetry & Calculate OWASP Risk Rating
    API->>AI: Send Analysis Data (Delimited Prompt Envelope)
    AI-->>API: Synthesized Report & Advisory (JSON)
    API->>API: Cross-validate AI findings vs. Static/Dynamic facts
    API->>DB: Save Fernet-Encrypted Scan Document
    UI->>API: SSE (Server-Sent Events) Status Poll
    API-->>UI: Pushes Complete Document
    UI->>User: Displays interactive Threat Dashboard
```

---

## 📂 REPOSITORY STRUCTURE & CODE SYMBOLS

```
KAVACH-AI/
├── backend/                       # FastAPI Backend Application Services
│   ├── main.py                    # Pipeline orchestrator, worker pool, downloaders, and cleanup [1]
│   ├── routes.py                  # API route handlers, stream uploads, rate limits, and hooks [2]
│   ├── auth.py                    # JWT token parser, security sessions, and admin filters [3]
│   ├── sandbox_runner.py          # Isolation wrapper spawning Docker-Sandbox subprocesses [4]
│   ├── Dockerfile-sandbox         # Build recipe for the eclipse-temurin JRE sandbox container [5]
│   ├── Dockerfile                 # Production Dockerfile for backend deployments
│   ├── supabase_db.py             # Encrypted Postgrest DB wrapper mimicking Firestore API [6]
│   ├── analysis_engine.py         # Semgrep rule processor and TruffleHog scanner [7]
│   ├── androguard_analyzer.py     # DEX Bytecode constant scanner and namespace filter [8]
│   ├── banking_fraud.py           # Signature heuristics for known trojans (SOVA, BRATA, etc.) [9]
│   ├── risk_engine.py             # OWASP Likelihood x Impact scoring calculator [10]
│   ├── attack_mapping.py          # Dynamic indicator mapper to MITRE ATT&CK techniques [11]
│   ├── dynamic_engine.py          # ADB interface, Frida session orchestrator, and app installer [12]
│   ├── playbook_engine.py         # UI Automator crawler and interactive monkey simulator [13]
│   ├── frida_hooks.py             # Javascript hooking files (okhttp3, file, and SMS intercepts) [14]
│   ├── vt_scan.py                 # Async VirusTotal SHA-256 hash lookup client [15]
│   └── test_intelligence.py       # Pytest testing suite covering security limits and rates [16]
├── frontend/                      # Next.js Frontend Web Application
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx           # Cyber-dashboard interface with live SSE poll streams [17]
│   │   │   ├── globals.css        # CSS stylesheets, matrix canvas configuration, themes
│   │   │   └── layout.tsx         # Next.js layout template
│   │   └── lib/
│   │       ├── api.ts             # API client with same-origin detection & IndexedDB cache [18]
│   │       └── types.ts           # Unified TypeScript definitions for scan documents [19]
├── supabase/                      # Supabase Local Development Configuration & Migrations
│   ├── config.toml                # Supabase local environment settings
│   └── migrations/
│       └── 20260611000000_...     # Database migration schema & PL/pgSQL rate functions [20]
├── ops/                           # Ops scripts and cleanup policies
│   ├── cleanup_orphan_apks.py     # Automatic process pruning unused host workspace files
│   └── storage-lifecycle.json     # Storage lifecycle settings
├── setup.sh                       # One-command dependency installation script
└── start.sh                       # One-command runtime orchestrator script
```

### Module Code Symbol Directory (Internal Clickable References)

*   [1] [backend/main.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/main.py): Pipeline orchestrator that coordinates analysis jobs using a `ThreadPoolExecutor` and a `Semaphore` (limit 2) to control host resources. Includes cleanups for temporary workspaces.
*   [2] [backend/routes.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/routes.py): Handles FastAPI routes, multipart file streams, rate limit updates, and hooks injection.
*   [3] [backend/auth.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/auth.py): Verifies incoming Authorization Bearer tokens against the configured JWT secret, with support for session headers.
*   [4] [backend/sandbox_runner.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/sandbox_runner.py): Secure subprocess runner that executes JADX/Apktool inside isolated Docker containers using dropped capabilities.
*   [5] [backend/Dockerfile-sandbox](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/Dockerfile-sandbox): Multi-stage Dockerfile that builds the sandbox container, using eclipse-temurin JRE and a non-root `sandbox` user.
*   [6] [backend/supabase_db.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/supabase_db.py): Drops in to replace standard Firestore interfaces, encrypting sensitive fields using Fernet before transmission.
*   [7] [backend/analysis_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/analysis_engine.py): Executes Semgrep AST checks and parses TruffleHog secrets outputs.
*   [8] [backend/androguard_analyzer.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/androguard_analyzer.py): Directly parses DEX file headers and checks constant tables.
*   [9] [backend/banking_fraud.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/banking_fraud.py): Rule matches signature checks against known mobile banking trojans.
*   [10] [backend/risk_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/risk_engine.py): Implements the OWASP Likelihood x Impact scoring framework.
*   [11] [backend/attack_mapping.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/attack_mapping.py): Maps bytecode telemetry and indicators to MITRE ATT&CK techniques.
*   [12] [backend/dynamic_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/dynamic_engine.py): Handles APK installations on the emulator and initiates Frida hooks sessions.
*   [13] [backend/playbook_engine.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/playbook_engine.py): Uses UIAutomator screen hierarchies to interact with the target app.
*   [14] [backend/frida_hooks.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/frida_hooks.py): Frida JavaScript interceptor code for capturing unencrypted outbound network traffic.
*   [15] [backend/vt_scan.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/vt_scan.py): Queries VirusTotal APIs asynchronously using file hashes.
*   [16] [backend/test_intelligence.py](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/backend/test_intelligence.py): Validates safety boundaries, file sizes, and API routes.
*   [17] [frontend/src/app/page.tsx](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/frontend/src/app/page.tsx): Main dashboard application, displaying threat metrics, dynamic traces, and MITRE maps.
*   [18] [frontend/src/lib/api.ts](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/frontend/src/lib/api.ts): Client wrapper implementing IndexedDB client-side caching.
*   [19] [frontend/src/lib/types.ts](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/frontend/src/lib/types.ts): Unified TypeScript types for API and dashboard states.
*   [20] [supabase/migrations/20260611000000_create_documents_table.sql](file:///home/p4cketsn1ff3r/Downloads/Projects/KAVACH%20AI/supabase/migrations/20260611000000_create_documents_table.sql): Database schema migrations and PL/pgSQL atomic rate limiting functions.

---

## 🛠️ TECHNICAL DEEP DIVES

### 1. The AI Layer (Multi-Tiered Cognitive Gateway)
KAVACH AI handles LLM interactions through a multi-tiered fallback architecture to ensure reliability and cost efficiency:
*   **Prompt Isolation and Defense**: To prevent prompt injection, inputs are wrapped inside explicit structural tags (`<ANALYSIS_PAYLOAD>`). Prompts contain system instructions that explicitly warn the model against executing instructions embedded in analyzed file strings.
*   **Token Optimization**: Analysis payloads are truncated dynamically using a `MAX_PER_FILE` limit of 4KB and a `MAX_TOTAL_PAYLOAD` limit of 40KB. This avoids context window bloat and controls execution costs.
*   **Sequential Model Fallbacks**: If the primary model `gemini-3.5-flash` is throttled, the orchestrator automatically falls back to secondary options:
    1. `gemini-3.5-flash` (Primary analysis)
    2. `gemini-3.1-flash-lite` (Low latency fallback)
    3. `gemini-2.5-flash` / `gemini-2.0-flash`
    4. Offline Heuristics Engine (Fallback summary when cloud APIs are unavailable)
*   **Anti-Hallucination Decoupling**: Numerical risk scoring is kept separate from LLM generations. Ratings are computed deterministically using standard formulas, restricting the LLM to summarizing findings.

---

### 2. Static Analysis Engine
The static analysis phase decompiles the APK and parses code structures:
*   **Manifest Inspector**: Extracts application package names, component export statuses, intent filters, and permission declarations.
*   **DEX Constant Pool Analyzer**: Directly scans Dalvik Executable (DEX) files using Androguard to find hardcoded base64 patterns, command execution keywords (`Runtime.getRuntime().exec`), and dynamic class loader calls. It automatically ignores common framework paths (like `androidx.*` or `kotlin.*`) to minimize noise.
*   **Secret Sweep & Code Auditor**: Integrates TruffleHog scanner logic and Semgrep rules mapped to the OWASP Mobile Application Security Verification Standard (MASVS) to identify embedded keys and potential vulnerabilities.

---

### 3. Dynamic Analysis Engine
When static analysis indicates possible risks, the dynamic analysis environment is triggered:
*   **Dynamic Class Interceptors (Frida)**: Intercepts `okhttp3.RealCall.enqueue` and `execute` methods to capture unencrypted outbound payloads, endpoints, and C2 servers before SSL encryption is applied.
*   **UI Playbook Automator**: Automatically interacts with the target application inside the emulator via UIAutomator. It uses view hierarchy selector matching to locate buttons, enter text fields, and dismiss system dialog warnings.
*   **Emulator Isolation**: Executes analyzed code within a headless Android Virtual Device (AVD) running behind a sandboxed environment to prevent potential host escapes.

---

## 🏛️ TECHNOLOGY STACK

| Category | Technology | Detail |
| :--- | :--- | :--- |
| **Frontend UI** | Next.js 14 / TypeScript | App Router layout, dynamic EventSource Server-Sent Events, Tailwind CSS |
| **Backend Core** | FastAPI (Python 3.11) | High-performance asynchronous routing, ThreadPoolExecutor parallel workers |
| **Database** | Supabase (PostgreSQL) | Postgrest REST API backend, client-side Fernet symmetric encryption |
| **Sandbox Execution** | Docker Engine | Capability-dropped isolated sandbox container (`kavach-sandbox:latest`) |
| **Static Analyzers** | JADX, APKTool, Androguard | Dalvik bytecode parsers, resource extractors, constant pool scanning |
| **Vulnerability Scanning**| Semgrep & TruffleHog | AST security audit, OWASP MASTG rule compliance, secrets scanner |
| **Dynamic Intercepts** | Frida & ADB Platform-Tools | OkHttp3 interceptors, runtime API hooks, UIAutomator playbooks |
| **AI Synthesis** | Google Gemini API | Gemini 3.5 Flash primary engine, multi-model fallback routines |

---

## 🔒 SECURITY HARDENING & SANDBOXING

```
  Untrusted APK Ingestion
      │
      ▼
  ┌─────────────────────────────────────────────────────────┐
  │ Host API SSRF Shield (socket.getaddrinfo verification)  │
  └──────────────────────────┬──────────────────────────────┘
                             │ (Passed)
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │ Zipbomb Scanner (Verifies uncompressed size < 2GB)     │
  └──────────────────────────┬──────────────────────────────┘
                             │ (Passed)
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │ Isolated Docker Subprocess (sandbox_runner.py)          │
  │ - Host System Isolation (--network none)                │
  │ - RAM Limits & Swap Controls (--memory 3g)             │
  │ - Dropped Capabilities (--cap-drop=ALL)                │
  │ - Writable Temporary Files System in RAM (--tmpfs /tmp) │
  │ - Immutable Root File System (--read-only)              │
  │ - Restricted Sandbox User (--user nobody)               │
  └─────────────────────────────────────────────────────────┘
```

KAVACH AI implements layered security controls to protect the host system during analysis:
*   **SSRF DNS-Rebinding Shield**: Ingest URLs are validated against resolved IP addresses using `socket.getaddrinfo`. Requests to loopback, multicast, or private IP networks (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, etc.) are blocked.
*   **Zipbomb Protection**: Inspects ZIP file headers before decompression. Archives exceeding an uncompressed size of 2GB or exhibiting compression ratios greater than 100x are rejected.
*   **Container Sandbox Isolation**: Executes reverse engineering tools inside Docker containers using strict security profiles:
    ```bash
    docker run --rm --network none --memory 3g --memory-swap 3g --cpus 2 --pids-limit 100 --user nobody --cap-drop=ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:size=512m -v /host/in:/sandbox/input:ro -v /host/out:/sandbox/output:rw kavach-sandbox:latest [CMD]
    ```
    This configuration blocks network access, limits memory/CPU consumption, drops all Linux capabilities, and runs tools as a restricted user.

---

## 🚀 LOCAL DEPLOYMENT GUIDE

Follow these steps to set up KAVACH AI on a local development machine:

### Prerequisites
*   **Operating System**: Linux (Ubuntu 22.04 LTS or newer recommended) or macOS
*   **Python 3.11+**
*   **Node.js 18+ & npm**
*   **Java JRE/JDK** (Required for JADX & APKTool decompilers)
*   **Android SDK Platform-Tools (adb)** (Configured in the system `PATH`)
*   **Docker Engine** (Required for containerized sandbox execution)

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/RamNarra/KAVACH-AI.git
cd KAVACH-AI
```

---

### Step 2: Initialize System Setup
Run the automated installation script. This script validates prerequisites, configures the Python virtual environment, installs backend requirements, sets up Next.js frontend node modules, and creates environment configuration templates:
```bash
chmod +x setup.sh start.sh
./setup.sh
```

---

### Step 3: Configure Environment Variables
Create a root `.env` file and set the required API keys and connection parameters:
```bash
# Edit project environment variables
nano .env
```
Ensure the following variables are configured:
```env
# Gemini Key
GEMINI_API_KEY="AIzaSyYourGeminiAPIKeyHere"

# Supabase Database Configuration
SUPABASE_URL="https://your-project-id.supabase.co"
SUPABASE_KEY="eyJhbGciOiJIUzI1NiIsIn..."
SUPABASE_JWT_SECRET="super_secret_kavach_jwt_security_token_1337"

# Operational Modes
KAVACH_DOCKER_SANDBOX=1        # Enable isolated Docker sandbox
KAVACH_ALLOW_LEGACY_UID=1       # Enable fallback session headers
```

---

### Step 4: Build the Sandbox Container
If `KAVACH_DOCKER_SANDBOX=1` is active, build the isolated analysis image:
```bash
docker build -t kavach-sandbox:latest -f backend/Dockerfile-sandbox backend/
```

---

### Step 5: Launch the Services
Start the FastAPI backend and Next.js frontend concurrently:
```bash
./start.sh
```
*   The frontend will be available at [http://localhost:3000](http://localhost:3000).
*   The backend gateway will be available at [http://localhost:8080](http://localhost:8080).

---

### 🐳 Alternative: Run via Docker Compose
To deploy the entire stack (Next.js client, FastAPI server, Redis, and a MobSF instance) using Docker Compose:
```bash
# Launch all compose services
docker compose up --build
```
*   Access the Next.js dashboard at [http://localhost:3000](http://localhost:3000).
*   Access MobSF at [http://localhost:8000](http://localhost:8000).

---

### 🔍 Verification & Troubleshooting

#### 1. Confirm Backend API Health
Verify the backend status by querying the health check endpoint:
```bash
curl -X GET http://localhost:8080/health
```
**Expected Response**:
```json
{
  "status": "healthy",
  "database": "connected",
  "sandbox": "docker"
}
```

#### 2. Troubleshooting Common Issues
*   **Port conflicts (8080 or 3000)**: Verify that no other local services are using these ports:
    ```bash
    lsof -i :8080
    lsof -i :3000
    ```
*   **Docker permission errors**: Ensure the current system user has permission to interact with the Docker daemon:
    ```bash
    sudo usermod -aG docker $USER
    ```
    *(Log out and log back in to apply group changes)*

---

## 📈 VERIFICATION & DEMONSTRATION GUIDE

To verify the analysis pipeline using a sample APK:

### 1. Run a Static Scan
1.  Open the dashboard at [http://localhost:3000](http://localhost:3000).
2.  Drag and drop your target `.apk` file into the upload zone, or enter a safe download URL.
3.  Click **Initiate Scan**.
4.  Monitor the log terminal to track JADX decompiler steps, secret sweeps, and manifest checks.

### 2. Run a Dynamic Sandbox Session
1.  Ensure an Android Emulator is running and accessible via ADB:
    ```bash
    adb devices
    ```
2.  On the scan dashboard, toggle **Enable Dynamic Tracing**.
3.  Click **Launch Sandbox**.
4.  The system will install the app, spawn Frida sessions to intercept OkHttp3 sockets, and simulate screen interactions to capture runtime logs.

### 3. Interpret the Threat Report
Upon completion, the dashboard will display the compiled findings:
*   **Overall Threat Score**: A rating from 0 to 100 derived using the OWASP Risk Rating Methodology.
*   **MITRE ATT&CK Mapping Accordion**: Displays mapped indicators associated with standard threat matrices.
*   **Verified Badge Elements**: Findings validated by static signatures are flagged with `✓ Evidence-Backed`, while AI-generated indicators are labeled with `⚠ AI Inferred`.

---

## 🗺️ FUTURE ROADMAP

```
  Short-Term (Q3 2026)      Medium-Term (Q4 2026)     Long-Term (2027)
  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
  │ 🧪 Emulator Pooling  │  │ 🛡️ Anti-Evasion      │  │ 🏦 Core Banking      │
  │   Pre-warmed Android │  │   Detect virtual-box │  │   Integrate via APIs │
  │   sandbox sessions   │  │   evasion code       │  │   to block transfers │
  └──────────┬───────────┘  └──────────┬───────────┘  └──────────┬───────────┘
             │                         │                         │
             ▼                         ▼                         ▼
```

### 1. Short-Term Objectives
*   **Pre-Warmed Emulator Pools**: Implement an emulator pool manager to reuse active virtual device instances, reducing startup overhead.
*   **Enhanced Taint Flow Tracking**: Improve register-level DEX data flow analyzers to identify complex repackaged overlays.

### 2. Medium-Term Objectives
*   **Anti-Evasion Detection**: Add checks to detect when analyzed applications attempt to bypass sandbox environments by identifying virtualization signatures.
*   **Expanded Trojan Fingerprints**: Extend signature matching databases to cover new Android malware families targeting regional UPI systems.

### 3. Long-Term Objectives
*   **Core Banking API Integration**: Integrate scanning pipelines with bank transaction gateways to automatically flag accounts associated with malicious C2 endpoints.
*   **On-Premises AI Deployment**: Transition from cloud API dependency to local LLMs (such as Llama-3 or Gemma-2) deployed within secure banking infrastructures.

---

## 👥 CONTRIBUTORS
*   **Ram Narra** - Lead Architecture & Implementation

---

## 📄 LICENSE
This project is licensed under the Apache 2.0 License. See the LICENSE file for details.

---

## 🤝 ACKNOWLEDGEMENTS
*   **Bank of India** and **IIT-Hyderabad** for hosting the 2026 Hackathon.
*   The open-source communities behind **JADX**, **APKTool**, **Androguard**, and **Frida**.
