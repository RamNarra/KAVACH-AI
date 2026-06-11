<div align="center">
  <img src="https://img.shields.io/badge/Security-Research--Prototype-red?style=for-the-badge&logo=shield" alt="Security" />
  <img src="https://img.shields.io/badge/AI-Multi--Tier--Resilient-purple?style=for-the-badge&logo=google-gemini" alt="GenAI" />
  <img src="https://img.shields.io/badge/Framework-Next.js--16-black?style=for-the-badge&logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" />
</div>

<h1 align="center">🛡️ KAVACH AI</h1>

<p align="center">
  <strong>Generative AI-Powered Mobile Banking Trojan Sandbox & Explainable Threat Auditing System</strong>
</p>

Kavach AI is an automated Android malware-analysis platform for `.apk` samples. It statically decompiles Android packages in a concurrent pipeline, injects Frida hooks at runtime for sandbox traces, and utilizes Google Gemini synthesis to turn complex bytecode and dynamic trace evidence into readable bank security investigation reports.

---

## ✨ Core Highlights & Capabilities

- 🏦 **Calibrated Banking Fraud Intelligence**: Dedicated scoring model representing mobile banking trojans. Uses the average formula `((BFL + BFI) / 2) * 10` for stable, non-alarmist rating scaling that isolates SMS interceptors, Accessibility API hijacking, screen overlay theft, and dynamic keyloggers.
- 🎯 **MITRE ATT&CK Mapping**: Deep semantic code auditing (Quark Engine + Androguard DEX constant tables) dynamically maps found triggers to the standard MITRE ATT&CK Mobile matrix.
- 🔬 **OkHttp3/Retrofit Decoupled Telemetry**: Standard socket tracing hooks only capture raw encrypted binary streams. Kavach AI injects custom Frida hooks targeting `okhttp3.RealCall.enqueue` and `execute` methods to capture fully decrypted HTTP/JSON outbound payloads before TLS transport.
- 🔑 **Dynamic User Gemini Keys**: Seamlessly switches to the user's custom API key (pasted in Settings or during registration) on the fly without restarting backend or frontend instances. Automatically falls back to the system's default API key when none is supplied.
- 🛡️ **AI-Findings Cross-Validation Engine**: Cross-references Gemini-generated threat narratives against deterministic static/dynamic scan telemetry. Findings are dynamically labeled with premium UI badges: `✓ Evidence-Backed` (green badge for signature-confirmed findings) and `⚠ AI Inferred` (yellow badge for speculative GenAI observations).
- 🧠 **Resilient Sandbox Spawner & Fallback Chain**: Engineered to survive virtualization lag on modern hypervisors. If the primary model `gemini-3.5-flash` fails, the GenAI client automatically tries the next model in a sequential fallback chain:
  1. `gemini-3.5-flash`
  2. `gemini-3.1-flash-lite`
  3. `gemini-3.1-pro`
  4. `gemini-2.5-flash`
  5. `gemini-2.5-pro`
  6. `gemini-2.0-flash`

---

## 🛠️ Instant Setup & Replication Guide (Multi-PC Migration)

Follow these simple steps to replicate the complete KAVACH AI development and testing environment on any machine.

### Prerequisites
Ensure the following packages are installed on your target machine:
- **Python 3.11+**
- **Node.js 18+ & npm**
- **Java JRE/JDK** (required by JADX & APKTool decompilers)
- **Android SDK Platform-Tools (adb)** (added to your system `PATH`)

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/RamNarra/KAVACH-AI.git
cd KAVACH-AI
```

### Step 2: Run Setup Script
Run the automated installation script. This checks your system prerequisites, builds a Python virtual environment with all required static analysis and Frida dependencies, installs Next.js frontend node modules, and creates environment configuration templates:
```bash
./setup.sh
```

### Step 3: Populate environment variables
Open the newly created `.env` file at the root of the project and populate it with your Google GenAI, Supabase, and optional VirusTotal credentials:
```bash
# Open and edit
nano .env
```

### Step 4: Run Application
Start both the FastAPI backend and Next.js frontend concurrently with a single command:
```bash
./start.sh
```
*Your frontend will be accessible at [http://localhost:3000](http://localhost:3000) and the backend API at [http://localhost:8080](http://localhost:8080).*

---

## 🐳 Self-Hosting via Docker Compose

Alternatively, spin up the entire pre-configured ecosystem (Next.js + FastAPI decompiler backend) inside a single command using Docker:

```bash
# Create root dotenv file
echo "GEMINI_API_KEY=your_gemini_api_key_here" > .env

# Build and launch compose services
docker compose up --build
```
*Access the Next.js dashboard at [http://localhost:3000](http://localhost:3000) (backend mounts on `http://localhost:8080`).*

---

<div align="center">
  Built with ❤️ for High-Fidelity Security Automation & Banking Protection
</div>
