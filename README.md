<div align="center">
  <img src="https://img.shields.io/badge/Security-Critical-red?style=for-the-badge&logo=shield" alt="Security" />
  <img src="https://img.shields.io/badge/AI-Generative-purple?style=for-the-badge&logo=google-gemini" alt="GenAI" />
  <img src="https://img.shields.io/badge/Framework-Next.js-black?style=for-the-badge&logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" />
</div>

<h1 align="center">🛡️ KAVACH AI</h1>

<p align="center">
  <strong>Generative AI-Based APK Malware Analysis & Threat Auditing System</strong>
</p>

Kavach AI is an automated, AI-driven malware analysis system for Android applications (`.apk`). It statically decompiles Android packages, extracts critical security-sensitive code blocks, and leverages **Google GenAI (Gemini 3.5 Flash)** to perform a complex threat audit—returning a structured JSON risk scorecard to a sleek Next.js UI.

---

## ✨ Features

- 🧠 **AI-Powered Threat Audits**: Employs Gemini 3.5 Flash for deep static analysis of code behaviors.
- 🏦 **Banking Fraud Intelligence**: Dedicated fraud score and badges (SMS stealer, overlay, UPI targeting, credential exfil).
- 🎯 **MITRE ATT&CK Mapping**: Mobile technique tags on static and fraud findings.
- 📊 **Explainable Risk Decomposition**: Static / dynamic / AI / fraud weighted breakdown.
- 🔬 **Dynamic Sandbox**: Frida instrumentation with runtime findings and trigger playbooks.
- 💬 **AI Analyst Chat**: Follow-up Q&A on completed reports (`POST /api/chat`).
- 📄 **Report Export**: Text executive report download (`GET /api/analysis/{id}/report`).
- 📦 **Automated Decompilation**: Uses `apktool` and `jadx` to extract `.class` and `.dex` bytecode right inside the Cloud Run environment.
- ⚡ **Real-Time Next.js Frontend**: Sleek dashboard featuring fake-terminal progress loaders, AI synthesis panels, findings grids, and historical run sidebars powered by Firebase Firestore.
- 🔐 **Robust Security Gating**: Enforces Google Cloud Storage lifecycle hygiene and strict Firebase security rules for authenticated-only access.
- 🚀 **Serverless Scalability**: Dockerized FastAPI container carefully tuned for high-memory JVM tasks, deployed to GCP Cloud Run.

---

## 🏗️ Technical Architecture

- **Frontend**: Next.js App Router (Tailwind CSS, React, Lucide Icons) deployed as a static site to Firebase Hosting.
- **Backend**: Python FastAPI service running in a custom Docker container (including JRE, APKTool, and JADX) deployed on GCP Cloud Run.
- **Routing**: In production, Firebase Hosting rewrite rules map all `/api/**` traffic from the client-side origin to the GCP Cloud Run service (`kavach-api`). This guarantees a single-origin policy, avoiding complex CORS setups in production and keeping calls clean.

---

## 🛠️ Google Cloud API Enablement

Before running backend code or deploying, ensure the required APIs are enabled on your Google Cloud project:

```bash
gcloud services enable aiplatform.googleapis.com \
                        run.googleapis.com \
                        cloudbuild.googleapis.com \
                        artifactregistry.googleapis.com
```

---

## 💻 Local Development Workflow

Ensure you have Python 3.11+, Java (JRE), `apktool`, and `jadx` installed locally on your system path.

### 1. Run the Python Backend Locally
Start the backend server using the standard uvicorn launcher:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Local dev without Firebase token middleware:
export DISABLE_AUTH=1
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```
Upon startup, FastAPI automatically triggers the **Dynamic Sandbox Bootstrapper** in the background:
- It checks if the Android Virtual Device (`kavach_sandbox`) is running. If not, it launches it headlessly.
- It automatically deploys and starts the matching **Frida Server-16** on the emulator.
- You can monitor the live bootstrap state at `/api/sandbox-health`.
- If the emulator/Frida setup is offline, the backend degrades gracefully to static-only reports.

### 2. Run the Next.js Frontend Locally
Create `frontend/.env.local`:
```text
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080
```
Then start the server:
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) to view the application interface.

---

## ☁️ Production Deployment Steps

### 1. Deploy the Backend to GCP Cloud Run
Deploy the FastAPI backend directly from source. Cloud Run will build the custom `Dockerfile`:

```bash
cd backend
gcloud run deploy kavach-api \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 4Gi \
  --cpu 2 \
  --timeout 180 \
  --concurrency 8 \
  --set-env-vars PROJECT_ID=kavach-ai-497708,LOCATION=global,MODEL_NAME=gemini-3.5-flash
```

> [!WARNING]
> Running JADX decompilation is heavily CPU/memory-intensive. Default Cloud Run settings (512MB RAM, 1 vCPU) will result in immediate **Out Of Memory (OOM) crashes**. We configure the runtime with at least **4GB RAM, 2 vCPUs**, and restrict concurrency to **8**.

### 2. Deploy the Next.js Frontend to Firebase Hosting
```bash
cd frontend
npm run build
cd ..
firebase deploy --only hosting,firestore,storage
```

---

## 🧹 Cost Control & Cleanup

- **Immediate Deletion**: Configured out-of-the-box inside the FastAPI server.
- **Orphan Cleanup**: Run the cleanup script to remove stale APKs older than 10 minutes:
  ```bash
  python ops/cleanup_orphan_apks.py
  ```
- **Safety Fallback**: Apply the safety fallback lifecycle rule to delete any remaining files older than 1 day:
  ```bash
  gcloud storage buckets update gs://kavach-ai-497708.firebasestorage.app --lifecycle-file=ops/storage-lifecycle.json
  ```

---
<div align="center">
  Built with ❤️ for Security Automation
</div>
