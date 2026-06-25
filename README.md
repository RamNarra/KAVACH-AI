# 🛡️ KAVACH AI

[![CI Status](https://github.com/RamNarra/KAVACH-AI/actions/workflows/ci-main.yml/badge.svg)](https://github.com/RamNarra/KAVACH-AI/actions/workflows/ci-main.yml)
[![Docker Image Status](https://github.com/RamNarra/KAVACH-AI/actions/workflows/publish-docker.yml/badge.svg)](https://github.com/RamNarra/KAVACH-AI/actions/workflows/publish-docker.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An intelligent, multi-layered mobile application vulnerability scanning and threat analysis platform.

---

## 📸 Demo & Screenshots

### Security Analysis Dashboard
![KAVACH AI Dashboard](assets/readme/boi_logo_reversed.png)
*Figure 1: The primary dashboard displaying threat score breakdowns, certificate forensic logs, and dynamic analysis findings.*

---

## 📌 Table of Contents
1. [Overview](#-overview)
2. [Features](#-features)
3. [Architecture](#-architecture)
4. [Folder Structure](#-folder-structure)
5. [Quickstart & Installation](#-quickstart--installation)
6. [Usage Guide](#-usage-guide)
7. [Docker Registry (GHCR) Usage](#-docker-registry-ghcr-usage)
8. [Tech Stack](#-tech-stack)
9. [Contributing & License](#-contributing--license)

---

## 🔍 Overview

KAVACH AI is a next-generation security suite designed to detect malware, vulnerabilities, and banking fraud flags inside Android application packages (APKs). It utilizes a multi-tiered inspection pipeline (combining AST code extraction, machine learning classification, and dynamic sandbox telemetry) to assess threat levels accurately and generate deterministic vulnerability scores.

---

## 🚀 Features

*   **Static Code Autopsy**: Decompiles DEX files using Jadx/Apktool to extract class-level structures and identify hidden API calls.
*   **Dynamic Sandbox Telemetry**: Automatically runs APK files inside a secure Android Virtual Device (AVD) using Frida hooks to trace live network, filesystem, and encryption APIs.
*   **YARA Evasion Detection**: Employs custom YARA signatures to detect root-cloaking, anti-emulation, and runtime packing tricks.
*   **Machine Learning Classifier**: Utilizes a trained random forest model to classify malicious APK behaviour flags.
*   **Project Intelligence Layer**: Uses a Graphify codebase knowledge graph and structured local skills to keep developer operations token-efficient and safe.

---

## 🏛️ Architecture

KAVACH AI is organized as a decoupled monorepo:

```
+-----------------------------------+
|       React / Next.js UI          |  <-- Port 3000
+-----------------+-----------------+
                  |
                  | FastAPI REST requests
                  v
+-----------------+-----------------+
|      FastAPI Backend Engine       |  <-- Port 8080 (Dockerized)
+--------+--------+--------+--------+
         |        |        |
         |        |        | Celery Tasks / Redis
         v        v        v
    +----+----+ +-+--+ +---+----+
    | Static  | | ML | | Frida  |
    | (Jadx)  | | RF | | Sandbox|
    +---------+ +----+ +--------+
```

---

## 📁 Folder Structure

```
kavach-ai/
├── backend/            # FastAPI source code, requirements, and analysis engines
├── frontend/           # Next.js React client source, package.json, and UI layouts
├── scripts/            # DevOps helpers (setup, startup, graph update, local verification)
├── .github/            # GitHub Actions CI pipelines and Docker publishing workflows
├── Dockerfile          # Root Dockerfile for containerizing the main FastAPI API service
├── docker-compose.yml  # Multi-container orchestration (Redis, Postgres, MobSF, Backend)
├── LICENSE             # Apache 2.0 license file
└── README.md           # The primary platform face
```

---

## 🛠️ Quickstart & Installation

### Prerequisites
- Docker & Docker Compose
- Python 3.12+ (for local backend runs)
- Node.js 20+ & npm (for local frontend runs)

### Local Environment Setup
1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/RamNarra/KAVACH-AI.git
    cd KAVACH-AI
    ```
2.  **Run One-Command Setup**:
    ```bash
    ./scripts/setup.sh
    ```
    This script initializes python virtual environments, installs npm packages, and creates `.env` configurations.

3.  **Run Locally**:
    ```bash
    ./scripts/start.sh
    ```
    Access the UI at `http://localhost:3000` and the API at `http://localhost:8080`.

---

## 🐳 Docker Registry (GHCR) Usage

KAVACH AI backend is published as a pre-built Docker image to GitHub Container Registry (GHCR).

### Running via Docker Compose
To boot the full system including PostgreSQL, Redis, MobSF and the API server, simply run:
```bash
docker compose up -d
```

### Direct Package Pull
Pull the official production backend image:
```bash
docker pull ghcr.io/ramnarra/kavach-backend:latest
```

Run the container stand-alone:
```bash
docker run -d -p 8080:8080 \
  -e GEMINI_API_KEY="your-api-key" \
  -e MOBSF_API_KEY="your-mobsf-key" \
  ghcr.io/ramnarra/kavach-backend:latest
```

---

## 💻 Tech Stack

*   **Frontend**: Next.js 16 (App Router), TypeScript, React 19, Material UI, Framer Motion.
*   **Backend**: Python 3.12, FastAPI, Celery, Uvicorn.
*   **Database & Broker**: PostgreSQL 17, Redis, SQLAlchemy.
*   **Security Analysis**: MobSF API, Androguard, Quark Engine, Yara-Python, Frida.

---

## 📄 License & Contributing

Licensed under the [Apache License 2.0](LICENSE). For issues or security reports, please contact the maintainers.
