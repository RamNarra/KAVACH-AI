# Contributing to KAVACH AI 🛡️

Thank you for your interest in contributing to KAVACH AI! This project is built to automate mobile banking trojan sandboxing, reverse engineering, and risk scoring to keep customers safe.

To maintain engineering excellence and clean open-source standards, please follow these guidelines when submitting bug reports, feature requests, or pull requests (PRs).

---

## 🛠️ Codebase Standards

All additions to the codebase must align with our core design systems and architecture protocols:

1.  **Strict Security Controls**:
    *   Any endpoint accepting input URLs must apply `is_safe_ingest_url()` checks to prevent SSRF vulnerabilities.
    *   Process isolation via the `sandbox_runner` Docker wrapper must not be bypassed under any production configurations.
2.  **GIL & Concurrency Compliance**:
    *   Do not perform CPU-heavy blocking operations on the primary FastAPI asynchronous event loop thread. Wrap decompilation commands or bytecode processing inside thread-safe background runners.
3.  **TypeScript & Type Safety**:
    *   Avoid the use of `any` types in the Next.js frontend or untyped dictionary parses (`dict[str, Any]`) in critical backend logic where structured models can be defined instead.
4.  **Formatting & Linting**:
    *   **Backend (Python)**: Format code using `black` or `yapf` standards. Ensure all imports are sorted.
    *   **Frontend (TypeScript)**: Format code using `prettier` and check with `eslint`.

---

## 🔬 Development Workflow

### 1. Set Up Your Environment
Ensure system prerequisites are met (Python 3.11+, Node.js 18+, Java, ADB Platform-Tools). Then execute the installation scripts:
```bash
./setup.sh
```

### 2. Sandbox Container Setup
Always rebuild your local sandbox image after editing any analysis engines or decompiler tools:
```bash
docker build -t kavach-sandbox:latest -f backend/Dockerfile-sandbox backend/
```

### 3. Running Test Suites
Before opening a pull request, run pytest suites to verify that file-upload limits, rate limiters, and endpoint routers function as expected:
```bash
cd backend
source venv/bin/activate
pytest test_intelligence.py
deactivate
```

---

## 🚀 Pull Request Protocol

1.  **Branch Naming**:
    *   Features: `feature/your-feature-name`
    *   Bug fixes: `bugfix/issue-description`
    *   Security hardening: `security/vulnerability-patched`
2.  **Descriptive Commits**: Provide clear, descriptive commit messages. Do not squash structural changes without descriptive details.
3.  **PR Checklists**:
    *   [ ] Verify code passes all local automated tests.
    *   [ ] Confirm Docker sandbox limits function properly.
    *   [ ] Ensure no secrets (API keys, db passwords) are committed in configuration templates.
    *   [ ] Update relevant sections in the `README.md` if introducing new environment configuration variables.
