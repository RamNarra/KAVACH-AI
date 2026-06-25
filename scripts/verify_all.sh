#!/bin/bash
# Consolidated verification script for KAVACH AI backend and frontend

set -o pipefail

PROJECT_ROOT="/home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH AI"
BACKEND_DIR="${PROJECT_ROOT}/backend"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"

PASSED_COUNT=0
FAILED_COUNT=0
FAILED_COMPONENTS=()

log_success() {
    echo -e "\e[32m[PASS]\e[0m $1"
    PASSED_COUNT=$((PASSED_COUNT + 1))
}

log_failure() {
    echo -e "\e[31m[FAIL]\e[0m $1"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FAILED_COMPONENTS+=("$1")
}

echo "=============================================="
echo "Starting KAVACH AI Code Verification"
echo "=============================================="

# --- 1. Backend Testing ---
echo "Running backend test suite (pytest)..."
cd "$BACKEND_DIR"

# Try to use virtualenv pytest, otherwise fallback to system pytest or python -m pytest
PYTEST_CMD="pytest"
if [ -f "venv/bin/pytest" ]; then
    PYTEST_CMD="venv/bin/pytest"
elif [ -f "../venv/bin/pytest" ]; then
    PYTEST_CMD="../venv/bin/pytest"
fi

if $PYTEST_CMD --version &>/dev/null; then
    if $PYTEST_CMD test_certificate_forensics.py test_intelligence.py; then
        log_success "Backend unit tests"
    else
        log_failure "Backend unit tests"
    fi
else
    # Fallback to python module
    if python3 -m pytest test_certificate_forensics.py test_intelligence.py; then
        log_success "Backend unit tests"
    else
        log_failure "Backend unit tests"
    fi
fi

# --- 1b. LLM Quality Evals ---
echo "Checking for GEMINI_API_KEY to run LLM Quality Evals..."
cd "$PROJECT_ROOT"
if [ -z "$GEMINI_API_KEY" ] && [ -f ".env" ]; then
    export GEMINI_API_KEY=$(grep -E "^GEMINI_API_KEY=" .env | cut -d'=' -f2- | tr -d '"' | tr -d "'")
fi

if [ -n "$GEMINI_API_KEY" ]; then
    echo "Running LLM Quality Evals..."
    if ./backend/venv/bin/python evals/run_evals.py; then
        log_success "LLM Quality Evals"
    else
        log_failure "LLM Quality Evals"
    fi
else
    echo "Skipping LLM Quality Evals (GEMINI_API_KEY not set)."
fi

# --- 2. Frontend Linting ---
echo "Running frontend linter (eslint)..."
cd "$FRONTEND_DIR"
if npm run lint; then
    log_success "Frontend lint checks"
else
    log_failure "Frontend lint checks"
fi

# --- 3. Frontend Compilation ---
echo "Running frontend production build (next build)..."
cd "$FRONTEND_DIR"
if npm run build; then
    log_success "Frontend compilation build"
else
    log_failure "Frontend compilation build"
fi

# --- 4. Final Verdict ---
echo "=============================================="
echo "Verification Summary:"
echo "Passed: $PASSED_COUNT, Failed: $FAILED_COUNT"
echo "=============================================="

if [ $FAILED_COUNT -eq 0 ]; then
    echo -e "\e[32mOverall Verdict: ALL CHECKS PASSED\e[0m"
    exit 0
else
    echo -e "\e[31mOverall Verdict: VERIFICATION FAILED\e[0m"
    echo "Failed components:"
    for component in "${FAILED_COMPONENTS[@]}"; do
        echo "  - $component"
    done
    exit 1
fi
