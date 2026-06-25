#!/usr/bin/env bash
# Move to the project root directory regardless of invocation path
cd "$(dirname "$0")/.."
# ============================================================
# KAVACH AI — Next.js Frontend Starter Script
# ============================================================

set -e

# ANSI styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}🛡️  Starting KAVACH AI Next.js Frontend...${NC}"
echo -e "${BLUE}============================================================${NC}"

# Read Root Environment Variables for API url configuration
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Kill any existing process bound to port 3000 to prevent port collisions
FRONTEND_PID_OLD=$(lsof -t -i:3000 || true)
if [ -n "$FRONTEND_PID_OLD" ]; then
    echo -e "  ⚠️ Terminating old frontend instance on port 3000 (PID: $FRONTEND_PID_OLD)..."
    kill -9 $FRONTEND_PID_OLD 2>/dev/null || true
    sleep 1
fi

cd frontend
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080 npm run dev
