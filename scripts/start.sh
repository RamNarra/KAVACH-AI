#!/usr/bin/env bash
# Move to the project root directory regardless of invocation path
cd "$(dirname "$0")/.."
# ============================================================
# KAVACH AI — One-Command Startup Script
# ============================================================

# ANSI styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ensure we clean up background processes on exit
trap cleanup INT TERM EXIT

cleanup() {
  echo -e "\n${RED}🛑 Stopping KAVACH AI Services...${NC}"
  if [ -n "$BACKEND_PID" ]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [ -n "$FRONTEND_PID" ]; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  exit 0
}

echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}🛡️  Starting KAVACH AI Platform...${NC}"
echo -e "${BLUE}============================================================${NC}"

# Read Root Environment Variables
if [ -f ".env" ]; then
    echo -e "  Loading environment variables from root .env..."
    # Sync .env to backend to make sure it's up to date
    cp .env backend/.env
    export $(grep -v '^#' .env | xargs)
else
    echo -e "${RED}❌ Error: Root '.env' file not found. Run './setup.sh' first to create it.${NC}"
    exit 1
fi

# Start Backend Server
echo -e "\n${YELLOW}🚀 Starting FastAPI Backend Server on port 8080...${NC}"
cd backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8080 &
BACKEND_PID=$!
deactivate
cd ..

# Wait briefly for backend port binding
sleep 2

# Start Frontend Server
echo -e "\n${YELLOW}🚀 Starting Next.js Frontend Server on port 3000...${NC}"
cd frontend
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080 npm run dev &
FRONTEND_PID=$!
cd ..

echo -e "\n${GREEN}✓ Servers started successfully!${NC}"
echo -e "  - Frontend URL: ${BLUE}http://localhost:3000${NC}"
echo -e "  - Backend URL:  ${BLUE}http://localhost:8080${NC}"
echo -e "Press ${YELLOW}Ctrl+C${NC} to shut down both servers cleanly."
echo -e "${BLUE}============================================================${NC}"

# Keep script running to monitor logs
wait
