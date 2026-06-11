#!/usr/bin/env bash
# ============================================================
# KAVACH AI — One-Command Setup & Installation Script
# ============================================================
set -e

# ANSI styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}🛡️  KAVACH AI — Initializing Setup Sequence...${NC}"
echo -e "${BLUE}============================================================${NC}"

# Check for Prerequisites
echo -e "\n${YELLOW}[Step 1/4] Checking System Prerequisites...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Error: python3 is not installed.${NC}"
    exit 1
fi
echo -e "  ✓ python3 found: $(python3 --version)"

if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Error: node (Node.js) is not installed.${NC}"
    exit 1
fi
echo -e "  ✓ node found: $(node --version)"

if ! command -v npm &> /dev/null; then
    echo -e "${RED}❌ Error: npm is not installed.${NC}"
    exit 1
fi
echo -e "  ✓ npm found: $(npm --version)"

if ! command -v java &> /dev/null; then
    echo -e "${YELLOW}⚠️  Warning: java (JRE) is missing. Static decompilers (JADX, APKTool) may not execute correctly without it.${NC}"
else
    echo -e "  ✓ java found: $(java -version 2>&1 | head -n 1)"
fi

if ! command -v adb &> /dev/null; then
    echo -e "${YELLOW}⚠️  Warning: adb is missing. Guest Android sandboxing will require adb on your system PATH.${NC}"
else
    echo -e "  ✓ adb found: $(adb --version | head -n 1)"
fi

# Setup Virtual Environment and Backend Dependencies
echo -e "\n${YELLOW}[Step 2/4] Initializing Python Virtual Environment & Backend dependencies...${NC}"
cd backend
if [ ! -d "venv" ]; then
    echo -e "  Creating virtual environment (venv)..."
    python3 -m venv venv
fi

echo -e "  Activating virtual environment and updating pip..."
source venv/bin/activate
pip install --upgrade pip

echo -e "  Installing requirements.txt (this may take a minute)..."
pip install -r requirements.txt
deactivate
cd ..

# Setup Frontend Packages
echo -e "\n${YELLOW}[Step 3/4] Installing Frontend Dependencies...${NC}"
cd frontend
echo -e "  Running npm install..."
npm install
cd ..

# Copy Environment Configurations
echo -e "\n${YELLOW}[Step 4/4] Configuring Environment Variables...${NC}"
if [ ! -f ".env" ]; then
    echo -e "  Copying .env.example to .env..."
    cp .env.example .env
    echo -e "  Copying .env.example to backend/.env..."
    cp .env.example backend/.env
    echo -e "${YELLOW}📝 Action Required: Please open the newly created '.env' file in the root directory and set your API keys.${NC}"
else
    echo -e "  ✓ Root .env file already exists."
    if [ ! -f "backend/.env" ]; then
         cp .env backend/.env
         echo -e "  ✓ Synced .env to backend/.env"
    fi
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}🎉 Setup Completed Successfully!${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "To start the application, configure your keys in the root '.env' file, and run:"
echo -e "  ${YELLOW}./start.sh${NC}"
echo -e "${BLUE}============================================================${NC}"
