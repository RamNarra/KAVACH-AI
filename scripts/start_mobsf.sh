#!/usr/bin/env bash
# Move to the project root directory regardless of invocation path
cd "$(dirname "$0")/.."
# ============================================================
# KAVACH AI — MobSF Docker Starter Script
# ============================================================

set -e

# ANSI styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}🐳 Launching MobSF Docker Container for Kavach AI...${NC}"
echo -e "${BLUE}============================================================${NC}"

# 1. Load Root Environment Variables
if [ -f ".env" ]; then
    echo -e "  Loading environment variables from root .env..."
    export $(grep -v '^#' .env | xargs)
else
    echo -e "${RED}❌ Warning: Root '.env' file not found. Using defaults.${NC}"
fi

MOBSF_IDENTIFIER="${MOBSF_ANALYZER_IDENTIFIER:-host.docker.internal:5556}"
echo -e "  - MobSF API Key:             ${GREEN}${MOBSF_API_KEY:-[Not Configured]}${NC}"
echo -e "  - Target Emulator IP/Port:   ${GREEN}${MOBSF_IDENTIFIER}${NC}"

# 2. Check Docker command availability
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: docker command not found. Please install Docker Engine first.${NC}"
    exit 1
fi

# 3. Detect if we need sudo for Docker
DOCKER_CMD="docker"
if ! docker ps &> /dev/null; then
    echo -e "  ${YELLOW}⚠️  Docker permissions check failed. Escalating to 'sudo'...${NC}"
    DOCKER_CMD="sudo docker"
fi

# 4. Start Docker Containers
echo -e "\n${YELLOW}🚀 Starting PostgreSQL, Redis, and MobSF services via docker compose...${NC}"
$DOCKER_CMD compose up -d postgres redis mobsf

# 5. Output Access Details
echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}🎉 MobSF Docker Container is now Running!${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "  - Web Interface:  ${BLUE}http://localhost:8000${NC}"
echo -e "  - API Endpoint:   ${BLUE}http://localhost:8000/api/v1/${NC}"
echo -e "  - Dynamic target: ${GREEN}${MOBSF_IDENTIFIER}${NC}"
echo -e "\nVerify connection by uploading an APK at [http://localhost:8000] and"
echo -e "initiating the dynamic analyzer."
echo -e "${BLUE}============================================================${NC}"
