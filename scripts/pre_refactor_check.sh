#!/bin/bash
# Pre-refactor graph freshness check script

set -e

PROJECT_ROOT="/home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH AI"
UPDATE_SCRIPT="${PROJECT_ROOT}/scripts/update_graph.sh"
QUERY_SCRIPT="${PROJECT_ROOT}/scripts/project_query.sh"

echo "=============================================="
echo "Starting Pre-Refactor Codebase Graph Validation"
echo "=============================================="

# 1. Update Graphify Graph
echo "Step 1: Refreshing the codebase knowledge graph..."
if [ -f "$UPDATE_SCRIPT" ]; then
    "$UPDATE_SCRIPT"
else
    echo "Error: update_graph.sh not found at $UPDATE_SCRIPT"
    exit 1
fi

# 2. Run graphify cluster-only to generate reports
echo "Step 2: Generating community report..."
if command -v graphify &> /dev/null; then
    graphify cluster-only .
else
    uv tool run graphify cluster-only .
fi

# 3. Verify Graph Freshness with core queries
echo "Step 3: Verifying graph query response for core components..."
CORE_SYMBOLS=("DatabaseManager" "run_analysis_pipeline" "analyze_mobsf")

for symbol in "${CORE_SYMBOLS[@]}"; do
    echo "----------------------------------------------"
    echo "Querying graph for: $symbol"
    if ! "$QUERY_SCRIPT" "$symbol" --budget 1000 > /dev/null; then
        echo "Error: Graph query failed for symbol '$symbol'"
        exit 1
    else
        echo "Success: Symbol '$symbol' resolved in knowledge graph."
    fi
done

echo "=============================================="
echo "Pre-Refactor Check: SUCCESS"
echo "Knowledge graph is active, fresh, and queryable."
echo "=============================================="
exit 0
