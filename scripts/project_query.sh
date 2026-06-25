#!/bin/bash
# Script to query the Graphify knowledge graph

if [ -z "$1" ]; then
    echo "Usage: $0 \"<query_phrase>\" [--dfs] [--budget <tokens>]"
    echo "Example: $0 \"Where are backend routes registered?\""
    exit 1
fi

echo "Querying Graphify knowledge graph..."
if command -v graphify &> /dev/null; then
    graphify query "$@"
else
    uv tool run graphify query "$@"
fi
