#!/bin/bash
# Script to incrementally update the Graphify codebase knowledge graph

set -e

PROJECT_ROOT="/home/p4cketsn1ff3r/Downloads/Projects_and_Development/Source_Code_and_Notebooks/Projects/KAVACH AI"

echo "Checking Graphify installation..."
if ! command -v graphify &> /dev/null; then
    echo "Graphify CLI not found in PATH."
    echo "Attempting to run via uv tool..."
    if command -v uv &> /dev/null; then
        uv tool run graphify .
    else
        echo "Error: Neither graphify nor uv is available."
        exit 1
    fi
else
    echo "Starting Graphify codebase mapping..."
    start_time=$(date +%s)
    
    # Run graphify extraction/update
    graphify .
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "Graphify mapping completed successfully in ${duration} seconds!"
    echo "Knowledge graph output generated in graphify-out/"
fi
