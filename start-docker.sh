#!/usr/bin/env bash
echo "=============================================================="
echo "  Building and Deploying Secure 3-Tier Application on Docker..."
echo "=============================================================="
docker compose up -d --build
echo ""
echo "Containers started! Access the application at http://localhost"
