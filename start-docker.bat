@echo off
title Secure 3-Tier Web Application - Docker Deployment
echo ==============================================================
echo   Building and Deploying Secure 3-Tier Application on Docker...
echo ==============================================================
docker compose up -d --build
echo.
echo Containers started!
echo Open http://localhost in your browser.
pause
