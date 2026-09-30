@echo off
title ScamShield Backend
echo.
echo  ============================================
echo   ScamShield Backend Startup
echo  ============================================
echo.
echo  Installing dependencies...
pip install -r requirements.txt
echo.
echo  Starting API server at http://localhost:8000
echo  API docs available at  http://localhost:8000/docs
echo.
echo  Press CTRL+C to stop the server.
echo.
uvicorn main:app --reload --host 0.0.0.0 --port 8000
pause
