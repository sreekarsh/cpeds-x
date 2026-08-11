@echo off
REM ============================================================
REM CPEDS-X Backend - one-click start (Windows)
REM ============================================================
cd /d "%~dp0backend"

echo [CPEDS-X] Setting up Python virtual environment...
if not exist ".venv" (
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo [CPEDS-X] Installing dependencies (first run only, ~2-3 min)...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt

echo [CPEDS-X] Starting FastAPI server on http://localhost:8000 ...
echo [CPEDS-X] API docs: http://localhost:8000/docs
uvicorn main:app --reload --port 8000

pause
