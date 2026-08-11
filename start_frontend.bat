@echo off
REM ============================================================
REM CPEDS-X Frontend - one-click start (Windows)
REM ============================================================
cd /d "%~dp0frontend"

echo [CPEDS-X] Installing npm dependencies (first run only)...
if not exist "node_modules" (
    call npm install
)

if not exist ".env" (
    copy .env.example .env >nul
    echo [CPEDS-X] Created .env pointing to http://localhost:8000
)

echo [CPEDS-X] Starting Vite dev server on http://localhost:5173 ...
call npm run dev

pause
