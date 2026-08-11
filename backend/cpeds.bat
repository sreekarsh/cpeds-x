@echo off
REM ====================================================================
REM  CPEDS-X launcher  ->  type `cpeds <command>` from your terminal.
REM
REM  Runs the in-process CLI (cli.py) with the project's virtual-env
REM  Python. Microsoft Store Python has no activate script, so we call
REM  the venv interpreter directly by absolute path.
REM
REM  Use it two ways:
REM    * from this folder:      cpeds simulate 2
REM    * from anywhere:         add this "backend" folder to your PATH,
REM                             then `cpeds ...` works in any directory.
REM
REM  %~dp0 = the folder THIS .bat lives in (backend\), with a trailing \.
REM  We pass cli.py by absolute path but DO NOT change your working
REM  directory, so relative log paths (e.g. `cpeds analyze trail.json`)
REM  resolve against wherever you are.
REM ====================================================================
setlocal
set "CPEDS_PY=%~dp0.venv\Scripts\python.exe"
if not exist "%CPEDS_PY%" (
  echo [cpeds] project venv not found at "%CPEDS_PY%" - falling back to system python 1>&2
  set "CPEDS_PY=python"
)
"%CPEDS_PY%" "%~dp0cli.py" %*
