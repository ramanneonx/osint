@echo off
title OSINT Log Profiler - Portable Edition
color 0D
cls

echo.
echo  ======================================================
echo   OSINT LOG PROFILER & ANALYZER v1.0 - PORTABLE
echo  ======================================================
echo.

REM 1. Check for local Python runtime folder in current folder
set PYTHON=%~dp0python\python.exe
if exist "%PYTHON%" (
    echo  [OK] Using local portable Python environment...
    goto :run_profiler
)

REM 2. Check registry for PythonCore installation
set REG_KEY="HKLM\SOFTWARE\Python\PythonCore\3.13\InstallPath"
reg query %REG_KEY% /ve >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=2*" %%a in ('reg query %REG_KEY% /ve ^| findstr "REG_SZ"') do (
        set PYTHON=%%bpython.exe
        if exist "%PYTHON%" goto :run_profiler
    )
)

REM 3. Try standard Python in PATH
where python >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON=python
    goto :run_profiler
)

REM 4. Try py launcher
where py >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON=py
    goto :run_profiler
)

echo  [ERROR] Python was not found on this system!
echo  Please ensure Python is installed or place a portable Python folder at: "%~dp0python"
echo.
pause
exit /b 1

:run_profiler
echo  [OK] Python found: "%PYTHON%"
echo  [OK] Initializing database directories...
if not exist "%~dp0database" mkdir "%~dp0database"
echo  [OK] Starting profiler server...
echo  [>>] Browser will open in ~2 seconds...
echo.
echo  ======================================================
echo   Press Ctrl+C inside this terminal window to stop
echo  ======================================================
echo.

cd /d "%~dp0"
"%PYTHON%" profiler_server.py

echo.
echo  [!] Profiler server stopped.
pause
