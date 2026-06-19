@echo off
title OSINT Search Engine - Portable Edition
color 0A
cls

echo.
echo  ======================================================
echo   OSINT LOG INTELLIGENCE PLATFORM v4.0 - PORTABLE
echo  ======================================================
echo.

REM 1. Check for local Python runtime folder in pendrive folder
set PYTHON=%~dp0python\python.exe
if exist "%PYTHON%" (
    echo  [OK] Using local portable Python environment...
    goto :run_server
)

REM 2. Check registry for PythonCore installation
set REG_KEY="HKLM\SOFTWARE\Python\PythonCore\3.13\InstallPath"
reg query %REG_KEY% /ve >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=2*" %%a in ('reg query %REG_KEY% /ve ^| findstr "REG_SZ"') do (
        set PYTHON=%%bpython.exe
        if exist "%PYTHON%" goto :run_server
    )
)

REM 3. Try standard Python in PATH
where python >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON=python
    goto :run_server
)

REM 4. Try py launcher
where py >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON=py
    goto :run_server
)

echo  [ERROR] Python was not found on this system!
echo.
echo  For complete zero-dependency portability on USB drives:
echo  Please copy an embeddable Python folder to: "%~dp0python"
echo.
echo  Or install Python globally from https://python.org
echo.
pause
exit /b 1

:run_server
echo  [OK] Python found: "%PYTHON%"
echo  [OK] Initializing log database directory...
if not exist "%~dp0database" mkdir "%~dp0database"
echo  [OK] Starting search engine server...
echo  [>>] Browser will open in ~2 seconds...
echo.
echo  ======================================================
echo   Press Ctrl+C inside this terminal window to stop
echo  ======================================================
echo.

cd /d "%~dp0"
"%PYTHON%" server.py

echo.
echo  [!] Server stopped.
pause
