@echo off
setlocal
cd /d "%~dp0"

echo.
echo  SentinelStream Local Prototype
echo  ------------------------------
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found.
  echo Install Node.js LTS from https://nodejs.org/ and run this file again.
  echo.
  pause
  exit /b 1
)

if not exist node_modules (
  echo Installing dependencies for the first run...
  call npm install
  if errorlevel 1 (
    echo.
    echo Dependency installation failed. Check your internet connection and try again.
    pause
    exit /b 1
  )
)

echo Starting the dashboard at http://localhost:3000/
echo Press Ctrl+C to stop the server.
echo.
call npm run dev
pause
