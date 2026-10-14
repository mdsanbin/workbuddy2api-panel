@echo off
title WorkBuddy2API
cd /d "%~dp0"

if not exist "dist\wb2api.exe" (
  echo [ERROR] dist\wb2api.exe not found.
  echo Build it first:
  echo   go build -trimpath -ldflags="-s -w" -o dist/wb2api.exe ./cmd/server
  echo.
  pause
  exit /b 1
)

echo.
echo   WorkBuddy2API starting ...
echo.
echo   Panel : http://127.0.0.1:7863/panel/
echo   API   : http://127.0.0.1:7863/v1  (OpenAI compatible)
echo   Config: config.json  ^(api_key inside^)
echo.
echo   Press Ctrl+C to stop.
echo.

dist\wb2api.exe

echo.
echo Service stopped.
pause
