@echo off
cd /d "%~dp0"
rem Builds the engine and the UI into dist\ and signs them; extra arguments go to scripts\publish.ps1 (e.g. -SkipSign).
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\publish.ps1 %* || exit /b 1
