@echo off
:: Benign dropper simulation for telemetry testing.
:: Actions: writes a file to APPDATA, adds a fake Run key, spawns notepad.exe.
:: All actions are harmless and leave no real persistence.

setlocal EnableDelayedExpansion

set PAYLOAD_DIR=%LOCALAPPDATA%\SandboxTelemetry
set PAYLOAD_FILE=%PAYLOAD_DIR%\benign_payload.exe
set REG_PATH=HKCU\Software\Microsoft\Windows\CurrentVersion\Run
set REG_VALUE=SandboxTelemetryTest

echo [dropper] creating payload directory: %PAYLOAD_DIR%
if not exist "%PAYLOAD_DIR%" mkdir "%PAYLOAD_DIR%"

echo [dropper] writing fake payload file
echo This is a benign test file used to generate sandbox telemetry. > "%PAYLOAD_FILE%"

echo [dropper] adding fake Run key for persistence telemetry
reg add "%REG_PATH%" /v "%REG_VALUE%" /t REG_SZ /d "%PAYLOAD_FILE%" /f >nul

echo [dropper] spawning child process: notepad.exe
start "" notepad.exe "%PAYLOAD_FILE%"

echo [dropper] sleeping 3 seconds, then cleaning up
ping -n 4 127.0.0.1 >nul

echo [dropper] removing fake Run key
reg delete "%REG_PATH%" /v "%REG_VALUE%" /f >nul 2>&1

echo [dropper] removing payload file
if exist "%PAYLOAD_FILE%" del "%PAYLOAD_FILE%" /f /q

echo [dropper] stopping spawned notepad.exe
taskkill /f /im notepad.exe >nul 2>&1

echo [dropper] done
