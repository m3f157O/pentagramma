#!/usr/bin/env pwsh
# Start the Hyper-V sandbox orchestrator.

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

# Activate virtual environment if present
$venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython -m uvicorn orchestrator.main:app --host 127.0.0.1 --port 18000
}
else {
    python -m uvicorn orchestrator.main:app --host 0.0.0.0 --port 8000
}
