@echo off
REM Tier-1 hook validation: benign activity that should produce
REM LdrLoadDll / NtDelayExecution / BCryptHashData apitrace events
REM without firing any of the new behavioral signatures.
certutil -hashfile C:\Windows\notepad.exe SHA256
timeout /t 3 /nobreak >nul
echo tier1-hooks-ok
