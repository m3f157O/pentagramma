@echo off
rem build_loadlib_x86.cmd -- compile the WoW64 LoadLibraryW VA helper (x86).
rem Output: agent\windows\guardian_loadlib_x86.exe (shipped to the guest with
rem the rest of agent\windows and run once by guardian_agent.py at startup).
setlocal
set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -find VC\Auxiliary\Build\vcvarsamd64_x86.bat`) do set VCVARS=%%i
if not defined VCVARS (echo [build] vcvarsamd64_x86.bat not found & exit /b 1)
call "%VCVARS%" >nul 2>&1
set SRC=%~dp0guardian_loadlib_x86.c
set OUT=%~dp0..\guardian_loadlib_x86.exe
cl /O2 /W3 /nologo "%SRC%" /Fe"%OUT%" /Fo"%~dp0guardian_loadlib_x86.obj" /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (echo [build] FAILED & exit /b 1)
echo [build] OK -^> %OUT%
