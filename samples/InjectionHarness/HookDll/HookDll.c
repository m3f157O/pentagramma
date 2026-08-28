// HookDll.dll — minimal WH_GETMESSAGE hook DLL for the InjectionHarness
// SetWindowsHookEx test (#12, PLAN.md Phase 2). Its only job is to export a
// valid hook callback so user32 will map this DLL into the hooked process
// when a message arrives (that remote load is the telemetry signal).
//
// Rebuild (from a VS2022 developer prompt or after vcvars64.bat):
//   cl /LD /O1 /nologo HookDll.c /Fe:HookDll.dll user32.lib
#include <windows.h>

__declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule; (void)reason; (void)reserved;
    return TRUE;
}
