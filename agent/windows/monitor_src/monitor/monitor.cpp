// Sandbox behavioral monitor DLL (Track 3.1 core hookset).
//
// Injected into a sample (and, later, its children -- Track 3.2) by
// monitor_loader.exe. On load it connects to the collector's named pipe,
// installs in-line hooks via MinHook, and streams one newline-delimited JSON
// event per intercepted call: {"api","category","pid","tid","arg0"}.
//
// Hookset (all at the ntdll CHOKE-POINT layer wherever one exists, so a
// higher-level Win32 wrapper bypass still gets caught -- proven in bring-up:
// cmd's `copy` never called kernel32!CreateFileW, only ntdll!NtCreateFile):
//   file       : kernel32!CreateFileW, kernel32!CreateProcessW, ntdll!NtCreateFile
//   memory     : ntdll!NtAllocateVirtualMemory, ntdll!NtProtectVirtualMemory
//                (the RWX signal), ntdll!NtWriteVirtualMemory,
//                ntdll!NtMapViewOfSection
//   injection  : ntdll!NtCreateThreadEx, ntdll!NtResumeThread (the classic
//                alloc -> write -> protect(RX) -> createthread/resume chain)
//   registry   : ntdll!NtSetValueKey
//   process    : ntdll!NtCreateUserProcess (Track 3.2 child-following: every
//                new non-WoW64 child gets this same DLL injected before its
//                first instruction runs)
//   loader     : ntdll!LdrLoadDll (loader-mediated loads that bypass the
//                kernel32!LoadLibrary wrapper; manual-map never calls this
//                and stays covered by the memory hooks + chain signatures)
//   timing     : ntdll!NtDelayExecution, kernel32!GetTickCount64,
//                ntdll!NtQuerySystemTime (sleep-skip / anti-sandbox checks)
//   crypto     : bcryptprimitives!BCryptEncrypt/BCryptDecrypt/BCryptHashData
// Deferred: network (ws2_32/winhttp), WoW64 (monitor_x86.dll).
//
// Two correctness points a monitor must get right:
//   * Re-entrancy -- a hook handler must not recurse into itself while
//     logging, so a thread-local guard makes the emit path call the original
//     directly.
//   * Ordering -- hooks must be live BEFORE the sample's first instruction
//     runs. Init happens on a dedicated thread (never heavy work under the
//     DllMain loader lock); when it finishes it signals a per-pid "ready"
//     event the loader waits on before it ResumeThread()s the sample.
//
// Volume control (mandatory -- a busy sample can spin on VirtualProtect or
// registry writes fast enough to produce 100k+ events/run otherwise):
//   * a GLOBAL cap across every hook combined,
//   * a PER-API cap so one chatty hook can't crowd out the rest,
//   * consecutive-duplicate collapsing per thread (same API + same detail
//     string back-to-back, e.g. a spin/poll loop, counted but not re-emitted).

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include "MinHook.h"
#include "../common/inject.h"

// Collector endpoint + ready-event name, shared verbatim with monitor_loader.exe
// and the guest-side apitrace_collector.py.
static const wchar_t* kPipeName = L"\\\\.\\pipe\\sandbox_apitrace";

static HANDLE            g_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION  g_pipeLock;
static volatile bool     g_pipeReady = false;
// True while MinHook is (un)patching hook targets. Our own patch sites are
// 5-byte protects INSIDE ntdll/kernel32/bcrypt images -- emitting them is
// pure self-noise (and with Phase-2 tamper flagging, a self-inflicted FP).
static volatile bool     g_installingHooks = false;

// Re-entrancy guard (a hook handler must not recurse into itself while
// logging) as an open-addressed TID set. It must be allocation-free, so it
// can be neither thread_local (implicit TLS slots of an injected DLL are not
// populated yet on a thread inside LdrpInitializeThread; ntdll calls hooked
// Nt* from there -> NULL TEB->TlsExpansionSlots deref, 0xC0000005) nor FLS
// (FlsSetValue ALLOCATES the FLS array on first use, which re-enters hooked
// NtAllocateVirtualMemory before the guard is set -> infinite recursion,
// 0xC00000FD; both root-caused 2026-07-27). A fixed table + CAS needs no
// per-thread runtime state at all. Only the owning thread can ever see its
// own TID in the table, so the recursion check is exact.
static constexpr int kInHookSlots = 128;
static volatile LONG g_inHookTids[kInHookSlots] = {};
static bool in_hook() {
    LONG tid = (LONG)GetCurrentThreadId();
    for (int i = 0; i < kInHookSlots; i++) {
        if (g_inHookTids[i] == tid) return true;
    }
    return false;
}
static void set_in_hook(bool on) {
    LONG tid = (LONG)GetCurrentThreadId();
    if (on) {
        for (int i = 0; i < kInHookSlots; i++) {
            if (g_inHookTids[i] == tid) return;  // already marked
            if (InterlockedCompareExchange(&g_inHookTids[i], tid, 0) == 0) return;
        }
        // Table full (128 threads simultaneously inside handlers is
        // practically impossible); proceeding unguarded is the safe failure.
    } else {
        for (int i = 0; i < kInHookSlots; i++) {
            if (g_inHookTids[i] == tid) { g_inHookTids[i] = 0; return; }
        }
    }
}

// Defined further below; should_emit needs it for per-API cap notices.
static void emit_raw(const char* api, const char* category, const char* arg0Escaped);

// Our own on-disk path, captured at DLL_PROCESS_ATTACH -- needed so the
// NtCreateUserProcess hook can inject this same DLL into child processes
// (Track 3.2 child-following).
static wchar_t g_monitorDllPath[MAX_PATH] = {0};

// Child-following kill switch (env var SANDBOX_MONITOR_NO_CHILD_FOLLOW=1):
// safety valve -- the NtCreateUserProcess EVENT is still emitted, only the
// recursive injection is skipped.
static volatile bool g_childFollowEnabled = true;

// --- volume control -------------------------------------------------------
enum ApiIndex {
    API_CreateFileW = 0,
    API_CreateProcessW,
    API_NtCreateFile,
    API_NtAllocateVirtualMemory,
    API_NtProtectVirtualMemory,
    API_NtWriteVirtualMemory,
    API_NtMapViewOfSection,
    API_NtCreateThreadEx,
    API_NtResumeThread,
    API_NtSetValueKey,
    API_NtCreateUserProcess,
    API_LdrLoadDll,
    API_NtDelayExecution,
    API_GetTickCount64,
    API_NtQuerySystemTime,
    API_BCryptEncrypt,
    API_BCryptDecrypt,
    API_BCryptHashData,
    API_NtQueueApcThread,
    API_NtSetContextThread,
    API_NtSuspendThread,
    API_NtOpenProcessToken,
    API_NtDuplicateToken,
    API_NtAdjustPrivilegesToken,
    API_NtReadVirtualMemory,
    API_NtUnmapViewOfSection,
    API_NtUnmapViewOfSectionEx,
    API_NtAllocateVirtualMemoryEx,
    API_NtMapViewOfSectionEx,
    API_NtQueueApcThreadEx,
    API_NtGetContextThread,
    API_NtSetInformationThread,
    API_NtSetInformationProcess,
    API_NtCreateTimer,
    API_NtSetTimer,
    API_NtCreateTransaction,
    API_NtRollbackTransaction,
    API_COUNT
};
static const char* kApiNames[API_COUNT] = {
    "CreateFileW", "CreateProcessW", "NtCreateFile", "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtMapViewOfSection",
    "NtCreateThreadEx", "NtResumeThread", "NtSetValueKey", "NtCreateUserProcess",
    "LdrLoadDll", "NtDelayExecution", "GetTickCount64", "NtQuerySystemTime",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptHashData",
    "NtQueueApcThread", "NtSetContextThread", "NtSuspendThread",
    "NtOpenProcessToken", "NtDuplicateToken", "NtAdjustPrivilegesToken",
    "NtReadVirtualMemory", "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx",
    "NtAllocateVirtualMemoryEx", "NtMapViewOfSectionEx", "NtQueueApcThreadEx",
    "NtGetContextThread", "NtSetInformationThread", "NtSetInformationProcess",
    "NtCreateTimer", "NtSetTimer", "NtCreateTransaction", "NtRollbackTransaction",
};
// Per-API caps (Track 3.2): chatty hooks get a higher budget than rare,
// high-signal ones so a flood of one kind can't crowd out the rest.
static const long kApiCaps[API_COUNT] = {
    3000,  // CreateFileW
    1000,  // CreateProcessW
    5000,  // NtCreateFile
    3000,  // NtAllocateVirtualMemory
    3000,  // NtProtectVirtualMemory
    2000,  // NtWriteVirtualMemory (cross-process only anyway)
    2000,  // NtMapViewOfSection
    1000,  // NtCreateThreadEx
    1000,  // NtResumeThread
    2000,  // NtSetValueKey
    1000,  // NtCreateUserProcess
    500,   // LdrLoadDll
    200,   // NtDelayExecution
    200,   // GetTickCount64
    200,   // NtQuerySystemTime
    1000,  // BCryptEncrypt
    1000,  // BCryptDecrypt
    1000,  // BCryptHashData
    1000,  // NtQueueApcThread
    1000,  // NtSetContextThread
    1000,  // NtSuspendThread
    500,   // NtOpenProcessToken (cross-process only anyway)
    500,   // NtDuplicateToken
    500,   // NtAdjustPrivilegesToken (SeDebug/SeImpersonate only anyway)
    2000,  // NtReadVirtualMemory (cross-process only anyway)
    1000,  // NtUnmapViewOfSection
    1000,  // NtUnmapViewOfSectionEx
    3000,  // NtAllocateVirtualMemoryEx
    2000,  // NtMapViewOfSectionEx
    1000,  // NtQueueApcThreadEx
    1000,  // NtGetContextThread
    200,   // NtSetInformationThread (HideFromDebugger only anyway)
    200,   // NtSetInformationProcess (debug classes only anyway)
    200,   // NtCreateTimer
    500,   // NtSetTimer
    100,   // NtCreateTransaction
    100,   // NtRollbackTransaction
};
// Global backstop across all hooks combined; overridable via env var so a
// pathological run can be re-tuned without a rebuild.
static long g_globalEventCap = 50000;
static volatile long g_totalEmitted = 0;
static volatile long g_perApiEmitted[API_COUNT] = {0};
static volatile bool g_capNoticeSent = false;
static volatile bool g_perApiCapNoticeSent[API_COUNT] = {0};

// NOTE: the old per-thread consecutive-dup check used thread_local storage
// and was removed (see the FLS note above). The cross-thread ring below
// collapses rapid consecutive duplicates just as well (same-thread repeats
// within the 1s window hit the ring too).

// Cross-thread, time-windowed duplicate suppression (Track 3.2): a small
// per-process ring of recently-emitted (api, detail) pairs. Catches what the
// per-thread consecutive check misses -- two threads polling the same call,
// or a loop alternating between calls. Approximate by design (races just mean
// an occasional duplicate slips through); target pids are already embedded in
// the detail strings, so (idx, detail) identity is sufficient.
struct DedupEntry { ApiIndex idx; char detail[128]; DWORD tick; };
static constexpr int kDedupRingSize = 64;
static const DWORD kDedupWindowMs = 1000;
static DedupEntry g_dedupRing[kDedupRingSize] = {};
static volatile LONG g_dedupPos = 0;

static bool recently_emitted(ApiIndex idx, const char* detail) {
    DWORD now = GetTickCount();
    for (int i = 0; i < kDedupRingSize; i++) {
        DedupEntry& e = g_dedupRing[i];
        if (e.tick && e.idx == idx && (now - e.tick) <= kDedupWindowMs &&
            strncmp(e.detail, detail, sizeof(e.detail) - 1) == 0) {
            return true;
        }
    }
    LONG pos = (LONG)(InterlockedIncrement(&g_dedupPos) % kDedupRingSize);
    DedupEntry& slot = g_dedupRing[pos];
    slot.idx = idx;
    strncpy_s(slot.detail, detail, sizeof(slot.detail) - 1);
    slot.tick = now;
    return false;
}

// Whether this call should actually be emitted, applying every volume-control
// rule; also does the counter bookkeeping. Call ONCE per candidate event,
// before formatting/writing it (skip the work if this returns false).
static bool should_emit(ApiIndex idx, const char* detail) {
    if (recently_emitted(idx, detail)) {
        return false;  // duplicate within the time window
    }
    long total = InterlockedIncrement(&g_totalEmitted);
    if (total > g_globalEventCap) {
        InterlockedDecrement(&g_totalEmitted);
        return false;
    }
    long perApi = InterlockedIncrement(&g_perApiEmitted[idx]);
    if (perApi > kApiCaps[idx]) {
        InterlockedDecrement(&g_perApiEmitted[idx]);
        InterlockedDecrement(&g_totalEmitted);
        if (!g_perApiCapNoticeSent[idx]) {
            // Transparency: the analyst must know this API's stream was cut.
            g_perApiCapNoticeSent[idx] = true;
            emit_raw("__event_cap_reached__", "meta", kApiNames[idx]);
        }
        return false;
    }
    return true;
}

// --- JSON / pipe plumbing --------------------------------------------------

// UTF-16 -> UTF-8, JSON-string-escaped, into `out`. Best-effort + truncating;
// a monitor must never crash the target on a weird argument.
static void json_escape_w(const wchar_t* ws, char* out, size_t outsz) {
    char utf8[1024];
    int n = 0;
    if (ws) n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, utf8, (int)sizeof(utf8) - 1, NULL, NULL);
    if (n <= 0) utf8[0] = 0; else utf8[n] = 0;  // n counts the NUL
    size_t o = 0;
    for (size_t i = 0; utf8[i] && o + 2 < outsz; i++) {
        unsigned char c = (unsigned char)utf8[i];
        if (c == '\\' || c == '"') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c == '\n')        { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\r')        { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c == '\t')        { out[o++] = '\\'; out[o++] = 't'; }
        else if (c < 0x20)         { /* drop other control chars */ }
        else                       { out[o++] = (char)c; }
    }
    out[o] = 0;
}

// Narrow (already-ASCII) JSON-string-escape -- for the formatted numeric/flag
// detail strings the memory/injection/registry hooks build (no wide-char
// conversion needed since they never embed raw user-controlled text).
static void json_escape_a(const char* s, char* out, size_t outsz) {
    size_t o = 0;
    for (size_t i = 0; s && s[i] && o + 2 < outsz; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\\' || c == '"') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c < 0x20)         { /* drop control chars */ }
        else                       { out[o++] = (char)c; }
    }
    out[o] = 0;
}

// --- CRT-free string building ---------------------------------------------
// Hook handlers must NEVER call CRT functions that touch per-thread CRT
// state (__acrt_ptd: _snprintf_s, fwprintf, ...). ntdll calls hooked Nt*
// functions from inside LdrpInitializeThread -- i.e. on threads whose CRT
// per-thread state does not exist yet -- so a CRT call in the emit path
// NULL-derefs and kills the sample with 0xC0000005. Root-caused 2026-07-27:
// 100% repro with the collector pipe connected + any heavily-multithreaded
// (.NET) sample; cmd.exe never crashed (no extra threads); without the pipe
// the emit path short-circuited before reaching any CRT call.
struct SBuf { char* p; char* end; };
static void sb_init(SBuf& b, char* buf, size_t n) { b.p = buf; b.end = buf + n - 1; if (n) buf[0] = 0; }
static void sb_ch(SBuf& b, char c) { if (b.p < b.end) { *b.p++ = c; *b.p = 0; } }
static void sb_str(SBuf& b, const char* s) { while (s && *s && b.p < b.end) { *b.p++ = *s++; } *b.p = 0; }
static void sb_u64(SBuf& b, unsigned long long v) {
    char t[24]; int i = 0;
    do { t[i++] = (char)('0' + (v % 10)); v /= 10; } while (v && i < 24);
    while (i && b.p < b.end) *b.p++ = t[--i];
    *b.p = 0;
}
static void sb_i64(SBuf& b, long long v) {
    if (v < 0) { sb_ch(b, '-'); sb_u64(b, (unsigned long long)(-(v + 1)) + 1); }
    else sb_u64(b, (unsigned long long)v);
}
static void sb_hex(SBuf& b, unsigned long long v) {
    char t[16]; int i = 0;
    if (!v) { sb_ch(b, '0'); return; }
    while (v && i < 16) { int d = (int)(v & 0xF); t[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v >>= 4; }
    while (i && b.p < b.end) *b.p++ = t[--i];
    *b.p = 0;
}

// Reconnect throttle: after a pipe loss we retry at most once per second so
// a permanently-dead collector can't stall the hooked sample.
static DWORD g_lastReconnectAttempt = 0;

// Try to re-establish the pipe to the collector. Caller holds g_pipeLock.
static bool pipe_reconnect_locked() {
    DWORD now = GetTickCount();
    if (now - g_lastReconnectAttempt < 1000) return false;
    g_lastReconnectAttempt = now;
    for (int i = 0; i < 3; i++) {
        HANDLE h = CreateFileW(kPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(h, &mode, NULL, NULL);
            g_pipe = h;
            return true;
        }
        if (GetLastError() == ERROR_PIPE_BUSY) WaitNamedPipeW(kPipeName, 500);
        else break;  // collector gone -- don't spin
    }
    return false;
}

// Write one line to the collector pipe. Caller holds g_pipeLock. On failure
// the pipe is dead (collector restart/crash): close it, RECONNECT, and only
// then emit one __pipe_lost__ meta event marking the gap -- emitting into a
// dead pipe would silently lose the marker along with the event.
static void pipe_write_locked(const char* buf, int len) {
    if (g_pipe == INVALID_HANDLE_VALUE) {
        // Lost earlier -- try to re-establish before writing.
        if (!pipe_reconnect_locked()) return;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(g_pipe, buf, (DWORD)len, &written, NULL);
    if (!ok || (int)written != len) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
        if (pipe_reconnect_locked()) {
            char line[224];
            SBuf b; sb_init(b, line, sizeof(line));
            sb_str(b, "{\"api\":\"__pipe_lost__\",\"category\":\"meta\",\"pid\":");
            sb_u64(b, GetCurrentProcessId());
            sb_str(b, ",\"tid\":");
            sb_u64(b, GetCurrentThreadId());
            sb_str(b, ",\"arg0\":\"pipe write failed; reconnected, events lost in the gap\"}\n");
            DWORD w2 = 0;
            WriteFile(g_pipe, line, (DWORD)(b.p - line), &w2, NULL);
        }
    }
}

// Emit-path buffers are STATIC and the whole format+write runs under
// g_pipeLock (recursive-safe): a hooked call must add as little stack as
// possible. The old per-call buffers (4 KB line + 2 KB escape) sat on the
// CALLING thread's stack -- .NET processes (CLR GC/JIT threads with small,
// deeply-used stacks) died with 0xC0000005 when a hooked API fired near the
// stack guard page. Root-caused 2026-07-27: pipe-connected monitor + any
// .NET sample crashed ~100%, cmd/native samples never did.
static char g_lineBuf[4096];
static char g_escWide[2048];
static char g_escNarrow[512];

// Raw emit (bypasses volume control) -- used for meta events and as the
// shared tail of emit()/emit_detail(). Caller holds g_pipeLock. CRT-free
// formatting (see SBuf note above).
static void emit_raw_locked(const char* api, const char* category, const char* arg0Escaped) {
    SBuf b; sb_init(b, g_lineBuf, sizeof(g_lineBuf));
    sb_str(b, "{\"api\":\""); sb_str(b, api);
    sb_str(b, "\",\"category\":\""); sb_str(b, category);
    sb_str(b, "\",\"pid\":"); sb_u64(b, GetCurrentProcessId());
    sb_str(b, ",\"tid\":"); sb_u64(b, GetCurrentThreadId());
    sb_str(b, ",\"arg0\":\""); sb_str(b, arg0Escaped);
    sb_str(b, "\"}\n");
    pipe_write_locked(g_lineBuf, (int)(b.p - g_lineBuf));
}

// Lock-taking variant for callers that don't already hold g_pipeLock
// (cap notices inside should_emit, init_thread's hello).
static void emit_raw(const char* api, const char* category, const char* arg0Escaped) {
    if (!g_pipeReady) return;
    EnterCriticalSection(&g_pipeLock);
    emit_raw_locked(api, category, arg0Escaped);
    LeaveCriticalSection(&g_pipeLock);
}

static void emit(const char* api, const char* category, const wchar_t* arg0) {
    if (!g_pipeReady || g_installingHooks) return;
    EnterCriticalSection(&g_pipeLock);
    json_escape_w(arg0, g_escWide, sizeof(g_escWide));
    emit_raw_locked(api, category, g_escWide);
    LeaveCriticalSection(&g_pipeLock);
}

static void emit_detail(ApiIndex idx, const char* category, const char* detail) {
    if (!g_pipeReady || g_installingHooks) return;
    if (!should_emit(idx, detail)) return;
    EnterCriticalSection(&g_pipeLock);
    json_escape_a(detail, g_escNarrow, sizeof(g_escNarrow));
    emit_raw_locked(kApiNames[idx], category, g_escNarrow);
    if (g_totalEmitted == g_globalEventCap && !g_capNoticeSent) {
        g_capNoticeSent = true;
        emit_raw_locked("__event_cap_reached__", "meta", "global");
    }
    LeaveCriticalSection(&g_pipeLock);
}

// Extract a (non-NUL-terminated) UNICODE_STRING file/value name, guarded so a
// malformed pointer can never fault the target.
static void copy_unicode_string(PUNICODE_STRING us, wchar_t* out, size_t outChars) {
    out[0] = 0;
    __try {
        if (us && us->Buffer && us->Length) {
            USHORT chars = (USHORT)(us->Length / sizeof(wchar_t));
            if (chars > outChars - 1) chars = (USHORT)(outChars - 1);
            memcpy(out, us->Buffer, (size_t)chars * sizeof(wchar_t));
            out[chars] = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
    }
}

// SEH-guarded reads for hook arguments that are user-mode pointers fully
// under the (potentially hostile) sample's control: a bogus non-NULL pointer
// must never fault us in-hook -- an in-hook crash kills the sample mid-run
// and reads as a false-clean report.
static SIZE_T safe_read_size(PSIZE_T p) {
    __try { return p ? *p : (SIZE_T)0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static LONGLONG safe_read_i64(PLARGE_INTEGER p) {
    __try { return p ? p->QuadPart : 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static PUNICODE_STRING safe_object_name(POBJECT_ATTRIBUTES oa) {
    __try { return oa ? oa->ObjectName : nullptr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// Wide -> UTF-8 (no JSON escaping) for detail strings that go through
// emit_detail, which does its own escaping.
static void wide_to_utf8(const wchar_t* ws, char* out, size_t outsz) {
    out[0] = 0;
    if (!ws || !outsz) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, out, (int)outsz - 1, NULL, NULL);
    if (n <= 0) out[0] = 0;
    else out[outsz - 1] = 0;
}

static bool is_executable_protect(ULONG protect) {
    // PAGE_EXECUTE=0x10, PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40,
    // PAGE_EXECUTE_WRITECOPY=0x80 -- any of the high nibble's bits.
    return (protect & 0xF0) != 0;
}

// Best-effort: is `h` a handle to a DIFFERENT process than us? Cross-process
// memory/thread operations are the injection-relevant case; same-process
// ones (e.g. a JIT engine protecting its own generated code RX) are common
// and far less interesting, but still logged -- just flagged distinctly.
static DWORD target_pid_of_process_handle(HANDLE h) {
    if (h == NULL || h == (HANDLE)-1 /* GetCurrentProcess() pseudo-handle */) return GetCurrentProcessId();
    DWORD pid = GetProcessId(h);
    return pid ? pid : 0;
}

// --- anti-tamper module ranges (Phase 2) -----------------------------------
// Write/protect operations landing inside ntdll's or amsi.dll's image are
// unhooking / ETW-AMSI-blinding attempts. Ranges are captured lazily (amsi
// loads on demand) with GetModuleInformation; lookups are plain address
// compares, no CRT, safe on any thread.
struct ModuleRange { uintptr_t base; uintptr_t end; };
static ModuleRange g_ntdllRange = {};
static ModuleRange g_amsiRange = {};

static void capture_range(HMODULE mod, ModuleRange* out) {
    if (!mod || out->base) return;
    MODULEINFO mi = {};
    if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) {
        out->base = (uintptr_t)mi.lpBaseOfDll;
        out->end = out->base + mi.SizeOfImage;
    }
}

static void ensure_ranges() {
    if (!g_ntdllRange.base) capture_range(GetModuleHandleW(L"ntdll.dll"), &g_ntdllRange);
    if (!g_amsiRange.base) capture_range(GetModuleHandleW(L"amsi.dll"), &g_amsiRange);  // NULL until loaded -- retried next call
}

// 0 = none, 1 = ntdll, 2 = amsi
static int tamper_target_of(uintptr_t addr) {
    if (g_ntdllRange.base && addr >= g_ntdllRange.base && addr < g_ntdllRange.end) return 1;
    if (g_amsiRange.base && addr >= g_amsiRange.base && addr < g_amsiRange.end) return 2;
    return 0;
}

// Flag a write/protect as tampering only when it is ACTIONABLE: a WRITE into
// a guarded module's image (patch), or a protect flipping such a region to
// EXECUTABLE (making patched code runnable). Routine RW<->RO flips inside
// ntdll by the loader/CLR are normal and must not flag (measured: 46 benign
// flips in one powershell run).
static void sb_tamper_flag(SBuf& b, uintptr_t addr) {
    int t = tamper_target_of(addr);
    if (t) {
        sb_str(b, " targets_module=");
        sb_str(b, t == 1 ? "ntdll" : "amsi");
    }
}

// --- hook typedefs + originals ---------------------------------------------

typedef HANDLE (WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI* CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                          BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef NTSTATUS (NTAPI* NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                         PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
                                               PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID,
                                             ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI* NtResumeThread_t)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI* NtSetValueKey_t)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
// The real process-creation choke point under kernel32!CreateProcessW. The
// last three params are opaque to us (RTL_USER_PROCESS_PARAMETERS /
// PS_CREATE_INFO / PS_ATTRIBUTE_LIST) -- PVOID keeps the signature callable
// without defining those structs.
typedef NTSTATUS (NTAPI* NtCreateUserProcess_t)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
                                                POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG,
                                                PVOID, PVOID, PVOID);
// Tier-1 expansion (loader / timing / crypto). BCrypt handles are opaque --
// PVOID keeps the signatures callable without pulling in bcrypt.h.
typedef NTSTATUS (NTAPI* LdrLoadDll_t)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS (NTAPI* NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
typedef ULONGLONG (WINAPI* GetTickCount64_t)(void);
typedef NTSTATUS (NTAPI* NtQuerySystemTime_t)(PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* BCryptEncrypt_t)(PVOID, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS (NTAPI* BCryptDecrypt_t)(PVOID, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS (NTAPI* BCryptHashData_t)(PVOID, PUCHAR, ULONG, ULONG);
// Injection-finisher expansion: APC-queue and thread-hijack paths (neither is
// visible to Sysmon -- no event exists for APC queueing or context-set).
typedef NTSTATUS (NTAPI* NtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI* NtSetContextThread_t)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI* NtSuspendThread_t)(HANDLE, PULONG);
// Token manipulation (privilege escalation / token theft).
typedef NTSTATUS (NTAPI* NtOpenProcessToken_t)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI* NtDuplicateToken_t)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE);
typedef NTSTATUS (NTAPI* NtAdjustPrivilegesToken_t)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
// CrowdStrike-parity batch: read side, hollowing unmap, Ex bypass variants,
// anti-debug information classes.
typedef NTSTATUS (NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI* NtUnmapViewOfSectionEx_t)(HANDLE, PVOID, ULONG);
typedef NTSTATUS (NTAPI* NtAllocateVirtualMemoryEx_t)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* NtMapViewOfSectionEx_t)(HANDLE, HANDLE, PVOID*, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* NtQueueApcThreadEx_t)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI* NtGetContextThread_t)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI* NtSetInformationThread_t)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* NtSetInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG);
// Timer-based sleep obfuscation (Ekko/Foliage) and TxF (doppelganging).
typedef NTSTATUS (NTAPI* NtCreateTimer_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI* NtSetTimer_t)(HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN);
typedef NTSTATUS (NTAPI* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID, PVOID, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* NtRollbackTransaction_t)(HANDLE, BOOLEAN);

static CreateFileW_t              o_CreateFileW = nullptr;
static CreateProcessW_t           o_CreateProcessW = nullptr;
static NtCreateFile_t             o_NtCreateFile = nullptr;
static NtAllocateVirtualMemory_t  o_NtAllocateVirtualMemory = nullptr;
static NtProtectVirtualMemory_t   o_NtProtectVirtualMemory = nullptr;
static NtWriteVirtualMemory_t     o_NtWriteVirtualMemory = nullptr;
static NtMapViewOfSection_t       o_NtMapViewOfSection = nullptr;
static NtCreateThreadEx_t         o_NtCreateThreadEx = nullptr;
static NtResumeThread_t           o_NtResumeThread = nullptr;
static NtSetValueKey_t            o_NtSetValueKey = nullptr;
static NtCreateUserProcess_t      o_NtCreateUserProcess = nullptr;
static LdrLoadDll_t               o_LdrLoadDll = nullptr;
static NtDelayExecution_t         o_NtDelayExecution = nullptr;
static GetTickCount64_t           o_GetTickCount64 = nullptr;
static NtQuerySystemTime_t        o_NtQuerySystemTime = nullptr;
static BCryptEncrypt_t            o_BCryptEncrypt = nullptr;
static BCryptDecrypt_t            o_BCryptDecrypt = nullptr;
static BCryptHashData_t           o_BCryptHashData = nullptr;
static NtQueueApcThread_t         o_NtQueueApcThread = nullptr;
static NtSetContextThread_t       o_NtSetContextThread = nullptr;
static NtSuspendThread_t          o_NtSuspendThread = nullptr;
static NtOpenProcessToken_t       o_NtOpenProcessToken = nullptr;
static NtDuplicateToken_t         o_NtDuplicateToken = nullptr;
static NtAdjustPrivilegesToken_t  o_NtAdjustPrivilegesToken = nullptr;
static NtReadVirtualMemory_t      o_NtReadVirtualMemory = nullptr;
static NtUnmapViewOfSection_t     o_NtUnmapViewOfSection = nullptr;
static NtUnmapViewOfSectionEx_t   o_NtUnmapViewOfSectionEx = nullptr;
static NtAllocateVirtualMemoryEx_t o_NtAllocateVirtualMemoryEx = nullptr;
static NtMapViewOfSectionEx_t     o_NtMapViewOfSectionEx = nullptr;
static NtQueueApcThreadEx_t       o_NtQueueApcThreadEx = nullptr;
static NtGetContextThread_t       o_NtGetContextThread = nullptr;
static NtSetInformationThread_t   o_NtSetInformationThread = nullptr;
static NtSetInformationProcess_t  o_NtSetInformationProcess = nullptr;
static NtCreateTimer_t            o_NtCreateTimer = nullptr;
static NtSetTimer_t               o_NtSetTimer = nullptr;
static NtCreateTransaction_t      o_NtCreateTransaction = nullptr;
static NtRollbackTransaction_t    o_NtRollbackTransaction = nullptr;

// --- child-following support (Track 3.2) ------------------------------------

#ifndef PROCESS_CREATE_FLAGS_SUSPENDED
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000001
#endif

static bool is_wow64_process(HANDLE hProcess) {
    BOOL wow = FALSE;
    IsWow64Process(hProcess, &wow);
    return wow != FALSE;
}

// Initial-thread handles of children WE just created via NtCreateUserProcess.
// kernel32!CreateProcessW (without CREATE_SUSPENDED) resumes the child's
// initial thread itself, right after NtCreateUserProcess returns -- that
// resume is process STARTUP, not an injection resume, so h_NtResumeThread
// must not emit it (otherwise every benign child spawn trips the
// ApitraceRemoteThread behavioral signature). A caller-initiated resume of a
// CREATE_SUSPENDED child (hollowing) still emits -- it is the signal.
struct FreshChild { HANDLE thread; bool createdSuspended; };
static constexpr int kFreshChildSlots = 64;
static FreshChild g_freshChildren[kFreshChildSlots] = {};
static CRITICAL_SECTION g_freshChildLock;

static void remember_fresh_child(HANDLE thread, bool createdSuspended) {
    EnterCriticalSection(&g_freshChildLock);
    // Oldest-slot replacement: find a free slot, else overwrite slot 0. The
    // window between create and resume is microscopic, so eviction loss is
    // practically impossible.
    int slot = 0;
    for (int i = 0; i < kFreshChildSlots; i++) {
        if (g_freshChildren[i].thread == NULL) { slot = i; break; }
    }
    g_freshChildren[slot].thread = thread;
    g_freshChildren[slot].createdSuspended = createdSuspended;
    LeaveCriticalSection(&g_freshChildLock);
}

// If `thread` is the initial thread of a child we created WITHOUT the
// suspended flag, consume the record and return true (auto-resume to
// suppress). Suspended creations keep their record consumed too, but return
// false so the deliberate resume still emits.
static bool is_fresh_child_auto_resume(HANDLE thread) {
    bool suppress = false;
    EnterCriticalSection(&g_freshChildLock);
    for (int i = 0; i < kFreshChildSlots; i++) {
        if (g_freshChildren[i].thread == thread) {
            suppress = !g_freshChildren[i].createdSuspended;
            g_freshChildren[i].thread = NULL;
            break;
        }
    }
    LeaveCriticalSection(&g_freshChildLock);
    return suppress;
}

// --- hook handlers -----------------------------------------------------

static HANDLE WINAPI h_CreateFileW(LPCWSTR nm, DWORD ac, DWORD sh, LPSECURITY_ATTRIBUTES sa,
                                   DWORD di, DWORD fl, HANDLE tm) {
    if (!in_hook()) { set_in_hook(true); emit("CreateFileW", "file", nm); set_in_hook(false); }
    return o_CreateFileW(nm, ac, sh, sa, di, fl, tm);
}

static BOOL WINAPI h_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                    BOOL inh, DWORD fl, LPVOID env, LPCWSTR dir,
                                    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    if (!in_hook()) { set_in_hook(true); emit("CreateProcessW", "process", app ? app : cmd); set_in_hook(false); }
    return o_CreateProcessW(app, cmd, pa, ta, inh, fl, env, dir, si, pi);
}

static NTSTATUS NTAPI h_NtCreateFile(PHANDLE fh, ACCESS_MASK am, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK io,
                                     PLARGE_INTEGER as, ULONG fa, ULONG sa, ULONG cd, ULONG co, PVOID eb, ULONG el) {
    if (!in_hook()) {
        set_in_hook(true);
        wchar_t name[520];
        copy_unicode_string(safe_object_name(oa), name, 520);
        emit("NtCreateFile", "file", name);
        set_in_hook(false);
    }
    return o_NtCreateFile(fh, am, oa, io, as, fa, sa, cd, co, eb, el);
}

static NTSTATUS NTAPI h_NtAllocateVirtualMemory(HANDLE proc, PVOID* base, ULONG_PTR zeroBits, PSIZE_T size,
                                                ULONG allocType, ULONG protect) {
    // Post-call emit: the ACTUAL base is only known after the allocation.
    NTSTATUS status = o_NtAllocateVirtualMemory(proc, base, zeroBits, size, allocType, protect);
    if (!in_hook()) {
        set_in_hook(true);
        ensure_ranges();
        DWORD targetPid = target_pid_of_process_handle(proc);
        uintptr_t addr = NT_SUCCESS(status) ? (uintptr_t)safe_read_size((PSIZE_T)base) : 0;
        char detail[160];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "target_pid="); sb_u64(b, targetPid);
        sb_str(b, " base=0x"); sb_hex(b, addr);
        sb_str(b, " size="); sb_u64(b, safe_read_size(size));
        sb_str(b, " protect=0x"); sb_hex(b, protect);
        sb_str(b, " executable="); sb_ch(b, is_executable_protect(protect) ? '1' : '0');
        sb_str(b, " cross_process="); sb_ch(b, targetPid != GetCurrentProcessId() ? '1' : '0');
        emit_detail(API_NtAllocateVirtualMemory, "memory", detail);
        set_in_hook(false);
    }
    return status;
}

static NTSTATUS NTAPI h_NtProtectVirtualMemory(HANDLE proc, PVOID* base, PSIZE_T size, ULONG newProtect, PULONG oldProtect) {
    if (!in_hook()) {
        set_in_hook(true);
        ensure_ranges();
        DWORD targetPid = target_pid_of_process_handle(proc);
        uintptr_t addr = (uintptr_t)safe_read_size((PSIZE_T)base);
        // The classic evasion/injection tell: flipping a region to executable
        // (RX/RWX) some time after allocating it RW -- the alloc+write+protect
        // pattern behavioral_signatures.py (Track 3.3) will key off this event.
        // targets_module= flags unhooking/ETW-AMSI tampering (Phase 2).
        char detail[160];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "target_pid="); sb_u64(b, targetPid);
        sb_str(b, " base=0x"); sb_hex(b, addr);
        sb_str(b, " size="); sb_u64(b, safe_read_size(size));
        sb_str(b, " new_protect=0x"); sb_hex(b, newProtect);
        sb_str(b, " executable="); sb_ch(b, is_executable_protect(newProtect) ? '1' : '0');
        sb_str(b, " cross_process="); sb_ch(b, targetPid != GetCurrentProcessId() ? '1' : '0');
        if (is_executable_protect(newProtect)) sb_tamper_flag(b, addr);
        emit_detail(API_NtProtectVirtualMemory, "memory", detail);
        set_in_hook(false);
    }
    return o_NtProtectVirtualMemory(proc, base, size, newProtect, oldProtect);
}

static NTSTATUS NTAPI h_NtWriteVirtualMemory(HANDLE proc, PVOID base, PVOID buffer, SIZE_T len, PSIZE_T written) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = target_pid_of_process_handle(proc);
        // Cross-process writes are the interesting case (WriteProcessMemory
        // into an injection target); same-process writes are routine and
        // extremely common (this API backs ordinary same-process memory
        // copies too on some code paths) -- only emit the cross-process ones
        // to keep this hook's volume sane without a separate suppression list.
        if (targetPid != GetCurrentProcessId()) {
            ensure_ranges();
            char detail[128];
            SBuf b; sb_init(b, detail, sizeof(detail));
            sb_str(b, "target_pid="); sb_u64(b, targetPid);
            sb_str(b, " base=0x"); sb_hex(b, (unsigned long long)(uintptr_t)base);
            sb_str(b, " len="); sb_u64(b, len);
            sb_tamper_flag(b, (uintptr_t)base);
            emit_detail(API_NtWriteVirtualMemory, "memory", detail);
        }
        set_in_hook(false);
    }
    return o_NtWriteVirtualMemory(proc, base, buffer, len, written);
}

static NTSTATUS NTAPI h_NtMapViewOfSection(HANDLE section, HANDLE proc, PVOID* base, ULONG_PTR zeroBits,
                                           SIZE_T commitSize, PLARGE_INTEGER offset, PSIZE_T viewSize,
                                           DWORD inherit, ULONG allocType, ULONG protect) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = target_pid_of_process_handle(proc);
        char detail[96];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "target_pid="); sb_u64(b, targetPid);
        sb_str(b, " protect=0x"); sb_hex(b, protect);
        sb_str(b, " cross_process="); sb_ch(b, targetPid != GetCurrentProcessId() ? '1' : '0');
        emit_detail(API_NtMapViewOfSection, "memory", detail);
        set_in_hook(false);
    }
    return o_NtMapViewOfSection(section, proc, base, zeroBits, commitSize, offset, viewSize, inherit, allocType, protect);
}

static NTSTATUS NTAPI h_NtCreateThreadEx(PHANDLE th, ACCESS_MASK am, POBJECT_ATTRIBUTES oa, HANDLE proc,
                                         PVOID start, PVOID arg, ULONG flags, SIZE_T zeroBits, SIZE_T stackSize,
                                         SIZE_T maxStackSize, PVOID attrList) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = target_pid_of_process_handle(proc);
        // The classic injection finisher: a thread created in ANOTHER process.
        // start= enables the reflective-load signature (exec alloc + thread
        // start on the same address).
        char detail[128];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "target_pid="); sb_u64(b, targetPid);
        sb_str(b, " start=0x"); sb_hex(b, (unsigned long long)(uintptr_t)start);
        sb_str(b, " cross_process="); sb_ch(b, targetPid != GetCurrentProcessId() ? '1' : '0');
        emit_detail(API_NtCreateThreadEx, "injection", detail);
        set_in_hook(false);
    }
    return o_NtCreateThreadEx(th, am, oa, proc, start, arg, flags, zeroBits, stackSize, maxStackSize, attrList);
}

static NTSTATUS NTAPI h_NtResumeThread(HANDLE thread, PULONG suspendCount) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = GetProcessIdOfThread(thread);
        if (targetPid && targetPid != GetCurrentProcessId()) {
            // kernel32's auto-resume of a just-created child's initial thread
            // is process startup, not an injection resume -- suppress it.
            if (!is_fresh_child_auto_resume(thread)) {
                char detail[64];
                SBuf b; sb_init(b, detail, sizeof(detail));
                sb_str(b, "target_pid="); sb_u64(b, targetPid);
                emit_detail(API_NtResumeThread, "injection", detail);
            }
        }
        set_in_hook(false);
    }
    return o_NtResumeThread(thread, suspendCount);
}

// Derive a sibling-file path next to our own DLL (g_monitorDllPath).
static bool sibling_path(const wchar_t* name, wchar_t* out, size_t outChars) {
    const wchar_t* slash = wcsrchr(g_monitorDllPath, L'\\');
    if (!slash) return false;
    size_t dirLen = (size_t)(slash - g_monitorDllPath) + 1;
    if (dirLen + wcslen(name) + 1 > outChars) return false;
    memcpy(out, g_monitorDllPath, dirLen * sizeof(wchar_t));
    wcscpy_s(out + dirLen, outChars - dirLen, name);
    return true;
}

// WoW64 child-following (x64 build only): our 64-bit DLL can't load into a
// 32-bit child, so delegate to the 32-bit loader helper in attach mode --
// its own LoadLibraryW address is the 32-bit one valid in every WoW64
// process. Fire-and-forget like same-bitness injection.
static void follow_wow64_child(DWORD childPid) {
    wchar_t loader86[MAX_PATH], dll86[MAX_PATH], cmd[3 * MAX_PATH];
    if (!sibling_path(L"monitor_loader_x86.exe", loader86, MAX_PATH)) { emit_raw("__wow64_follow__", "meta", "fail:sibling_loader"); return; }
    if (!sibling_path(L"monitor_x86.dll", dll86, MAX_PATH)) { emit_raw("__wow64_follow__", "meta", "fail:sibling_dll"); return; }
    if (GetFileAttributesW(loader86) == INVALID_FILE_ATTRIBUTES) { emit_raw("__wow64_follow__", "meta", "fail:no_loader_file"); return; }
    if (GetFileAttributesW(dll86) == INVALID_FILE_ATTRIBUTES) { emit_raw("__wow64_follow__", "meta", "fail:no_dll_file"); return; }
    _snwprintf_s(cmd, _countof(cmd), _TRUNCATE, L"\"%ls\" attach \"%ls\" %lu", loader86, dll86, childPid);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        emit_raw("__wow64_follow__", "meta", "ok:loader_spawned");
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        emit_raw("__wow64_follow__", "meta", "fail:createprocess");
    }
}

// --- timers / transactions (Phase 2 B+C) -----------------------------------

static NTSTATUS NTAPI h_NtCreateTimer(PHANDLE ph, ACCESS_MASK am, POBJECT_ATTRIBUTES oa, ULONG timerType) {
    if (!in_hook()) {
        set_in_hook(true);
        emit_detail(API_NtCreateTimer, "timing", "create");
        set_in_hook(false);
    }
    return o_NtCreateTimer(ph, am, oa, timerType);
}

static NTSTATUS NTAPI h_NtSetTimer(HANDLE timer, PLARGE_INTEGER dueTime, PVOID apcRoutine, PVOID apcCtx,
                                   BOOLEAN resume, LONG period, PBOOLEAN prevState) {
    if (!in_hook()) {
        set_in_hook(true);
        // dueTime is the same LARGE_INTEGER convention as NtDelayExecution
        // (negative = relative 100ns). apc=1 marks the Foliage/Ekko pattern:
        // code execution via timer APC instead of a sleeping thread.
        LONGLONG v = safe_read_i64(dueTime);
        long long delayMs = -1;
        if (v < 0) {
            unsigned long long mag = (unsigned long long)(-(v + 1)) + 1;
            unsigned long long ms = mag / 10000;
            delayMs = (ms > 604800000ULL) ? 604800000LL : (long long)ms;
        }
        char detail[96];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "delay_ms="); sb_i64(b, delayMs);
        sb_str(b, " period_ms="); sb_i64(b, period);
        sb_str(b, " apc="); sb_ch(b, apcRoutine ? '1' : '0');
        emit_detail(API_NtSetTimer, "timing", detail);
        set_in_hook(false);
    }
    return o_NtSetTimer(timer, dueTime, apcRoutine, apcCtx, resume, period, prevState);
}

static NTSTATUS NTAPI h_NtCreateTransaction(PHANDLE ph, ACCESS_MASK am, POBJECT_ATTRIBUTES oa, PVOID guid,
                                            PVOID toa, ULONG createOptions, ULONG isolationLevel, ULONG isolationFlags,
                                            PLARGE_INTEGER timeout, PUNICODE_STRING description) {
    if (!in_hook()) {
        set_in_hook(true);
        // NTFS transactions are near-absent from benign software; presence
        // alone is the doppelganging tell.
        emit_detail(API_NtCreateTransaction, "evasion", "create");
        set_in_hook(false);
    }
    return o_NtCreateTransaction(ph, am, oa, guid, toa, createOptions, isolationLevel, isolationFlags, timeout, description);
}

static NTSTATUS NTAPI h_NtRollbackTransaction(HANDLE tx, BOOLEAN wait) {
    if (!in_hook()) {
        set_in_hook(true);
        emit_detail(API_NtRollbackTransaction, "evasion", "rollback");
        set_in_hook(false);
    }
    return o_NtRollbackTransaction(tx, wait);
}

// PS_ATTRIBUTE_LIST layout (undocumented but stable since Vista): a count-
// prefixed array of {Attribute, Size, Value, ReturnLength}. We only look for
// PS_ATTRIBUTE_PARENT_PROCESS (0x00020006), whose Value is a process HANDLE
// -- when present, the caller picked a DIFFERENT parent than itself, i.e.
// PPID spoofing. SEH-guarded: the list is a user-mode pointer.
struct PsAttribute { ULONG_PTR attr; SIZE_T size; ULONG_PTR value; PSIZE_T retLen; };
static DWORD spoofed_parent_pid(PVOID attrList) {
    DWORD ppid = 0;
    __try {
        SIZE_T total = *(SIZE_T*)attrList;
        if (total >= sizeof(SIZE_T) + sizeof(PsAttribute) && total < 4096) {
            size_t count = (total - sizeof(SIZE_T)) / sizeof(PsAttribute);
            PsAttribute* attrs = (PsAttribute*)((SIZE_T*)attrList + 1);
            for (size_t i = 0; i < count && i < 64; i++) {
                if (attrs[i].attr == 0x00020006 && attrs[i].value) {
                    ppid = GetProcessId((HANDLE)attrs[i].value);
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { ppid = 0; }
    return ppid;
}

static NTSTATUS NTAPI h_NtCreateUserProcess(
    PHANDLE ph, PHANDLE th, ACCESS_MASK pa, ACCESS_MASK ta,
    POBJECT_ATTRIBUTES poa, POBJECT_ATTRIBUTES toa, ULONG pflags, ULONG tflags,
    PVOID params, PVOID createInfo, PVOID attrList) {
    // Call through first: the returned handles are what we need. Crucially,
    // for the Win32 CreateProcessW path the child's main thread is STILL
    // suspended at this point (kernel32 resumes it only after
    // NtCreateUserProcess returns), so injecting here is race-free.
    NTSTATUS status = o_NtCreateUserProcess(ph, th, pa, ta, poa, toa, pflags, tflags,
                                            params, createInfo, attrList);
    if (!NT_SUCCESS(status) || !ph || !th || !*ph || !*th) return status;
    if (in_hook()) return status;
    set_in_hook(true);

    DWORD childPid = GetProcessId(*ph);
    bool createdSuspended = (pflags & PROCESS_CREATE_FLAGS_SUSPENDED) != 0;
    bool wow64 = is_wow64_process(*ph);
    DWORD ppid = attrList ? spoofed_parent_pid(attrList) : 0;
    if (childPid) {
        remember_fresh_child(*th, createdSuspended);
        char detail[128];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "child_pid="); sb_u64(b, childPid);
        sb_str(b, " suspended="); sb_ch(b, createdSuspended ? '1' : '0');
        sb_str(b, " wow64="); sb_ch(b, wow64 ? '1' : '0');
        if (ppid && ppid != GetCurrentProcessId()) {
            // PPID spoof: the process handle named as parent isn't us.
            sb_str(b, " ppid="); sb_u64(b, ppid);
            sb_str(b, " ppid_spoofed=1");
        }
        emit_detail(API_NtCreateUserProcess, "process", detail);

        // Child-following: inject our own DLL into the new child (same
        // bitness only -- a 64-bit DLL can't load into a WoW64 child).
        // FIRE-AND-FORGET: no ready handshake -- holding the child frozen
        // through a full load+hook cycle while the parent is mid-CreateProcess
        // inside kernel32 breaks the child's own startup (observed: nested
        // cmd failing with ERROR_ACCESS_DENIED). The child loads the monitor
        // concurrently with its own init, trading a few ms of unhooked
        // startup for a creation path indistinguishable from unhooked.
        // in_hook()=true suppresses the injector's hooked calls (VirtualAllocEx
        // -> NtAllocateVirtualMemory etc.), so injection makes no self-noise.
        // Bitness: same-bitness injects directly; an x64 monitor delegates
        // WoW64 children to monitor_loader_x86.exe (attach mode); an x86
        // monitor can't reach x64 children and skips them.
        if (g_monitorDllPath[0] && g_childFollowEnabled) {
#ifdef _WIN64
            if (!wow64) {
                bool ok = inject_monitor_into_process(*ph, *th, g_monitorDllPath, 0, L"monitor", true);
                if (!ok)
                    OutputDebugStringW(L"[monitor] child injection failed\n");
            } else {
                follow_wow64_child(childPid);
            }
#else
            if (wow64) {
                bool ok = inject_monitor_into_process(*ph, *th, g_monitorDllPath, 0, L"monitor", true);
                if (!ok)
                    OutputDebugStringW(L"[monitor] child injection failed\n");
            }
            // else: x64 child from a WoW64 parent -- skipped (would need an
            // x64 helper; rare enough to accept as a blind spot).
#endif
        }
    }
    set_in_hook(false);
    return status;
}

static NTSTATUS NTAPI h_NtSetValueKey(HANDLE key, PUNICODE_STRING name, ULONG titleIdx, ULONG type, PVOID data, ULONG dataSize) {
    if (!in_hook()) {
        set_in_hook(true);
        wchar_t valueName[260];
        copy_unicode_string(name, valueName, 260);
        emit("NtSetValueKey", "registry", valueName);
        set_in_hook(false);
    }
    return o_NtSetValueKey(key, name, titleIdx, type, data, dataSize);
}

// --- Tier-1 handlers: loader / timing / crypto ----------------------------

static NTSTATUS NTAPI h_LdrLoadDll(PWSTR path, PULONG flags, PUNICODE_STRING name, PHANDLE handle) {
    if (!in_hook()) {
        set_in_hook(true);
        // The module path is the signal (loads from user-writable/UNC dirs).
        // copy_unicode_string is already SEH-safe; emit via emit_detail so
        // caps + dedup apply (a loader loop can't flood the trace).
        wchar_t mod[520];
        copy_unicode_string(name, mod, 520);
        char utf8[1024];
        wide_to_utf8(mod, utf8, sizeof(utf8));
        emit_detail(API_LdrLoadDll, "loader", utf8);
        set_in_hook(false);
    }
    return o_LdrLoadDll(path, flags, name, handle);
}

static NTSTATUS NTAPI h_NtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER interval) {
    if (!in_hook()) {
        set_in_hook(true);
        // Negative = relative time in 100ns units; positive = absolute
        // (reported as delay_ms=-1 -- the anti-sandbox signature keys off
        // long RELATIVE sleeps). Overflow-safe magnitude: -LLONG_MIN is UB,
        // and absurd values (garbage intervals) are clamped to 7 days so the
        // signature can reject them as implausible.
        LONGLONG v = safe_read_i64(interval);
        long long delayMs = -1;
        if (v < 0) {
            unsigned long long mag = (unsigned long long)(-(v + 1)) + 1;
            unsigned long long ms = mag / 10000;
            delayMs = (ms > 604800000ULL) ? 604800000LL : (long long)ms;
        }
        char detail[64];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "delay_ms="); sb_i64(b, delayMs);
        sb_str(b, " alertable="); sb_ch(b, alertable ? '1' : '0');
        emit_detail(API_NtDelayExecution, "timing", detail);
        set_in_hook(false);
    }
    return o_NtDelayExecution(alertable, interval);
}

static ULONGLONG WINAPI h_GetTickCount64(void) {
    if (!in_hook()) {
        set_in_hook(true);
        // No arguments worth capturing -- presence/rate is the signal (the
        // dedup ring collapses polling loops into ~1 event/sec).
        emit_detail(API_GetTickCount64, "timing", "poll");
        set_in_hook(false);
    }
    return o_GetTickCount64();
}

static NTSTATUS NTAPI h_NtQuerySystemTime(PLARGE_INTEGER sysTime) {
    if (!in_hook()) {
        set_in_hook(true);
        emit_detail(API_NtQuerySystemTime, "timing", "poll");
        set_in_hook(false);
    }
    return o_NtQuerySystemTime(sysTime);
}

// Crypto: input/output lengths + key handle make each genuinely-distinct op
// pass the dedup ring (deliberately NOT deduped by key alone -- a ransomware
// encrypt loop over many files must produce enough events for the
// ApitraceCryptoBurst signature to fire; the per-API cap bounds the volume).
static NTSTATUS NTAPI h_BCryptEncrypt(PVOID hKey, PUCHAR in, ULONG inLen, PVOID pad, PUCHAR iv,
                                      ULONG ivLen, PUCHAR out, ULONG outLen, PULONG result, ULONG flags) {
    if (!in_hook()) {
        set_in_hook(true);
        char detail[96];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "op=encrypt input_len="); sb_u64(b, inLen);
        sb_str(b, " output_len="); sb_u64(b, outLen);
        sb_str(b, " key=0x"); sb_hex(b, (unsigned long long)(ULONG_PTR)hKey);
        emit_detail(API_BCryptEncrypt, "crypto", detail);
        set_in_hook(false);
    }
    return o_BCryptEncrypt(hKey, in, inLen, pad, iv, ivLen, out, outLen, result, flags);
}

static NTSTATUS NTAPI h_BCryptDecrypt(PVOID hKey, PUCHAR in, ULONG inLen, PVOID pad, PUCHAR iv,
                                      ULONG ivLen, PUCHAR out, ULONG outLen, PULONG result, ULONG flags) {
    if (!in_hook()) {
        set_in_hook(true);
        char detail[96];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "op=decrypt input_len="); sb_u64(b, inLen);
        sb_str(b, " output_len="); sb_u64(b, outLen);
        sb_str(b, " key=0x"); sb_hex(b, (unsigned long long)(ULONG_PTR)hKey);
        emit_detail(API_BCryptDecrypt, "crypto", detail);
        set_in_hook(false);
    }
    return o_BCryptDecrypt(hKey, in, inLen, pad, iv, ivLen, out, outLen, result, flags);
}

static NTSTATUS NTAPI h_BCryptHashData(PVOID hHash, PUCHAR in, ULONG inLen, ULONG flags) {
    if (!in_hook()) {
        set_in_hook(true);
        char detail[96];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "op=hash input_len="); sb_u64(b, inLen);
        sb_str(b, " hash=0x"); sb_hex(b, (unsigned long long)(ULONG_PTR)hHash);
        emit_detail(API_BCryptHashData, "crypto", detail);
        set_in_hook(false);
    }
    return o_BCryptHashData(hHash, in, inLen, flags);
}

// --- APC / thread-hijack / token handlers ----------------------------------

static void emit_thread_target(ApiIndex idx, const char* category, HANDLE thread, bool crossOnly) {
    DWORD targetPid = GetProcessIdOfThread(thread);
    if (!targetPid) return;
    bool cross = targetPid != GetCurrentProcessId();
    if (crossOnly && !cross) return;
    char detail[96];
    SBuf b; sb_init(b, detail, sizeof(detail));
    sb_str(b, "target_pid="); sb_u64(b, targetPid);
    sb_str(b, " cross_process="); sb_ch(b, cross ? '1' : '0');
    emit_detail(idx, category, detail);
}

static void emit_apc_target(ApiIndex idx, HANDLE thread, PVOID routine) {
    DWORD targetPid = GetProcessIdOfThread(thread);
    if (!targetPid) return;
    bool cross = targetPid != GetCurrentProcessId();
    char detail[128];
    SBuf b; sb_init(b, detail, sizeof(detail));
    sb_str(b, "target_pid="); sb_u64(b, targetPid);
    sb_str(b, " start=0x"); sb_hex(b, (unsigned long long)(uintptr_t)routine);
    sb_str(b, " cross_process="); sb_ch(b, cross ? '1' : '0');
    emit_detail(idx, "injection", detail);
}

static NTSTATUS NTAPI h_NtQueueApcThread(HANDLE thread, PVOID routine, PVOID arg1, PVOID arg2, PVOID arg3) {
    if (!in_hook()) {
        set_in_hook(true);
        // APC queueing is the classic injection finisher that Sysmon cannot
        // see at all (no event exists for it).
        emit_apc_target(API_NtQueueApcThread, thread, routine);
        set_in_hook(false);
    }
    return o_NtQueueApcThread(thread, routine, arg1, arg2, arg3);
}

static NTSTATUS NTAPI h_NtSetContextThread(HANDLE thread, PCONTEXT ctx) {
    if (!in_hook()) {
        set_in_hook(true);
        // Thread hijacking: context-set on a foreign thread. Same-process
        // context-sets are rare; emit all, the signature keys on cross.
        emit_thread_target(API_NtSetContextThread, "injection", thread, false);
        set_in_hook(false);
    }
    return o_NtSetContextThread(thread, ctx);
}

static NTSTATUS NTAPI h_NtSuspendThread(HANDLE thread, PULONG prevCount) {
    if (!in_hook()) {
        set_in_hook(true);
        // Only cross-process suspends (hijack setup); own-process suspends
        // are routine synchronization.
        emit_thread_target(API_NtSuspendThread, "injection", thread, true);
        set_in_hook(false);
    }
    return o_NtSuspendThread(thread, prevCount);
}

// SEH-safe scan of a TOKEN_PRIVILEGES blob for the two escalation-relevant
// privileges being ENABLED. Bit0 = SeDebugPrivilege (20), bit1 =
// SeImpersonatePrivilege (18).
static DWORD interesting_privileges_enabled(PTOKEN_PRIVILEGES tp) {
    DWORD found = 0;
    __try {
        if (tp && tp->PrivilegeCount > 0 && tp->PrivilegeCount < 64) {
            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                if (tp->Privileges[i].Luid.HighPart != 0) continue;
                if (!(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) continue;
                DWORD low = tp->Privileges[i].Luid.LowPart;
                if (low == 20) found |= 1;
                if (low == 18) found |= 2;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { found = 0; }
    return found;
}

static NTSTATUS NTAPI h_NtAdjustPrivilegesToken(HANDLE token, BOOLEAN disableAll, PTOKEN_PRIVILEGES newState,
                                                ULONG bufLen, PTOKEN_PRIVILEGES prevState, PULONG retLen) {
    // Only the escalation-relevant enables are worth an event -- processes
    // toggle mundane privileges constantly.
    DWORD interesting = interesting_privileges_enabled(newState);
    if (interesting && !in_hook()) {
        set_in_hook(true);
        char detail[96];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "privileges=");
        if (interesting & 1) sb_str(b, "SeDebugPrivilege ");
        if (interesting & 2) sb_str(b, "SeImpersonatePrivilege");
        emit_detail(API_NtAdjustPrivilegesToken, "token", detail);
        set_in_hook(false);
    }
    return o_NtAdjustPrivilegesToken(token, disableAll, newState, bufLen, prevState, retLen);
}

static NTSTATUS NTAPI h_NtOpenProcessToken(HANDLE proc, ACCESS_MASK access, PHANDLE token) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = target_pid_of_process_handle(proc);
        // Only cross-process opens (token theft/setup); own-process opens are
        // constant noise.
        if (targetPid && targetPid != GetCurrentProcessId()) {
            char detail[64];
            SBuf b; sb_init(b, detail, sizeof(detail));
            sb_str(b, "target_pid="); sb_u64(b, targetPid);
            emit_detail(API_NtOpenProcessToken, "token", detail);
            set_in_hook(false);
        } else {
            set_in_hook(false);
        }
    }
    return o_NtOpenProcessToken(proc, access, token);
}

static NTSTATUS NTAPI h_NtDuplicateToken(HANDLE existing, ACCESS_MASK access, POBJECT_ATTRIBUTES oa,
                                         BOOLEAN effectiveOnly, ULONG type, PHANDLE newToken) {
    if (!in_hook()) {
        set_in_hook(true);
        // Presence is the signal; type 2 = SecurityImpersonation... TOKEN_TYPE
        // enum: 1 = TokenPrimary, 2 = TokenImpersonation.
        char detail[64];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "token_type="); sb_u64(b, type);
        emit_detail(API_NtDuplicateToken, "token", detail);
        set_in_hook(false);
    }
    return o_NtDuplicateToken(existing, access, oa, effectiveOnly, type, newToken);
}

// --- read side / unmap / Ex variants / anti-debug ---------------------------

static NTSTATUS NTAPI h_NtReadVirtualMemory(HANDLE proc, PVOID base, PVOID buffer, SIZE_T len, PSIZE_T read) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = target_pid_of_process_handle(proc);
        // Cross-process reads only (secret theft / injection recon); same-
        // process reads are routine and too chatty to be useful.
        if (targetPid != GetCurrentProcessId() && targetPid != 0) {
            char detail[128];
            SBuf b; sb_init(b, detail, sizeof(detail));
            sb_str(b, "target_pid="); sb_u64(b, targetPid);
            sb_str(b, " base=0x"); sb_hex(b, (unsigned long long)(uintptr_t)base);
            sb_str(b, " len="); sb_u64(b, len);
            emit_detail(API_NtReadVirtualMemory, "memory", detail);
        }
        set_in_hook(false);
    }
    return o_NtReadVirtualMemory(proc, base, buffer, len, read);
}

static void emit_unmap(ApiIndex idx, HANDLE proc) {
    DWORD targetPid = target_pid_of_process_handle(proc);
    char detail[96];
    SBuf b; sb_init(b, detail, sizeof(detail));
    sb_str(b, "target_pid="); sb_u64(b, targetPid);
    sb_str(b, " cross_process="); sb_ch(b, (targetPid && targetPid != GetCurrentProcessId()) ? '1' : '0');
    emit_detail(idx, "memory", detail);
}

static NTSTATUS NTAPI h_NtUnmapViewOfSection(HANDLE proc, PVOID base) {
    if (!in_hook()) {
        set_in_hook(true);
        // Hollowing step 1: gutting the victim image (cross-process). Also
        // emitted same-process (module unmapping is normal there; the
        // signature keys on cross).
        emit_unmap(API_NtUnmapViewOfSection, proc);
        set_in_hook(false);
    }
    return o_NtUnmapViewOfSection(proc, base);
}

static NTSTATUS NTAPI h_NtUnmapViewOfSectionEx(HANDLE proc, PVOID base, ULONG flags) {
    if (!in_hook()) {
        set_in_hook(true);
        emit_unmap(API_NtUnmapViewOfSectionEx, proc);
        set_in_hook(false);
    }
    return o_NtUnmapViewOfSectionEx(proc, base, flags);
}

static NTSTATUS NTAPI h_NtAllocateVirtualMemoryEx(HANDLE proc, PVOID* base, PSIZE_T size, ULONG allocType,
                                                  ULONG protect, PVOID extParams, ULONG extCount) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = target_pid_of_process_handle(proc);
        char detail[128];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "target_pid="); sb_u64(b, targetPid);
        sb_str(b, " size="); sb_u64(b, safe_read_size(size));
        sb_str(b, " protect=0x"); sb_hex(b, protect);
        sb_str(b, " executable="); sb_ch(b, is_executable_protect(protect) ? '1' : '0');
        sb_str(b, " cross_process="); sb_ch(b, targetPid != GetCurrentProcessId() ? '1' : '0');
        emit_detail(API_NtAllocateVirtualMemoryEx, "memory", detail);
        set_in_hook(false);
    }
    return o_NtAllocateVirtualMemoryEx(proc, base, size, allocType, protect, extParams, extCount);
}

static NTSTATUS NTAPI h_NtMapViewOfSectionEx(HANDLE section, HANDLE proc, PVOID* base, PLARGE_INTEGER offset,
                                             PSIZE_T viewSize, ULONG allocType, ULONG protect, PVOID extParams, ULONG extCount) {
    if (!in_hook()) {
        set_in_hook(true);
        DWORD targetPid = target_pid_of_process_handle(proc);
        char detail[96];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "target_pid="); sb_u64(b, targetPid);
        sb_str(b, " protect=0x"); sb_hex(b, protect);
        sb_str(b, " cross_process="); sb_ch(b, targetPid != GetCurrentProcessId() ? '1' : '0');
        emit_detail(API_NtMapViewOfSectionEx, "memory", detail);
        set_in_hook(false);
    }
    return o_NtMapViewOfSectionEx(section, proc, base, offset, viewSize, allocType, protect, extParams, extCount);
}

static NTSTATUS NTAPI h_NtQueueApcThreadEx(HANDLE thread, HANDLE reserve, PVOID routine, PVOID arg1, PVOID arg2, PVOID arg3) {
    if (!in_hook()) {
        set_in_hook(true);
        emit_apc_target(API_NtQueueApcThreadEx, thread, routine);
        set_in_hook(false);
    }
    return o_NtQueueApcThreadEx(thread, reserve, routine, arg1, arg2, arg3);
}

static NTSTATUS NTAPI h_NtGetContextThread(HANDLE thread, PCONTEXT ctx) {
    if (!in_hook()) {
        set_in_hook(true);
        // Hijack chain: context read before the (hooked) context set. Cross-
        // process only; own-thread queries are routine.
        emit_thread_target(API_NtGetContextThread, "injection", thread, true);
        set_in_hook(false);
    }
    return o_NtGetContextThread(thread, ctx);
}

static NTSTATUS NTAPI h_NtSetInformationThread(HANDLE thread, ULONG infoClass, PVOID info, ULONG infoLen) {
    // 0x11 = ThreadHideFromDebugger -- the classic anti-debug move.
    if (infoClass == 0x11 && !in_hook()) {
        set_in_hook(true);
        char detail[64];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "class=ThreadHideFromDebugger");
        emit_detail(API_NtSetInformationThread, "evasion", detail);
        set_in_hook(false);
    }
    return o_NtSetInformationThread(thread, infoClass, info, infoLen);
}

static NTSTATUS NTAPI h_NtSetInformationProcess(HANDLE proc, ULONG infoClass, PVOID info, ULONG infoLen) {
    // Anti-debug process classes: 7 = ProcessDebugPort, 30 =
    // ProcessDebugObjectHandle, 31 = ProcessDebugFlags.
    if ((infoClass == 7 || infoClass == 30 || infoClass == 31) && !in_hook()) {
        set_in_hook(true);
        char detail[64];
        SBuf b; sb_init(b, detail, sizeof(detail));
        sb_str(b, "class="); sb_u64(b, infoClass);
        sb_str(b, " target_pid="); sb_u64(b, target_pid_of_process_handle(proc));
        emit_detail(API_NtSetInformationProcess, "evasion", detail);
        set_in_hook(false);
    }
    return o_NtSetInformationProcess(proc, infoClass, info, infoLen);
}

// --- init / attach -----------------------------------------------------

static void signal_ready() {
    wchar_t ev[64];
    _snwprintf_s(ev, _TRUNCATE, L"Local\\sandbox_monitor_ready_%lu", GetCurrentProcessId());
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, ev);
    if (h) { SetEvent(h); CloseHandle(h); }
}

// (hookTarget, handler, &original) triples -- one table drives both
// MH_CreateHook calls and GetProcAddress lookups, so adding a hook later is a
// one-line addition here rather than a scattered edit. altModule is tried
// when the primary module doesn't export the proc (version differences,
// e.g. BCrypt* living in bcrypt.dll vs bcryptprimitives.dll across builds).
struct HookSpec { const char* module; const char* altModule; const char* proc; LPVOID handler; LPVOID* original; };
static const HookSpec kHooks[] = {
    { "kernel32.dll", nullptr, "CreateFileW",              (LPVOID)&h_CreateFileW,              (LPVOID*)&o_CreateFileW },
    { "kernel32.dll", nullptr, "CreateProcessW",            (LPVOID)&h_CreateProcessW,            (LPVOID*)&o_CreateProcessW },
    { "ntdll.dll",    nullptr, "NtCreateFile",              (LPVOID)&h_NtCreateFile,              (LPVOID*)&o_NtCreateFile },
    { "ntdll.dll",    nullptr, "NtAllocateVirtualMemory",    (LPVOID)&h_NtAllocateVirtualMemory,   (LPVOID*)&o_NtAllocateVirtualMemory },
    { "ntdll.dll",    nullptr, "NtProtectVirtualMemory",     (LPVOID)&h_NtProtectVirtualMemory,    (LPVOID*)&o_NtProtectVirtualMemory },
    { "ntdll.dll",    nullptr, "NtWriteVirtualMemory",       (LPVOID)&h_NtWriteVirtualMemory,      (LPVOID*)&o_NtWriteVirtualMemory },
    { "ntdll.dll",    nullptr, "NtMapViewOfSection",         (LPVOID)&h_NtMapViewOfSection,        (LPVOID*)&o_NtMapViewOfSection },
    { "ntdll.dll",    nullptr, "NtCreateThreadEx",           (LPVOID)&h_NtCreateThreadEx,          (LPVOID*)&o_NtCreateThreadEx },
    { "ntdll.dll",    nullptr, "NtResumeThread",             (LPVOID)&h_NtResumeThread,            (LPVOID*)&o_NtResumeThread },
    { "ntdll.dll",    nullptr, "NtSetValueKey",              (LPVOID)&h_NtSetValueKey,             (LPVOID*)&o_NtSetValueKey },
    { "ntdll.dll",    nullptr, "NtCreateUserProcess",        (LPVOID)&h_NtCreateUserProcess,       (LPVOID*)&o_NtCreateUserProcess },
    { "ntdll.dll",    nullptr, "LdrLoadDll",                 (LPVOID)&h_LdrLoadDll,                (LPVOID*)&o_LdrLoadDll },
    { "ntdll.dll",    nullptr, "NtDelayExecution",           (LPVOID)&h_NtDelayExecution,          (LPVOID*)&o_NtDelayExecution },
    { "kernel32.dll", nullptr, "GetTickCount64",             (LPVOID)&h_GetTickCount64,            (LPVOID*)&o_GetTickCount64 },
    { "ntdll.dll",    nullptr, "NtQuerySystemTime",          (LPVOID)&h_NtQuerySystemTime,         (LPVOID*)&o_NtQuerySystemTime },
    // BCrypt*: on the Win10 guest and Win11 host these live in bcrypt.dll
    // (bcryptprimitives.dll does NOT export them there -- GetProcAddress=0
    // silently skipped the hooks in the first guest validation). Older/other
    // builds may only export them from bcryptprimitives.dll, hence the
    // fallback.
    { "bcrypt.dll",  "bcryptprimitives.dll", "BCryptEncrypt",  (LPVOID)&h_BCryptEncrypt,         (LPVOID*)&o_BCryptEncrypt },
    { "bcrypt.dll",  "bcryptprimitives.dll", "BCryptDecrypt",  (LPVOID)&h_BCryptDecrypt,         (LPVOID*)&o_BCryptDecrypt },
    { "bcrypt.dll",  "bcryptprimitives.dll", "BCryptHashData", (LPVOID)&h_BCryptHashData,        (LPVOID*)&o_BCryptHashData },
    { "ntdll.dll",    nullptr, "NtQueueApcThread",           (LPVOID)&h_NtQueueApcThread,          (LPVOID*)&o_NtQueueApcThread },
    { "ntdll.dll",    nullptr, "NtSetContextThread",          (LPVOID)&h_NtSetContextThread,         (LPVOID*)&o_NtSetContextThread },
    { "ntdll.dll",    nullptr, "NtSuspendThread",             (LPVOID)&h_NtSuspendThread,            (LPVOID*)&o_NtSuspendThread },
    { "ntdll.dll",    nullptr, "NtOpenProcessToken",          (LPVOID)&h_NtOpenProcessToken,         (LPVOID*)&o_NtOpenProcessToken },
    { "ntdll.dll",    nullptr, "NtDuplicateToken",            (LPVOID)&h_NtDuplicateToken,           (LPVOID*)&o_NtDuplicateToken },
    { "ntdll.dll",    nullptr, "NtAdjustPrivilegesToken",     (LPVOID)&h_NtAdjustPrivilegesToken,    (LPVOID*)&o_NtAdjustPrivilegesToken },
    { "ntdll.dll",    nullptr, "NtReadVirtualMemory",         (LPVOID)&h_NtReadVirtualMemory,        (LPVOID*)&o_NtReadVirtualMemory },
    { "ntdll.dll",    nullptr, "NtUnmapViewOfSection",        (LPVOID)&h_NtUnmapViewOfSection,       (LPVOID*)&o_NtUnmapViewOfSection },
    { "ntdll.dll",    nullptr, "NtUnmapViewOfSectionEx",      (LPVOID)&h_NtUnmapViewOfSectionEx,     (LPVOID*)&o_NtUnmapViewOfSectionEx },
    { "ntdll.dll",    nullptr, "NtAllocateVirtualMemoryEx",   (LPVOID)&h_NtAllocateVirtualMemoryEx,  (LPVOID*)&o_NtAllocateVirtualMemoryEx },
    { "ntdll.dll",    nullptr, "NtMapViewOfSectionEx",        (LPVOID)&h_NtMapViewOfSectionEx,       (LPVOID*)&o_NtMapViewOfSectionEx },
    { "ntdll.dll",    nullptr, "NtQueueApcThreadEx",          (LPVOID)&h_NtQueueApcThreadEx,         (LPVOID*)&o_NtQueueApcThreadEx },
    { "ntdll.dll",    nullptr, "NtGetContextThread",          (LPVOID)&h_NtGetContextThread,         (LPVOID*)&o_NtGetContextThread },
    { "ntdll.dll",    nullptr, "NtSetInformationThread",      (LPVOID)&h_NtSetInformationThread,     (LPVOID*)&o_NtSetInformationThread },
    { "ntdll.dll",    nullptr, "NtSetInformationProcess",     (LPVOID)&h_NtSetInformationProcess,    (LPVOID*)&o_NtSetInformationProcess },
    { "ntdll.dll",    nullptr, "NtCreateTimer",               (LPVOID)&h_NtCreateTimer,              (LPVOID*)&o_NtCreateTimer },
    { "ntdll.dll",    nullptr, "NtSetTimer",                  (LPVOID)&h_NtSetTimer,                 (LPVOID*)&o_NtSetTimer },
    { "ntdll.dll",    nullptr, "NtCreateTransaction",         (LPVOID)&h_NtCreateTransaction,        (LPVOID*)&o_NtCreateTransaction },
    { "ntdll.dll",    nullptr, "NtRollbackTransaction",       (LPVOID)&h_NtRollbackTransaction,      (LPVOID*)&o_NtRollbackTransaction },
};

static DWORD WINAPI init_thread(LPVOID) {
    // Connect to the collector (started before the sample launches; retry to be
    // robust to ordering).
    for (int i = 0; i < 50 && g_pipe == INVALID_HANDLE_VALUE; i++) {
        g_pipe = CreateFileW(kPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (g_pipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() == ERROR_PIPE_BUSY) WaitNamedPipeW(kPipeName, 2000);
        else Sleep(100);
    }
    if (g_pipe != INVALID_HANDLE_VALUE) {
        DWORD mode = PIPE_READMODE_BYTE;
        SetNamedPipeHandleState(g_pipe, &mode, NULL, NULL);
        g_pipeReady = true;
        emit_raw("__monitor_attached__", "meta", "");
    }

    // Optional global-cap override (no rebuild needed for pathological runs).
    {
        wchar_t capbuf[32];
        DWORD n = GetEnvironmentVariableW(L"SANDBOX_APITRACE_GLOBAL_CAP", capbuf, 32);
        if (n > 0 && n < 32) {
            long v = wcstol(capbuf, NULL, 10);
            if (v > 0) g_globalEventCap = v;
        }
    }

    // Child-following kill switch (inherited by children, so one env var
    // disables the whole tree).
    {
        wchar_t buf[8];
        DWORD n = GetEnvironmentVariableW(L"SANDBOX_MONITOR_NO_CHILD_FOLLOW", buf, 8);
        if (n > 0 && n < 8 && buf[0] == L'1') g_childFollowEnabled = false;
    }

    if (MH_Initialize() == MH_OK) {
        g_installingHooks = true;
        for (const HookSpec& spec : kHooks) {
            // kernel32/ntdll are always loaded; anything else
            // (bcrypt now, ws2_32/winhttp later) is lazy-loaded.
            // Runs on the dedicated init thread, never under the loader lock.
            FARPROC target = nullptr;
            const char* mods[2] = { spec.module, spec.altModule };
            for (int mi = 0; mi < 2 && !target; mi++) {
                const char* modName = mods[mi];
                if (!modName) continue;
                HMODULE mod = GetModuleHandleA(modName);
                if (!mod) mod = LoadLibraryA(modName);
                if (!mod) continue;
                target = GetProcAddress(mod, spec.proc);
            }
            if (!target) continue;
            MH_CreateHook((LPVOID)target, spec.handler, spec.original);
        }
        MH_EnableHook(MH_ALL_HOOKS);
        g_installingHooks = false;
    }

    // Tell the loader hooks are live so it can resume the (still-suspended)
    // sample -- closes the race where the sample runs before hooks install.
    signal_ready();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        InitializeCriticalSection(&g_pipeLock);
        InitializeCriticalSection(&g_freshChildLock);
        GetModuleFileNameW(hinst, g_monitorDllPath, MAX_PATH);
        HANDLE t = CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
