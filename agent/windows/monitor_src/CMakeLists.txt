# Sandbox behavioral monitor -- build definition.
#
# Produces three artifacts (see README.md):
#   monitor_x64.dll     - the injected in-line-hook monitor (MinHook-based)
#   monitor_loader.exe  - launches a sample suspended, injects the DLL, resumes
#   (a 32-bit monitor_x86.dll is added in Track 3.2 for WoW64 samples)
#
# Configure + build (x64, from a normal shell -- cmake locates MSVC itself):
#   cmake -G "Visual Studio 17 2022" -A x64 -S . -B build
#   cmake --build build --config Release
# Artifacts land in build/Release/. scripts/build_monitor.ps1 wraps this and
# copies the outputs up to agent/windows/ (shipped prebuilt, like Sysmon64.exe).

cmake_minimum_required(VERSION 3.15)
project(sandbox_monitor C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT so the DLL/loader drop into the guest with no VC++ redist dependency.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# --- MinHook (vendored, BSD 2-Clause) as a static lib ---
file(GLOB MINHOOK_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/minhook/src/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/minhook/src/hde/*.c")
add_library(minhook STATIC ${MINHOOK_SRC})
target_include_directories(minhook PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/vendor/minhook/include")

# --- monitor DLL ---
add_library(monitor SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/monitor/monitor.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/common/inject.cpp")
target_link_libraries(monitor PRIVATE minhook psapi)

# --- loader EXE ---
add_executable(monitor_loader
    "${CMAKE_CURRENT_SOURCE_DIR}/loader/monitor_loader.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/common/inject.cpp")

# Bitness-aware artifact names: configure with -A x64 and -A Win32 to get both
# (scripts/build_monitor.ps1 does exactly that).
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(monitor PROPERTIES OUTPUT_NAME "monitor_x86")
    set_target_properties(monitor_loader PROPERTIES OUTPUT_NAME "monitor_loader_x86")
else()
    set_target_properties(monitor PROPERTIES OUTPUT_NAME "monitor_x64")
    set_target_properties(monitor_loader PROPERTIES OUTPUT_NAME "monitor_loader")
endif()
