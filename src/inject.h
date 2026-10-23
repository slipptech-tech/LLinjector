#pragma once

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

// One row of the process picker.
struct ProcessEntry {
    DWORD pid = 0;
    std::wstring name;
    std::wstring path;
    std::wstring arch;   // "x64", "x86", "ARM64", "?"
};

struct InjectResult {
    bool ok = false;
    bool already_loaded = false;
    DWORD last_error = 0;
    std::wstring detail;
};

std::vector<ProcessEntry> list_processes();

// Architecture of an already-opened process.
std::wstring arch_of_process(HANDLE process);

// Architecture of the injector binary itself.
std::wstring self_arch();

std::wstring win32_error_text(DWORD code);

// Loads dll_path into pid with a remote LoadLibraryExW call, resolving the
// DLL's dependencies relative to the DLL itself. The remote stub reports back
// both the module handle and GetLastError, so a failure comes with the real
// reason from inside the target rather than a guess.
InjectResult inject_loadlibrary(
    DWORD pid,
    const std::wstring& dll_path,
    const std::function<void(const std::wstring&)>& progress,
    const std::wstring& process_name = {});
