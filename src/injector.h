#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "config.h"

struct ProcessEntry {
    DWORD pid = 0;
    std::wstring name;
    std::wstring path;
    std::wstring arch;   // "x64", "x86", "ARM64", "?"
};

struct InjectReport {
    bool ok = false;
    bool already_loaded = false;
    DWORD last_error = 0;
    std::wstring detail;

    std::uint64_t module_base = 0;
    std::wstring syscall_mode;
    bool peb_lists = false;
    bool hash = false;
    bool rb_tree = false;
    std::size_t etw_slots = 0;
    bool staged = false;
    bool staged_deleted = false;
    bool still_listed = false;
};

std::vector<ProcessEntry> list_processes();
std::wstring arch_of_process(HANDLE process);
std::wstring self_arch();
std::wstring win32_error_text(DWORD code);

// Loads dll_path through LoadLibraryExW inside pid, then performs the requested
// stealth pass. Delivery uses NtCreateThreadEx through the syscall table; the
// payload is optionally staged to a fresh file name and removed afterwards.
InjectReport inject_library(
    DWORD pid,
    const std::wstring& dll_path,
    const Config& config,
    const std::function<void(const std::wstring&)>& progress,
    const std::wstring& process_name = {});
