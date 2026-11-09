// Verification payload. It records what the loader APIs answer about itself
// several seconds after injection, i.e. after the injector has unlinked it.
// The log lands in %TEMP%\LLInjector_verify_<pid>.txt.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdio>
#include <string>

// Linked from ntdll.lib on purpose: this must be a real IAT import so the
// injector's EtwEventWrite patch can be observed from inside the payload.
extern "C" __declspec(dllimport) unsigned long __stdcall EtwEventWrite(
    unsigned long long registration, const void* descriptor,
    unsigned long count, const void* data);

namespace {

std::uintptr_t g_base = 0;
std::wstring g_path;
std::wstring g_name;
DWORD g_pid = 0;

std::wstring temp_directory() {
    wchar_t buffer[MAX_PATH * 2] = {};
    const DWORD length = GetTempPathW(ARRAYSIZE(buffer), buffer);
    if (!length || length >= ARRAYSIZE(buffer)) return L".";
    return std::wstring(buffer, length);
}

std::wstring base_name_of(const std::wstring& path) {
    const std::size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

bool module_in_toolhelp(std::uintptr_t base) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                               GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    bool found = false;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (reinterpret_cast<std::uintptr_t>(entry.modBaseAddr) == base) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

bool write_utf8(const std::wstring& path, const std::wstring& text) {
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                           static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return false;
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        utf8.data(), needed, nullptr, nullptr);

    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    const BOOL ok = WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()),
                              &wrote, nullptr);
    CloseHandle(file);
    return ok && wrote == utf8.size();
}

unsigned long call_etw_safely() {
    __try {
        return EtwEventWrite(0, nullptr, 0, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFEul;
    }
}

DWORD WINAPI worker(void*) {
    Sleep(8000);

    SetLastError(0);
    HMODULE by_name = GetModuleHandleW(g_name.c_str());
    const DWORD name_error = GetLastError();

    SetLastError(0);
    HMODULE by_address = nullptr;
    const BOOL address_ok = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&worker), &by_address);
    const DWORD address_error = GetLastError();

    const bool listed = module_in_toolhelp(g_base);
    const DWORD file_attributes = GetFileAttributesW(g_path.c_str());

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    std::uintptr_t pc_to_file = 0;
    std::uintptr_t ldr_entry = 0;
    LONG ldr_status = 0;
    if (ntdll) {
        using RtlPcToFileHeaderFn = PVOID(WINAPI*)(PVOID, PVOID*);
        if (const auto pc_fn = reinterpret_cast<RtlPcToFileHeaderFn>(
                GetProcAddress(ntdll, "RtlPcToFileHeader"))) {
            PVOID image_base = nullptr;
            pc_fn(reinterpret_cast<PVOID>(&worker), &image_base);
            pc_to_file = reinterpret_cast<std::uintptr_t>(image_base);
        }
        using LdrFindEntryForAddressFn = LONG(NTAPI*)(PVOID, PVOID*);
        if (const auto ldr_fn = reinterpret_cast<LdrFindEntryForAddressFn>(
                GetProcAddress(ntdll, "LdrFindEntryForAddress"))) {
            PVOID entry = nullptr;
            ldr_status = ldr_fn(reinterpret_cast<PVOID>(&worker), &entry);
            ldr_entry = reinterpret_cast<std::uintptr_t>(entry);
        }
    }

    wchar_t line[512];
    std::wstring report;
    swprintf_s(line, L"pid=%lu\n", g_pid);
    report += line;
    swprintf_s(line, L"base=0x%llX\n",
               static_cast<unsigned long long>(g_base));
    report += line;
    swprintf_s(line, L"path=%s\n", g_path.c_str());
    report += line;
    swprintf_s(line, L"name=%s\n", g_name.c_str());
    report += line;
    swprintf_s(line, L"by_name=0x%llX\n",
               static_cast<unsigned long long>(
                   reinterpret_cast<std::uintptr_t>(by_name)));
    report += line;
    swprintf_s(line, L"by_name_error=%lu\n", name_error);
    report += line;
    swprintf_s(line, L"by_address=0x%llX\n",
               static_cast<unsigned long long>(
                   reinterpret_cast<std::uintptr_t>(by_address)));
    report += line;
    swprintf_s(line, L"by_address_ok=%d\n", address_ok ? 1 : 0);
    report += line;
    swprintf_s(line, L"by_address_error=%lu\n", address_error);
    report += line;
    swprintf_s(line, L"toolhelp=%d\n", listed ? 1 : 0);
    report += line;
    swprintf_s(line, L"file_exists=%d\n",
               file_attributes != INVALID_FILE_ATTRIBUTES ? 1 : 0);
    report += line;
    swprintf_s(line, L"pc_to_file=0x%llX\n",
               static_cast<unsigned long long>(pc_to_file));
    report += line;
    swprintf_s(line, L"ldr_find_status=0x%08lX\n",
               static_cast<unsigned long>(ldr_status));
    report += line;
    swprintf_s(line, L"ldr_find_entry=0x%llX\n",
               static_cast<unsigned long long>(ldr_entry));
    report += line;
    report += L"etw_return=pending\n";

    wchar_t name[64];
    swprintf_s(name, L"LLInjector_verify_%lu.txt", g_pid);
    const std::wstring out = temp_directory() + name;

    // Write the loader results before the ETW call. If a third-party ETW
    // redirect is missing, the partial file still shows what was verified.
    write_utf8(out, report);

    wchar_t etw_line[64];
    swprintf_s(etw_line, L"etw_return=0x%08lX\n", call_etw_safely());
    const std::wstring pending_line = L"etw_return=pending\n";
    const std::size_t pending = report.find(pending_line);
    if (pending != std::wstring::npos)
        report.replace(pending, pending_line.size(), etw_line);
    write_utf8(out, report);
    return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        g_base = reinterpret_cast<std::uintptr_t>(module);
        g_pid = GetCurrentProcessId();

        wchar_t path[32768] = {};
        const DWORD length = GetModuleFileNameW(module, path, ARRAYSIZE(path));
        if (length && length < ARRAYSIZE(path)) g_path.assign(path, length);
        g_name = base_name_of(g_path);

        HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
