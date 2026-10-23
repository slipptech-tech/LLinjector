// Test payload: proves the injector really loaded this DLL into a foreign
// process. DllMain drops a file in %TEMP% named after the host pid and records
// where the module was mapped from.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(instance);

    wchar_t temp[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, temp)) return TRUE;

    wchar_t marker[MAX_PATH] = {};
    swprintf_s(marker, L"%sLLInjector_payload_%lu.txt", temp, GetCurrentProcessId());

    wchar_t module[MAX_PATH] = {};
    GetModuleFileNameW(instance, module, MAX_PATH);

    HANDLE file = CreateFileW(marker, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return TRUE;

    char utf8[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_UTF8, 0, module, -1, utf8, sizeof(utf8) - 1, nullptr, nullptr);

    char line[MAX_PATH * 4 + 64] = {};
    _snprintf_s(line, sizeof(line), _TRUNCATE,
                "loaded in pid %lu\r\nmodule: %s\r\n", GetCurrentProcessId(), utf8);

    DWORD written = 0;
    WriteFile(file, line, static_cast<DWORD>(strlen(line)), &written, nullptr);
    CloseHandle(file);

    return TRUE;
}
