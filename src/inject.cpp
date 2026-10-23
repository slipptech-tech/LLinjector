#include "inject.h"

#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include <utility>
#include <vector>

namespace {

using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

// Dependencies of the injected DLL have to be looked up next to the DLL first.
// The default search order uses the target executable's directory and PATH, so
// a healthy DLL that keeps its dependencies in its own folder dies inside
// LoadLibrary with ERROR_MOD_NOT_FOUND (126). LOAD_WITH_ALTERED_SEARCH_PATH
// makes the DLL's directory the base for its whole dependency graph.
constexpr std::uint32_t kLoadWithAlteredSearchPath = 0x00000008;

// Parameter block written into the target and passed to the remote thread.
// The stub reads every address from here instead of baking them into the code,
// so one stub blob serves every injection and survives per-process ASLR.
struct RemoteCall {
    std::uint64_t path;             // +0
    std::uint64_t result;           // +8
    std::uint64_t load_library_ex;  // +16
    std::uint64_t get_last_error;   // +24
    std::uint32_t flags;            // +32
    std::uint32_t reserved;         // +36
};
static_assert(sizeof(RemoteCall) == 40, "layout is part of the stub contract");
static_assert(offsetof(RemoteCall, flags) == 32, "layout is part of the stub contract");

struct RemoteResult {
    std::uint64_t module;      // +0
    std::uint32_t load_error;  // +8
    std::uint32_t reserved;    // +12
};
static_assert(sizeof(RemoteResult) == 16, "layout is part of the stub contract");

#if defined(_WIN64)

// Stub executed inside the target. rcx holds the address of RemoteCall, which
// is exactly the shape CreateRemoteThread hands to the start routine.
//
//   sub  rsp, 38h                 ; shadow space + one local, keeps 16-byte alignment
//   mov  [rsp+20h], rcx           ; keep the parameter block across the call
//   mov  rax, [rcx+16]            ; LoadLibraryExW
//   mov  r8d, [rcx+32]            ; flags
//   xor  edx, edx                 ; hFile = nullptr
//   mov  rcx, [rcx]               ; path
//   call rax
//   ... store the module handle, or call GetLastError and store that instead
//
// The result block is zeroed by VirtualAllocEx, so a missing field means the
// corresponding step was never reached.
std::vector<std::uint8_t> build_stub() {
    std::vector<std::uint8_t> code;
    std::vector<std::pair<std::size_t, std::size_t*>> fixups;
    std::size_t load_failed = 0;
    std::size_t done = 0;

    auto bytes = [&](std::initializer_list<std::uint8_t> list) {
        code.insert(code.end(), list.begin(), list.end());
    };
    auto clear = [&](std::uint8_t condition) {
        bytes({0x0F, condition});
        const std::size_t at = code.size();
        code.resize(code.size() + 4);
        return at;
    };
    auto jump = [&]() {
        bytes({0xE9});
        const std::size_t at = code.size();
        code.resize(code.size() + 4);
        return at;
    };
    auto mark = [&]() { return code.size(); };

    bytes({0x48, 0x83, 0xEC, 0x38});        // sub rsp, 38h
    bytes({0x48, 0x89, 0x4C, 0x24, 0x20});  // mov [rsp+20h], rcx
    bytes({0x48, 0x8B, 0x41, 0x10});        // mov rax, [rcx+10h]
    bytes({0x44, 0x8B, 0x41, 0x20});        // mov r8d, [rcx+20h]
    bytes({0x33, 0xD2});                    // xor edx, edx
    bytes({0x48, 0x8B, 0x09});              // mov rcx, [rcx]
    bytes({0xFF, 0xD0});                    // call rax
    bytes({0x48, 0x8B, 0x54, 0x24, 0x20});  // mov rdx, [rsp+20h]
    bytes({0x4C, 0x8B, 0x4A, 0x08});        // mov r9, [rdx+8]
    bytes({0x48, 0x85, 0xC0});              // test rax, rax
    fixups.emplace_back(clear(0x84), &load_failed);   // jz load_failed
    bytes({0x49, 0x89, 0x01});              // mov [r9], rax
    fixups.emplace_back(jump(), &done);     // jmp done

    load_failed = mark();
    bytes({0x48, 0x8B, 0x44, 0x24, 0x20});  // mov rax, [rsp+20h]
    bytes({0x48, 0x8B, 0x40, 0x18});        // mov rax, [rax+18h]
    bytes({0xFF, 0xD0});                    // call rax
    bytes({0x48, 0x8B, 0x54, 0x24, 0x20});  // mov rdx, [rsp+20h]
    bytes({0x4C, 0x8B, 0x4A, 0x08});        // mov r9, [rdx+8]
    bytes({0x41, 0x89, 0x41, 0x08});        // mov [r9+8], eax

    done = mark();
    bytes({0x48, 0x83, 0xC4, 0x38});        // add rsp, 38h
    bytes({0x33, 0xC0});                    // xor eax, eax
    bytes({0xC3});                          // ret

    for (const auto& [at, label] : fixups) {
        const auto displacement = static_cast<std::int32_t>(*label - (at + 4));
        std::memcpy(code.data() + at, &displacement, sizeof(displacement));
    }
    return code;
}

#else

// x86 counterpart. stdcall: LoadLibraryExW pops its three arguments and the
// stub closes with `ret 4`, dropping the thread parameter the same way the
// original one-argument stub did.
std::vector<std::uint8_t> build_stub() {
    std::vector<std::uint8_t> code;
    std::vector<std::pair<std::size_t, std::size_t*>> fixups;
    std::size_t have_module = 0;
    std::size_t done = 0;

    auto bytes = [&](std::initializer_list<std::uint8_t> list) {
        code.insert(code.end(), list.begin(), list.end());
    };
    auto clear = [&](std::uint8_t condition) {
        bytes({0x0F, condition});
        const std::size_t at = code.size();
        code.resize(code.size() + 4);
        return at;
    };
    auto jump = [&]() {
        bytes({0xE9});
        const std::size_t at = code.size();
        code.resize(code.size() + 4);
        return at;
    };
    auto mark = [&]() { return code.size(); };

    bytes({0x55});                          // push ebp
    bytes({0x8B, 0xEC});                    // mov ebp, esp
    bytes({0x53});                          // push ebx
    bytes({0x56});                          // push esi
    bytes({0x57});                          // push edi
    bytes({0x8B, 0x75, 0x08});              // mov esi, [ebp+8]
    bytes({0xFF, 0x76, 0x20});              // push dword [esi+20h]
    bytes({0x6A, 0x00});                    // push 0
    bytes({0xFF, 0x36});                    // push dword [esi]
    bytes({0xFF, 0x56, 0x10});              // call dword [esi+10h]
    bytes({0x8B, 0xD8});                    // mov ebx, eax
    bytes({0x8B, 0x7E, 0x08});              // mov edi, [esi+8]
    bytes({0x85, 0xC0});                    // test eax, eax
    fixups.emplace_back(clear(0x85), &have_module);   // jnz have_module
    bytes({0xFF, 0x56, 0x18});              // call dword [esi+18h]
    bytes({0x89, 0x47, 0x08});              // mov [edi+8], eax
    fixups.emplace_back(jump(), &done);     // jmp done

    have_module = mark();
    bytes({0x89, 0x1F});                    // mov [edi], ebx

    done = mark();
    bytes({0x5F});                          // pop edi
    bytes({0x5E});                          // pop esi
    bytes({0x5B});                          // pop ebx
    bytes({0x5D});                          // pop ebp
    bytes({0x33, 0xC0});                    // xor eax, eax
    bytes({0xC2, 0x04, 0x00});              // ret 4

    for (const auto& [at, label] : fixups) {
        const auto displacement = static_cast<std::int32_t>(*label - (at + 4));
        std::memcpy(code.data() + at, &displacement, sizeof(displacement));
    }
    return code;
}

#endif

const std::vector<std::uint8_t>& loader_stub() {
    static const std::vector<std::uint8_t> stub = build_stub();
    return stub;
}

IsWow64Process2Fn is_wow64_process2() {
    static IsWow64Process2Fn fn = []() -> IsWow64Process2Fn {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!kernel32) return nullptr;
        return reinterpret_cast<IsWow64Process2Fn>(
            GetProcAddress(kernel32, "IsWow64Process2"));
    }();
    return fn;
}

std::wstring machine_name(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return L"x86";
        case IMAGE_FILE_MACHINE_AMD64: return L"x64";
        case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
        case IMAGE_FILE_MACHINE_ARMNT: return L"ARM";
        default: return L"?";
    }
}

// Reads the Machine field out of a PE image without mapping it.
WORD read_pe_machine(const std::wstring& path, std::wstring& error) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = L"не удалось открыть файл: " + win32_error_text(GetLastError());
        return 0;
    }

    WORD machine = 0;
    IMAGE_DOS_HEADER dos{};
    DWORD got = 0;

    if (ReadFile(file, &dos, sizeof(dos), &got, nullptr) && got == sizeof(dos) &&
        dos.e_magic == IMAGE_DOS_SIGNATURE) {
        LARGE_INTEGER offset{};
        offset.QuadPart = dos.e_lfanew;
        if (SetFilePointerEx(file, offset, nullptr, FILE_BEGIN)) {
            DWORD signature = 0;
            if (ReadFile(file, &signature, sizeof(signature), &got, nullptr) &&
                got == sizeof(signature) && signature == IMAGE_NT_SIGNATURE) {
                IMAGE_FILE_HEADER header{};
                if (ReadFile(file, &header, sizeof(header), &got, nullptr) &&
                    got == sizeof(header)) {
                    machine = header.Machine;
                }
            }
        }
    }

    CloseHandle(file);
    if (!machine) error = L"файл не похож на PE-библиотеку";
    return machine;
}

struct ModuleInfo {
    bool found = false;
    std::uintptr_t base = 0;
    std::uintptr_t size = 0;
};

ModuleInfo find_module(
    DWORD pid,
    const std::wstring& path,
    std::uintptr_t expected_base = 0) {
    ModuleInfo info;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return info;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            const auto base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            // The base is the loader's own answer. A path can differ by a
            // junction, an 8.3 name or a case we did not predict, so prefer the
            // address whenever LoadLibrary already told us where it mapped.
            const bool base_matches = expected_base && base == expected_base;
            const bool path_matches =
                !expected_base && _wcsicmp(entry.szExePath, path.c_str()) == 0;
            if (base_matches || path_matches) {
                info.found = true;
                info.base = base;
                info.size = entry.modBaseSize;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return info;
}

// The module list is maintained by the target loader, and a snapshot taken
// immediately after LoadLibraryExW returns can race with that update on a busy
// process. Poll briefly instead of turning a valid load into a red error.
ModuleInfo find_loaded_module(
    DWORD pid,
    const std::wstring& path,
    std::uintptr_t expected_base) {
    ModuleInfo info;
    for (int attempt = 0; attempt < 20; ++attempt) {
        info = find_module(pid, path, expected_base);
        if (info.found || expected_base == 0) return info;
        Sleep(25);
    }
    return info;
}

struct ModuleSpan {
    std::wstring name;
    std::uintptr_t base = 0;
    std::uintptr_t size = 0;
};

std::vector<ModuleSpan> module_spans(DWORD pid) {
    std::vector<ModuleSpan> spans;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return spans;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            ModuleSpan span;
            span.name = entry.szModule;
            span.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            span.size = entry.modBaseSize;
            spans.push_back(std::move(span));
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return spans;
}

const std::vector<ModuleSpan>& local_module_spans() {
    static const std::vector<ModuleSpan> spans =
        module_spans(GetCurrentProcessId());
    return spans;
}

// Kernel32 is a shared image and normally sits at the same address in every
// process of the same boot. That is an assumption, not a rule: per-process
// ASLR (ForceRelocateImages) moves it, and then a hardcoded LoadLibrary address
// sends the remote thread into unmapped memory and takes the target down.
// Mapping the offset into the module of the same name in the target removes the
// assumption. Exports forwarded to kernelbase are handled too, because the
// lookup starts from whichever module actually contains the local address.
std::uintptr_t translate_to_target(
    std::uintptr_t local_address,
    const std::vector<ModuleSpan>& local_spans,
    const std::vector<ModuleSpan>& target_spans) {

    for (const ModuleSpan& local : local_spans) {
        if (local_address < local.base || local_address >= local.base + local.size)
            continue;

        for (const ModuleSpan& target : target_spans) {
            if (_wcsicmp(target.name.c_str(), local.name.c_str()) == 0)
                return target.base + (local_address - local.base);
        }
        break;
    }

    // Snapshot denied or the module is not loaded in the target: the shared
    // image base is still right in the overwhelming majority of processes.
    return local_address;
}

std::wstring absolute_path(const std::wstring& path) {
    const DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!needed) return path;

    std::wstring full(static_cast<std::size_t>(needed), L'\0');
    const DWORD written = GetFullPathNameW(path.c_str(), needed, full.data(), nullptr);
    if (!written || written >= needed) return path;

    full.resize(written);
    return full;
}

bool is_cs2_process(const std::wstring& name) {
    return _wcsicmp(name.c_str(), L"cs2.exe") == 0 ||
           _wcsicmp(name.c_str(), L"cs2") == 0;
}

std::wstring loader_hint(DWORD code) {
    switch (code) {
        case ERROR_MOD_NOT_FOUND:
            return L"Загрузчик не нашёл зависимую DLL. Ищет он её сначала в папке самой "
                   L"DLL, затем в системных и в PATH цели. Если зависимость лежит в "
                   L"другой папке — положите её рядом с DLL или добавьте папку в PATH "
                   L"процесса. Для vcruntime140/msvcp140 поставьте Visual C++ "
                   L"Redistributable. Защищённые игры (CS2 с Trusted Mode и подобные) "
                   L"могут отдавать этот же код на любую неподписанную DLL — проверьте "
                   L"опцию запуска такой игры.";
        case ERROR_PROC_NOT_FOUND:
            return L"Зависимая DLL нашлась, но в ней нет нужной функции — версии "
                   L"не совпадают.";
        case ERROR_BAD_EXE_FORMAT:
            return L"Файл не является PE-образом нужной разрядности. Управляемая "
                   L".NET-сборка так тоже не загрузится: ей нужен CLR-хост, а не "
                   L"LoadLibrary.";
        case ERROR_ACCESS_DENIED:
            return L"Доступ к файлу запрещён: ACL, AppLocker/WDAC или защита процесса.";
        case ERROR_DLL_INIT_FAILED:
            return L"DllMain вернула FALSE — DLL сама отказалась загружаться.";
        case ERROR_INVALID_IMAGE_HASH:
            return L"Подпись образа не прошла проверку (WDAC или драйвер защиты).";
        case ERROR_ACCESS_DISABLED_BY_POLICY:
            return L"Загрузку заблокировала политика AppLocker/Software Restriction "
                   L"Policies.";
        case ERROR_NOT_ENOUGH_MEMORY:
            return L"В целевом процессе не хватило памяти под образ DLL.";
        default:
            return L"";
    }
}

// Turns on SeDebugPrivilege. An elevated token carries it but leaves it
// disabled, and without it an administrator can be refused PROCESS_VM_WRITE on
// a process owned by the interactive user -- the exact opposite of what
// elevation is supposed to buy.
bool enable_debug_privilege() {
    static const bool enabled = []() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return false;

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
            CloseHandle(token);
            return false;
        }

        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(ERROR_SUCCESS);
        const BOOL ok = AdjustTokenPrivileges(token, FALSE, &privileges,
                                              sizeof(privileges), nullptr, nullptr);
        const DWORD error = GetLastError();
        CloseHandle(token);
        return ok && error == ERROR_SUCCESS;
    }();
    return enabled;
}

struct HandleGuard {
    HANDLE value = nullptr;
    ~HandleGuard() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
};

// Frees a block in the target before the process handle is closed, which is
// why the guards are declared after the process guard.
struct RemoteGuard {
    HANDLE process = nullptr;
    void* address = nullptr;
    ~RemoteGuard() {
        if (process && address) VirtualFreeEx(process, address, 0, MEM_RELEASE);
    }
};

std::wstring hex_value(std::uint64_t value) {
    wchar_t buffer[32];
    swprintf_s(buffer, L"0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

}  // namespace

std::wstring win32_error_text(DWORD code) {
    wchar_t* buffer = nullptr;
    DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring text;
    if (length && buffer) {
        text.assign(buffer, length);
        while (!text.empty() &&
               (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' '))
            text.pop_back();
    } else {
        text = L"неизвестная ошибка";
    }
    if (buffer) LocalFree(buffer);

    wchar_t suffix[32];
    swprintf_s(suffix, L" (%lu)", code);
    return text + suffix;
}

std::wstring self_arch() {
#if defined(_M_ARM64)
    return L"ARM64";
#elif defined(_WIN64)
    return L"x64";
#else
    return L"x86";
#endif
}

std::wstring arch_of_process(HANDLE process) {
    if (!process) return L"?";

    if (IsWow64Process2Fn query = is_wow64_process2()) {
        USHORT process_machine = 0;
        USHORT native_machine = 0;
        if (query(process, &process_machine, &native_machine)) {
            // UNKNOWN means "not running under WOW64": the process is native.
            if (process_machine == IMAGE_FILE_MACHINE_UNKNOWN)
                process_machine = native_machine;
            return machine_name(process_machine);
        }
    }

    BOOL wow64 = FALSE;
    if (IsWow64Process(process, &wow64)) {
#if defined(_WIN64)
        return wow64 ? L"x86" : self_arch();
#else
        (void)wow64;
        return L"x86";
#endif
    }
    return L"?";
}

std::vector<ProcessEntry> list_processes() {
    std::vector<ProcessEntry> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            ProcessEntry process;
            process.pid = entry.th32ProcessID;
            process.name = entry.szExeFile;
            if (process.name.empty()) continue;   // System Idle (0) and friends

            HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid);
            if (handle) {
                wchar_t path[32768];
                DWORD length = static_cast<DWORD>(ARRAYSIZE(path));
                if (QueryFullProcessImageNameW(handle, 0, path, &length))
                    process.path.assign(path, length);
                process.arch = arch_of_process(handle);
                CloseHandle(handle);
            }

            processes.push_back(std::move(process));
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processes;
}

InjectResult inject_loadlibrary(
    DWORD pid,
    const std::wstring& dll_path,
    const std::function<void(const std::wstring&)>& progress,
    const std::wstring& process_name) {

    InjectResult result;
    auto note = [&](const std::wstring& text) {
        if (progress) progress(text);
    };

    // Normalise once. A module list always reports full paths, so a relative
    // path from the command line would never match what the target loaded.
    const std::wstring resolved = absolute_path(dll_path);

    if (is_cs2_process(process_name)) {
        note(L"CS2: для загрузки неподписанной DLL нужен запуск с "
             L"-allow_third_party_software (Trusted Mode).");
    }

    // Reject the obvious mistakes before touching the target at all.
    std::wstring file_error;
    const WORD dll_machine = read_pe_machine(resolved, file_error);
    if (!dll_machine) {
        result.detail = file_error;
        return result;
    }

    HandleGuard process;
    enable_debug_privilege();
    process.value = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                FALSE, pid);
    if (!process.value) {
        result.last_error = GetLastError();
        result.detail = L"OpenProcess: " + win32_error_text(result.last_error);
        if (result.last_error == ERROR_ACCESS_DENIED) {
            result.detail += L"\nПроцесс защищён системой, либо запущен от другого "
                             L"пользователя. Запустите инжектор от администратора.";
        } else if (result.last_error == ERROR_INVALID_PARAMETER) {
            result.detail += L"\nПроцесс уже завершился.";
        }
        return result;
    }

    const std::wstring target_arch = arch_of_process(process.value);
    note(L"цель: " + target_arch + L", инжектор: " + self_arch() +
         L", DLL: " + machine_name(dll_machine));

    if (target_arch != L"?" && target_arch != self_arch()) {
        result.detail = L"Процесс " + target_arch + L", а инжектор " + self_arch() +
                        L".\nНужна сборка той же разрядности: " +
                        (target_arch == L"x86" ? L"LLInjector_x86.exe" : L"LLInjector.exe");
        return result;
    }

    if (machine_name(dll_machine) != target_arch && target_arch != L"?") {
        result.detail = L"Разрядность DLL (" + machine_name(dll_machine) +
                        L") не совпадает с процессом (" + target_arch + L").\n"
                        L"Если это управляемая .NET-сборка, LoadLibrary её всё равно "
                        L"не загрузит: ей нужен CLR-хост.";
        return result;
    }

    const ModuleInfo before = find_module(pid, resolved);
    if (before.found) {
        result.ok = true;
        result.already_loaded = true;
        result.detail = L"Эта DLL уже загружена в процесс, база " +
                        hex_value(before.base) +
                        L". Повторный LoadLibrary не вызовет DllMain — "
                        L"перезапустите целевой процесс для чистой загрузки.";
        note(result.detail);
        return result;
    }

    // One allocation holds the parameter block and the wide path. The stub
    // receives its address as the thread parameter.
    constexpr std::size_t kPathOffset = 64;
    const std::size_t path_bytes = (resolved.size() + 1) * sizeof(wchar_t);
    const std::size_t block_bytes = kPathOffset + path_bytes;

    std::vector<std::uint8_t> call_block(block_bytes, 0);
    std::memcpy(call_block.data() + kPathOffset, resolved.c_str(), path_bytes);

    RemoteGuard remote_call;
    remote_call.process = process.value;
    remote_call.address = VirtualAllocEx(process.value, nullptr, block_bytes,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_call.address) {
        result.last_error = GetLastError();
        result.detail = L"VirtualAllocEx (аргументы): " + win32_error_text(result.last_error);
        return result;
    }

    RemoteGuard remote_out;
    remote_out.process = process.value;
    remote_out.address = VirtualAllocEx(process.value, nullptr, 64,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_out.address) {
        result.last_error = GetLastError();
        result.detail = L"VirtualAllocEx (результат): " + win32_error_text(result.last_error);
        return result;
    }

    const auto call_address = reinterpret_cast<std::uintptr_t>(remote_call.address);
    const auto out_address = reinterpret_cast<std::uintptr_t>(remote_out.address);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const FARPROC load_library = kernel32 ? GetProcAddress(kernel32, "LoadLibraryExW") : nullptr;
    const FARPROC get_last_error = kernel32 ? GetProcAddress(kernel32, "GetLastError") : nullptr;
    if (!load_library || !get_last_error) {
        result.detail = L"не удалось получить адреса LoadLibraryExW/GetLastError";
        return result;
    }

    const std::vector<ModuleSpan>& local_spans = local_module_spans();
    const std::vector<ModuleSpan> target_spans = module_spans(pid);
    const std::uintptr_t remote_load = translate_to_target(
        reinterpret_cast<std::uintptr_t>(load_library), local_spans, target_spans);
    const std::uintptr_t remote_error = translate_to_target(
        reinterpret_cast<std::uintptr_t>(get_last_error), local_spans, target_spans);
    note(L"LoadLibraryExW: " + hex_value(remote_load));

    RemoteCall call{};
    call.path = call_address + kPathOffset;
    call.result = out_address;
    call.load_library_ex = remote_load;
    call.get_last_error = remote_error;
    call.flags = kLoadWithAlteredSearchPath;
    std::memcpy(call_block.data(), &call, sizeof(call));

    SIZE_T written = 0;
    if (!WriteProcessMemory(process.value, remote_call.address, call_block.data(),
                            call_block.size(), &written) ||
        written != call_block.size()) {
        result.last_error = GetLastError();
        result.detail = L"WriteProcessMemory (аргументы): " +
                        win32_error_text(result.last_error);
        return result;
    }
    note(L"аргументы записаны по адресу " + hex_value(call_address));

    const std::vector<std::uint8_t>& stub = loader_stub();
    RemoteGuard remote_stub;
    remote_stub.process = process.value;
    remote_stub.address = VirtualAllocEx(process.value, nullptr, stub.size(),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_stub.address) {
        result.last_error = GetLastError();
        result.detail = L"VirtualAllocEx (код): " + win32_error_text(result.last_error);
        return result;
    }

    if (!WriteProcessMemory(process.value, remote_stub.address, stub.data(),
                            stub.size(), &written) ||
        written != stub.size()) {
        result.last_error = GetLastError();
        result.detail = L"WriteProcessMemory (код): " + win32_error_text(result.last_error);
        return result;
    }

    // The stub never writes to itself; dropping the write bit keeps the page
    // out of the heap of RWX regions a scanner flags first.
    DWORD previous = 0;
    VirtualProtectEx(process.value, remote_stub.address, stub.size(),
                     PAGE_EXECUTE_READ, &previous);
    FlushInstructionCache(process.value, remote_stub.address, stub.size());

    HandleGuard thread;
    thread.value = CreateRemoteThread(
        process.value, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_stub.address),
        remote_call.address, 0, nullptr);
    if (!thread.value) {
        result.last_error = GetLastError();
        result.detail = L"CreateRemoteThread: " + win32_error_text(result.last_error);
        return result;
    }

    note(L"поток создан, ожидание LoadLibraryExW");
    const DWORD wait = WaitForSingleObject(thread.value, 30000);

    RemoteResult remote{};
    SIZE_T got = 0;
    const bool read_ok =
        ReadProcessMemory(process.value, remote_out.address, &remote,
                          sizeof(remote), &got) && got == sizeof(remote);

    if (wait == WAIT_TIMEOUT) {
        // A module handle already stored means the loader finished and the
        // thread is still inside DllMain. That is loaded, just not returned.
        if (read_ok && remote.module) {
            result.ok = true;
            result.detail = L"DLL загружена, база " + hex_value(remote.module) +
                            L", но поток не завершился за 30 секунд: DllMain, судя "
                            L"по всему, ещё работает.";
            return result;
        }
        result.detail = L"LoadLibraryExW не завершилась за 30 секунд: DllMain, "
                        L"судя по всему, завис.";
        return result;
    }
    if (wait != WAIT_OBJECT_0) {
        result.last_error = GetLastError();
        result.detail = L"WaitForSingleObject: " + win32_error_text(result.last_error);
        return result;
    }

    if (!read_ok) {
        result.last_error = GetLastError();
        result.detail = L"не удалось прочитать результат из целевого процесса: " +
                        win32_error_text(result.last_error);
        return result;
    }

    if (!remote.module) {
        result.last_error = remote.load_error;
        result.detail = L"LoadLibraryExW вернула NULL: " +
                        win32_error_text(remote.load_error);
        if (remote.load_error == ERROR_MOD_NOT_FOUND && is_cs2_process(process_name)) {
            result.detail += L"\nCS2 запущена в Trusted Mode: она блокирует загрузку "
                             L"неподписанных DLL и возвращает ошибку 126. Закройте CS2, "
                             L"добавьте -allow_third_party_software в параметры запуска "
                             L"(Steam -> CS2 -> Свойства -> Параметры запуска), запустите "
                             L"игру заново и повторите инъекцию. VAC/Trusted Mode при этом "
                             L"отключаются.";
        } else {
            const std::wstring hint = loader_hint(remote.load_error);
            if (!hint.empty()) result.detail += L"\n" + hint;
        }
        return result;
    }

    note(L"LoadLibraryExW вернула " + hex_value(remote.module));

#if defined(_WIN64)
    const auto module_base = static_cast<std::uintptr_t>(remote.module);
#else
    const auto module_base = static_cast<std::uintptr_t>(
        static_cast<std::uint32_t>(remote.module));
#endif

    const ModuleInfo after = find_loaded_module(pid, resolved, module_base);
    if (after.found) {
        result.ok = true;
        result.detail = L"DLL загружена, база " + hex_value(after.base) + L".";
        return result;
    }

    // The handle is authoritative, but a stale or filtered module snapshot
    // should not turn a real load into a failure. Confirm that the loader's
    // answer points at a PE image in the target before deciding.
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS nt{};
    SIZE_T read = 0;
    const auto base = module_base;
    const bool pe_ok =
        base &&
        ReadProcessMemory(process.value, reinterpret_cast<LPCVOID>(base),
                          &dos, sizeof(dos), &read) &&
        read == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        dos.e_lfanew > 0 && dos.e_lfanew < 0x10000000 &&
        ReadProcessMemory(process.value,
                          reinterpret_cast<LPCVOID>(base + dos.e_lfanew),
                          &nt, sizeof(nt), &read) &&
        read == sizeof(nt) && nt.Signature == IMAGE_NT_SIGNATURE;

    if (pe_ok) {
        result.ok = true;
        result.detail = L"DLL загружена, база " + hex_value(remote.module) +
                        L". Модуль не попал в снимок списка загруженных, но "
                        L"PE-заголовок по этому адресу корректен.";
        return result;
    }

    result.ok = false;
    result.last_error = ERROR_MOD_NOT_FOUND;
    result.detail = L"LoadLibraryExW вернула " + hex_value(remote.module) +
                    L", но модуль не найден и память по этому адресу не является "
                    L"PE-образом. Целевой процесс мог завершиться во время инъекции.";
    return result;
}
