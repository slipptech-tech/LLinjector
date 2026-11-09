// Delivery: avoids the Win32 remote-thread API by calling NtCreateThreadEx
// through the runtime syscall table; the load itself is LoadLibraryExW.
// Remains: kernel thread/image-load callbacks, ETW-TI and the image section/VAD.

#include "injector.h"

#include "cleanup.h"
#include "etw.h"
#include "syscalls.h"
#include "unlink.h"

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

constexpr std::uint32_t kLoadWithAlteredSearchPath = 0x00000008;

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

// The loader stub. rcx is the parameter block (NtCreateThreadEx hands the
// start argument over exactly like the thread entry does).
std::vector<std::uint8_t> build_loader_stub() {
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
    fixups.emplace_back(clear(0x84), &load_failed);
    bytes({0x49, 0x89, 0x01});              // mov [r9], rax
    fixups.emplace_back(jump(), &done);

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

std::vector<std::uint8_t> build_loader_stub() {
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
    fixups.emplace_back(clear(0x85), &have_module);
    bytes({0xFF, 0x56, 0x18});              // call dword [esi+18h]
    bytes({0x89, 0x47, 0x08});              // mov [edi+8], eax
    fixups.emplace_back(jump(), &done);

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
    static const std::vector<std::uint8_t> stub = build_loader_stub();
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

ModuleInfo find_module(DWORD pid, const std::wstring& path,
                       std::uintptr_t expected_base = 0) {
    ModuleInfo info;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return info;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            const auto base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            const bool base_matches = expected_base && base == expected_base;
            const bool path_matches =
                !expected_base && !path.empty() && _wcsicmp(entry.szExePath, path.c_str()) == 0;
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
    static const std::vector<ModuleSpan> spans = module_spans(GetCurrentProcessId());
    return spans;
}

std::uintptr_t translate_to_target(std::uintptr_t local_address,
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

std::wstring hex_value(std::uint64_t value) {
    wchar_t buffer[32];
    swprintf_s(buffer, L"0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

struct ProcessClose {
    HANDLE handle = nullptr;
    ~ProcessClose() {
        if (handle) nt::close_handle(handle);
    }
};

struct ThreadClose {
    HANDLE handle = nullptr;
    ~ThreadClose() {
        if (handle) nt::close_handle(handle);
    }
};

struct RemoteBlocks {
    HANDLE process = nullptr;
    std::vector<std::uintptr_t> blocks;
    bool armed = true;

    void add(std::uintptr_t address) {
        if (address) blocks.push_back(address);
    }
    ~RemoteBlocks() {
        if (!armed) return;
        for (std::uintptr_t address : blocks) {
            std::wstring ignored;
            nt::free_memory(process, address, 0, ignored);
        }
    }
};

struct EtwCleanup {
    etw::State* state = nullptr;
    bool keep = false;
    std::function<void(const std::wstring&)> log;
    ~EtwCleanup() {
        if (!keep && state) etw::restore(*state, log);
    }
};

struct StageCleanup {
    cleanup::StagedFile* file = nullptr;
    const Config* config = nullptr;
    std::function<void(const std::wstring&)> log;
    bool armed = true;
    ~StageCleanup() {
        if (!armed || !file || !config || !file->created) return;
        if (!config->delete_staged) {
            if (log) log(L"cleanup: staged copy kept: " + file->path);
            return;
        }
        std::wstring detail;
        cleanup::remove(*file, detail);
        if (log) log(L"cleanup: " + detail);
    }
};

bool allocate_remote(nt::Table& table, HANDLE process, std::size_t size,
                     std::uintptr_t& address, std::wstring& error) {
    SIZE_T region = size;
    const LONG status = table.allocate(process, reinterpret_cast<PVOID*>(&address), 0,
                                       &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!nt::ok(status) || !address) {
        error = L"NtAllocateVirtualMemory " + nt::status_text(status);
        return false;
    }
    return true;
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
            if (process.name.empty()) continue;

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

InjectReport inject_library(
    DWORD pid,
    const std::wstring& dll_path,
    const Config& config,
    const std::function<void(const std::wstring&)>& progress,
    const std::wstring& process_name) {

    InjectReport report;
    const auto note = [&](const std::wstring& text) {
        if (progress) progress(text);
    };

    std::wstring nt_error;
    nt::Table& table = nt::init(config.direct_syscalls, nt_error);
    report.syscall_mode = table.mode;
    note(L"NT: " + table.mode);
    if (!table.open_process || !table.allocate || !table.free || !table.protect ||
        !table.write || !table.read || !table.create_thread || !table.wait ||
        !table.terminate_thread || !table.close || !table.query_information) {
        report.detail = L"NT-слой не инициализирован: " + table.mode;
        note(L"ошибка: " + report.detail);
        return report;
    }

    const std::wstring resolved = absolute_path(dll_path);
    if (is_cs2_process(process_name)) {
        note(L"CS2: для загрузки неподписанной DLL нужен запуск с "
             L"-allow_third_party_software (Trusted Mode).");
    }

    std::wstring file_error;
    const WORD dll_machine = read_pe_machine(resolved, file_error);
    if (!dll_machine) {
        report.detail = file_error;
        note(L"ошибка: " + report.detail);
        return report;
    }

    enable_debug_privilege();

    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, nullptr, 0, nullptr, nullptr);
    nt::ClientId client;
    client.process = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    client.thread = nullptr;

    HANDLE process = nullptr;
    const LONG open_status = table.open_process(
        &process,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ,
        &attributes, &client);
    if (!nt::ok(open_status) || !process) {
        report.detail = L"NtOpenProcess: " + nt::status_text(open_status);
        if (open_status == static_cast<LONG>(0xC0000022)) {
            report.detail += L"\nПроцесс защищён системой, либо запущен от другого "
                             L"пользователя. Запустите инжектор от администратора.";
        }
        note(L"ошибка: " + report.detail);
        return report;
    }
    ProcessClose process_guard{process};

    const std::wstring target_arch = arch_of_process(process);
    note(L"цель: " + target_arch + L", инжектор: " + self_arch() +
         L", DLL: " + machine_name(dll_machine));
    if (target_arch != L"?" && target_arch != self_arch()) {
        report.detail = L"Процесс " + target_arch + L", а инжектор " + self_arch() +
                        L".\nНужна сборка той же разрядности: " +
                        (target_arch == L"x86" ? L"LLInjector_x86.exe" : L"LLInjector.exe");
        note(L"ошибка: " + report.detail);
        return report;
    }
    if (target_arch != L"?" && machine_name(dll_machine) != target_arch) {
        report.detail = L"Разрядность DLL (" + machine_name(dll_machine) +
                        L") не совпадает с процессом (" + target_arch + L").\n"
                        L"Если это управляемая .NET-сборка, LoadLibrary её всё равно "
                        L"не загрузит: ей нужен CLR-хост.";
        note(L"ошибка: " + report.detail);
        return report;
    }

    const ModuleInfo before = find_module(pid, resolved);
    if (before.found) {
        report.ok = true;
        report.already_loaded = true;
        report.detail = L"Эта DLL уже загружена в процесс, база " +
                        hex_value(before.base) +
                        L". Повторный LoadLibrary не вызовет DllMain — "
                        L"перезапустите целевой процесс для чистой загрузки.";
        note(report.detail);
        return report;
    }

    // Stage the image under a fresh name. The source folder is preferred so
    // sibling dependencies still resolve; otherwise %TEMP% is used. The file
    // is deleted after mapping, never the user's original.
    cleanup::StagedFile staged;
    std::wstring payload = resolved;
    if (config.stage) {
        std::wstring stage_error;
        if (cleanup::stage(resolved, staged, stage_error)) {
            payload = staged.path;
            report.staged = true;
            note(L"staging: " + payload);
        } else {
            note(L"staging недоступен, загружаю исходный путь: " + stage_error);
        }
    } else {
        note(L"staging отключён, используется исходный путь");
    }

    StageCleanup stage_guard{&staged, &config,
                             [&](const std::wstring& text) { note(text); }, true};

    etw::State etw_state;
    EtwCleanup etw_guard{&etw_state, false,
                         [&](const std::wstring& text) { note(text); }};

    RemoteBlocks remote{process};
    ThreadClose thread_guard;

    auto fail = [&](std::wstring detail, DWORD error = 0) -> InjectReport {
        report.ok = false;
        report.last_error = error;
        report.detail = std::move(detail);
        note(L"ошибка: " + report.detail);
        return report;
    };

    auto success = [&](const std::wstring& detail) -> InjectReport {
        if (staged.created && config.delete_staged) {
            std::wstring removal;
            report.staged_deleted = cleanup::remove(staged, removal);
            note(L"cleanup: " + removal);
        } else if (staged.created) {
            note(L"cleanup: staged copy kept: " + staged.path);
        }
        stage_guard.armed = false;
        etw_guard.keep = true;
        report.ok = true;
        report.detail = detail;
        note(detail);
        return report;
    };

    if (config.suppress_etw) {
        note(L"ETW: подавление через IAT до загрузки");
        etw::suppress(process, pid, table, etw_state,
                      [&](const std::wstring& text) { note(text); });
    } else {
        note(L"ETW: отключено конфигурацией");
    }

    // Parameter block: RemoteCall followed by the wide payload path.
    constexpr std::size_t kPathOffset = 64;
    const std::size_t path_bytes = (payload.size() + 1) * sizeof(wchar_t);
    const std::size_t block_bytes = kPathOffset + path_bytes;
    std::vector<std::uint8_t> call_block(block_bytes, 0);
    std::memcpy(call_block.data() + kPathOffset, payload.c_str(), path_bytes);

    std::uintptr_t remote_call = 0;
    std::wstring alloc_error;
    if (!allocate_remote(table, process, block_bytes, remote_call, alloc_error))
        return fail(alloc_error);
    remote.add(remote_call);

    std::uintptr_t remote_out = 0;
    if (!allocate_remote(table, process, 64, remote_out, alloc_error))
        return fail(alloc_error);
    remote.add(remote_out);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const FARPROC load_library = kernel32 ? GetProcAddress(kernel32, "LoadLibraryExW") : nullptr;
    const FARPROC get_last_error = kernel32 ? GetProcAddress(kernel32, "GetLastError") : nullptr;
    if (!load_library || !get_last_error)
        return fail(L"не удалось получить адреса LoadLibraryExW/GetLastError");

    const std::vector<ModuleSpan>& local_spans = local_module_spans();
    const std::vector<ModuleSpan> target_spans = module_spans(pid);
    const std::uintptr_t remote_load = translate_to_target(
        reinterpret_cast<std::uintptr_t>(load_library), local_spans, target_spans);
    const std::uintptr_t remote_error = translate_to_target(
        reinterpret_cast<std::uintptr_t>(get_last_error), local_spans, target_spans);
    note(L"LoadLibraryExW: " + hex_value(remote_load));

    RemoteCall call{};
    call.path = remote_call + kPathOffset;
    call.result = remote_out;
    call.load_library_ex = remote_load;
    call.get_last_error = remote_error;
    call.flags = kLoadWithAlteredSearchPath;
    std::memcpy(call_block.data(), &call, sizeof(call));

    if (!nt::write_memory(process, remote_call, call_block.data(), call_block.size(),
                          alloc_error))
        return fail(alloc_error);

    const std::vector<std::uint8_t>& stub = loader_stub();
    std::uintptr_t remote_stub = 0;
    if (!allocate_remote(table, process, 4096, remote_stub, alloc_error))
        return fail(alloc_error);
    remote.add(remote_stub);

    if (!nt::write_memory(process, remote_stub, stub.data(), stub.size(), alloc_error))
        return fail(alloc_error);

    ULONG previous = 0;
    if (!nt::protect_memory(process, remote_stub, 4096, PAGE_EXECUTE_READ, previous,
                            alloc_error))
        return fail(alloc_error);
    FlushInstructionCache(process, reinterpret_cast<LPCVOID>(remote_stub), stub.size());

    HANDLE thread = nt::create_remote_thread(process, remote_stub, remote_call, alloc_error);
    if (!thread) return fail(alloc_error);
    thread_guard.handle = thread;

    note(L"поток создан (NtCreateThreadEx), ожидание LoadLibraryExW");
    bool timed_out = false;
    std::wstring wait_error;
    const bool waited = nt::wait_handle(thread, config.wait_ms ? config.wait_ms : 30000,
                                        timed_out, wait_error);

    RemoteResult remote_result{};
    const bool result_read = nt::read_memory(process, remote_out, &remote_result,
                                             sizeof(remote_result), alloc_error);

    if (!waited || timed_out) {
        std::wstring detail;
        if (!waited) {
            detail = L"NtWaitForSingleObject: " + wait_error;
        } else {
            detail = L"LoadLibraryExW не завершилась за " +
                     std::to_wstring(config.wait_ms ? config.wait_ms : 30000) +
                     L" мс: DllMain, судя по всему, завис.";
        }
        if (result_read && remote_result.module) {
            detail += L" Модуль уже получил базу " +
                      hex_value(remote_result.module) + L", но поток не завершился.";
        }

        bool exited = false;
        if (config.terminate_on_timeout) {
            table.terminate_thread(thread, 0);
            std::wstring ignored;
            bool ignored_timeout = false;
            exited = nt::wait_handle(thread, 2000, ignored_timeout, ignored) &&
                     !ignored_timeout;
            note(exited ? L"поток принудительно завершён"
                        : L"поток не завершился даже после NtTerminateThread");
        }
        if (!exited) {
            remote.armed = false;
            detail += L"\nПамять удалённого стаба не освобождена, чтобы не уронить "
                      L"процесс: поток может всё ещё исполняться.";
        }
        return fail(detail);
    }

    if (!result_read) return fail(alloc_error);

    if (!remote_result.module) {
        report.last_error = remote_result.load_error;
        std::wstring detail = L"LoadLibraryExW вернула NULL: " +
                              win32_error_text(remote_result.load_error);
        if (remote_result.load_error == ERROR_MOD_NOT_FOUND &&
            is_cs2_process(process_name)) {
            detail += L"\nCS2 запущена в Trusted Mode: она блокирует загрузку "
                      L"неподписанных DLL и возвращает ошибку 126. Закройте CS2, "
                      L"добавьте -allow_third_party_software в параметры запуска, "
                      L"запустите игру заново и повторите инъекцию.";
        } else {
            const std::wstring hint = loader_hint(remote_result.load_error);
            if (!hint.empty()) detail += L"\n" + hint;
        }
        return fail(detail, remote_result.load_error);
    }

    note(L"LoadLibraryExW вернула " + hex_value(remote_result.module));

#if defined(_WIN64)
    const std::uintptr_t module_base = static_cast<std::uintptr_t>(remote_result.module);
#else
    const std::uintptr_t module_base = static_cast<std::uintptr_t>(
        static_cast<std::uint32_t>(remote_result.module));
#endif
    report.module_base = module_base;

    const ModuleInfo after_load = find_module(pid, L"", module_base);
    if (!after_load.found) {
        // The handle is authoritative; verify it points at a PE image anyway so
        // a stale return value cannot turn into a "success" we then unlink.
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS nt{};
        std::wstring read_error;
        const bool pe_ok =
            nt::read_memory(process, module_base, &dos, sizeof(dos), read_error) &&
            dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 &&
            dos.e_lfanew < 0x10000000 &&
            nt::read_memory(process, module_base + dos.e_lfanew, &nt, sizeof(nt),
                            read_error) &&
            nt.Signature == IMAGE_NT_SIGNATURE;
        if (!pe_ok) {
            return fail(L"LoadLibraryExW вернула " + hex_value(remote_result.module) +
                        L", но память по адресу не является PE-образом. Целевой "
                        L"процесс мог завершиться во время инъекции.");
        }
        note(L"модуль не попал в снимок Toolhelp сразу после загрузки, PE по базе верен");
    }

    if (config.suppress_etw) {
        const std::size_t added = etw::suppress(
            process, pid, table, etw_state,
            [&](const std::wstring& text) { note(text); });
        note(L"ETW: добавлено слотов после загрузки: " + std::to_wstring(added));
    }
    report.etw_slots = etw_state.patches.size();

    note(L"unlink: удаление модуля из структур загрузчика");
    const loader_unlink::Report link = loader_unlink::hide(
        process, module_base, config,
        [&](const std::wstring& text) { note(text); });
    report.peb_lists = link.peb_lists;
    report.hash = link.hash;
    report.rb_tree = link.rb_tree;
    note(L"unlink: " + link.detail);

    ModuleInfo after_unlink = find_module(pid, L"", module_base);
    for (int attempt = 0; attempt < 10 && after_unlink.found; ++attempt) {
        Sleep(10);
        after_unlink = find_module(pid, L"", module_base);
    }
    report.still_listed = after_unlink.found;
    note(report.still_listed ? L"проверка Toolhelp: модуль ВСЁ ЕЩЁ в списке"
                             : L"проверка Toolhelp: модуль в списке отсутствует");

    std::wstring detail = L"DLL загружена, база " + hex_value(module_base) + L".";
    detail += L"\nPEB-списки: " +
              std::wstring(report.peb_lists ? L"3/3 удалены" : L"удалены не все");
    detail += L"\nLdrpHashTable: " +
              std::wstring(report.hash ? L"цепочка разрезана" : L"не разрезана");
    detail += L"\nRB-tree: " +
              std::wstring(report.rb_tree ? L"узел удалён" : L"узел не удалён");
    detail += L"\nETW: ";
    if (config.suppress_etw)
        detail += std::to_wstring(report.etw_slots) + L" слотов IAT";
    else
        detail += L"отключено";
    detail += L"\nToolhelp: " +
              std::wstring(report.still_listed ? L"модуль виден" : L"модуль не виден");
    detail += L"\nФайл: ";
    if (report.staged)
        detail += report.staged_deleted ? L"временная копия удалена" : L"копия ОСТАЛАСЬ";
    else
        detail += L"staging не использовался, исходный файл не тронут";
    detail += L"\nNT: " + report.syscall_mode;

    return success(detail);
}
