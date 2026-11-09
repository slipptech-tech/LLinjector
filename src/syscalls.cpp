// Hides: ntdll user-mode hooks from the injector's own NT calls by resolving
// SSNs and the syscall gadget at runtime. Remains: the syscall instruction,
// kernel callbacks/ETW; x86 uses ntdll exports instead of direct syscalls.

#include "syscalls.h"

#include "generated/syscall_data.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace nt {
namespace {

struct ExportRow {
    std::string name;
    std::uintptr_t address = 0;
    unsigned ssn = 0;
    bool clean = false;
};

bool parse_stub(const std::uint8_t* code, unsigned& ssn) {
    // Windows 10/11 x64: 4C 8B D1 B8 <ssn> ...
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8) {
        std::memcpy(&ssn, code + 4, sizeof(ssn));
        return ssn < 0x10000;
    }
    // Older builds without the r10 shuffle.
    if (code[0] == 0xB8) {
        std::memcpy(&ssn, code + 1, sizeof(ssn));
        return ssn < 0x10000;
    }
    return false;
}

unsigned generated_ssn(const char* name) {
    if (std::strcmp(name, "NtOpenProcess") == 0) return ll_gen::kNtOpenProcess;
    if (std::strcmp(name, "NtAllocateVirtualMemory") == 0) return ll_gen::kNtAllocateVirtualMemory;
    if (std::strcmp(name, "NtFreeVirtualMemory") == 0) return ll_gen::kNtFreeVirtualMemory;
    if (std::strcmp(name, "NtProtectVirtualMemory") == 0) return ll_gen::kNtProtectVirtualMemory;
    if (std::strcmp(name, "NtWriteVirtualMemory") == 0) return ll_gen::kNtWriteVirtualMemory;
    if (std::strcmp(name, "NtReadVirtualMemory") == 0) return ll_gen::kNtReadVirtualMemory;
    if (std::strcmp(name, "NtCreateThreadEx") == 0) return ll_gen::kNtCreateThreadEx;
    if (std::strcmp(name, "NtWaitForSingleObject") == 0) return ll_gen::kNtWaitForSingleObject;
    if (std::strcmp(name, "NtTerminateThread") == 0) return ll_gen::kNtTerminateThread;
    if (std::strcmp(name, "NtClose") == 0) return ll_gen::kNtClose;
    if (std::strcmp(name, "NtQueryInformationProcess") == 0) return ll_gen::kNtQueryInformationProcess;
    return 0xFFFFFFFFu;
}

std::uint8_t* find_gadget(std::uint8_t* base, IMAGE_NT_HEADERS* nt) {
    // The generated RVA is tried first, but only when the bytes still match.
    if (ll_gen::k_gadget_rva != 0xFFFFFFFFu &&
        ll_gen::k_gadget_rva + 2 < nt->OptionalHeader.SizeOfImage &&
        base[ll_gen::k_gadget_rva] == 0x0F &&
        base[ll_gen::k_gadget_rva + 1] == 0x05 &&
        base[ll_gen::k_gadget_rva + 2] == 0xC3) {
        return base + ll_gen::k_gadget_rva;
    }

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        const std::size_t span = std::min<std::size_t>(
            section->Misc.VirtualSize,
            section->SizeOfRawData ? section->SizeOfRawData : section->Misc.VirtualSize);
        const std::uint8_t* start = base + section->VirtualAddress;
        for (std::size_t at = 0; at + 2 < span; ++at) {
            if (start[at] == 0x0F && start[at + 1] == 0x05 && start[at + 2] == 0xC3)
                return const_cast<std::uint8_t*>(start + at);
        }
    }
    return nullptr;
}

std::vector<ExportRow> read_exports(std::uint8_t* base, std::size_t image_size) {
    std::vector<ExportRow> rows;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return rows;
    if (dos->e_lfanew <= 0 || static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > image_size)
        return rows;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return rows;

    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return rows;
    if (dir.VirtualAddress + dir.Size > image_size) return rows;

    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
    auto* functions = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
    auto* ordinals = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;
        if (exp->NumberOfFunctions <= ordinals[i]) continue;

        const std::uintptr_t address =
            reinterpret_cast<std::uintptr_t>(base) + functions[ordinals[i]];
        if (address < reinterpret_cast<std::uintptr_t>(base) ||
            address + 8 >= reinterpret_cast<std::uintptr_t>(base) + image_size)
            continue;

        ExportRow row;
        row.name = name;
        row.address = address;
        row.clean = parse_stub(reinterpret_cast<const std::uint8_t*>(address), row.ssn);
        rows.push_back(std::move(row));
    }
    return rows;
}

unsigned halo_gate(const std::vector<ExportRow>& rows, std::uintptr_t address) {
    // Address order of the Nt* exports equals service-number order on every
    // ntdll that follows the normal Windows layout. Walk outwards from the
    // hooked stub until a clean neighbour is found and project its index.
    std::vector<const ExportRow*> sorted;
    sorted.reserve(rows.size());
    for (const ExportRow& row : rows) sorted.push_back(&row);
    std::sort(sorted.begin(), sorted.end(), [](const ExportRow* a, const ExportRow* b) {
        return a->address < b->address;
    });

    std::size_t index = sorted.size();
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        if (sorted[i]->address == address) {
            index = i;
            break;
        }
    }
    if (index == sorted.size()) return 0xFFFFFFFFu;

    for (std::size_t distance = 1; distance < sorted.size(); ++distance) {
        if (index >= distance && sorted[index - distance]->clean) {
            const long long value = static_cast<long long>(sorted[index - distance]->ssn) +
                                    static_cast<long long>(distance);
            if (value >= 0 && value < 0x10000) return static_cast<unsigned>(value);
        }
        if (index + distance < sorted.size() && sorted[index + distance]->clean) {
            const long long value = static_cast<long long>(sorted[index + distance]->ssn) -
                                    static_cast<long long>(distance);
            if (value >= 0 && value < 0x10000) return static_cast<unsigned>(value);
        }
    }
    return 0xFFFFFFFFu;
}

struct NamedSlot {
    const char* name;
    unsigned index;
};

constexpr NamedSlot k_slots[] = {
    {"NtOpenProcess", 0},
    {"NtAllocateVirtualMemory", 1},
    {"NtFreeVirtualMemory", 2},
    {"NtProtectVirtualMemory", 3},
    {"NtWriteVirtualMemory", 4},
    {"NtReadVirtualMemory", 5},
    {"NtCreateThreadEx", 6},
    {"NtWaitForSingleObject", 7},
    {"NtTerminateThread", 8},
    {"NtClose", 9},
    {"NtQueryInformationProcess", 10},
};

constexpr std::size_t k_stub_stride = 32;
constexpr std::size_t k_stub_page = 4096;

std::wstring win32_text(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring text;
    if (length && buffer) {
        text.assign(buffer, length);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' ||
                                 text.back() == L' '))
            text.pop_back();
    }
    if (buffer) LocalFree(buffer);
    return text;
}

Table build_table(bool prefer_direct) {
    Table table;
    std::wstring error;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        table.mode = L"ntdll.dll is not loaded";
        return table;
    }

    auto* base = reinterpret_cast<std::uint8_t*>(ntdll);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        table.mode = L"bad ntdll DOS header";
        return table;
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        table.mode = L"bad ntdll NT header";
        return table;
    }
    const std::size_t image_size = nt->OptionalHeader.SizeOfImage;

    auto export_of = [&](const char* name) -> void* {
        return reinterpret_cast<void*>(GetProcAddress(ntdll, name));
    };

    table.open_process = reinterpret_cast<NtOpenProcessFn>(export_of("NtOpenProcess"));
    table.allocate = reinterpret_cast<NtAllocateVirtualMemoryFn>(export_of("NtAllocateVirtualMemory"));
    table.free = reinterpret_cast<NtFreeVirtualMemoryFn>(export_of("NtFreeVirtualMemory"));
    table.protect = reinterpret_cast<NtProtectVirtualMemoryFn>(export_of("NtProtectVirtualMemory"));
    table.write = reinterpret_cast<NtWriteVirtualMemoryFn>(export_of("NtWriteVirtualMemory"));
    table.read = reinterpret_cast<NtReadVirtualMemoryFn>(export_of("NtReadVirtualMemory"));
    table.create_thread = reinterpret_cast<NtCreateThreadExFn>(export_of("NtCreateThreadEx"));
    table.wait = reinterpret_cast<NtWaitForSingleObjectFn>(export_of("NtWaitForSingleObject"));
    table.terminate_thread = reinterpret_cast<NtTerminateThreadFn>(export_of("NtTerminateThread"));
    table.close = reinterpret_cast<NtCloseFn>(export_of("NtClose"));
    table.query_information = reinterpret_cast<NtQueryInformationProcessFn>(
        export_of("NtQueryInformationProcess"));

    if (!table.open_process || !table.allocate || !table.free || !table.protect ||
        !table.write || !table.read || !table.create_thread || !table.wait ||
        !table.terminate_thread || !table.close || !table.query_information) {
        table.mode = L"ntdll exports are missing";
        return table;
    }

#if defined(_WIN64)
    if (prefer_direct) {
        std::vector<ExportRow> rows = read_exports(base, image_size);
        std::uint8_t* gadget = find_gadget(base, nt);
        if (!gadget) {
            table.mode = L"x64: syscall gadget not found, using ntdll exports";
            return table;
        }

        auto* page = static_cast<std::uint8_t*>(
            VirtualAlloc(nullptr, k_stub_page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!page) {
            table.mode = L"x64: trampoline page allocation failed, using ntdll exports";
            return table;
        }

        unsigned direct_count = 0;
        for (const NamedSlot& slot : k_slots) {
            const ExportRow* row = nullptr;
            for (const ExportRow& candidate : rows) {
                if (candidate.name == slot.name) {
                    row = &candidate;
                    break;
                }
            }
            if (!row) continue;

            unsigned ssn = 0xFFFFFFFFu;
            if (row->clean) {
                ssn = row->ssn;
            } else {
                ssn = generated_ssn(slot.name);
                if (ssn == 0xFFFFFFFFu) ssn = halo_gate(rows, row->address);
            }
            if (ssn == 0xFFFFFFFFu) continue;

            std::uint8_t* code = page + slot.index * k_stub_stride;
            code[0] = 0x4C;  // mov r10, rcx
            code[1] = 0x8B;
            code[2] = 0xD1;
            code[3] = 0xB8;  // mov eax, imm32
            std::memcpy(code + 4, &ssn, sizeof(ssn));
            code[8] = 0x49;  // mov r11, imm64
            code[9] = 0xBB;
            const std::uint64_t target = reinterpret_cast<std::uint64_t>(gadget);
            std::memcpy(code + 10, &target, sizeof(target));
            code[18] = 0x41; // jmp r11
            code[19] = 0xFF;
            code[20] = 0xE3;
            ++direct_count;
        }

        if (direct_count) {
            DWORD previous = 0;
            if (!VirtualProtect(page, k_stub_page, PAGE_EXECUTE_READ, &previous)) {
                VirtualFree(page, 0, MEM_RELEASE);
                table.mode = L"x64: trampoline page protection failed, using ntdll exports";
                return table;
            }
            FlushInstructionCache(GetCurrentProcess(), page, k_stub_page);

            for (const NamedSlot& slot : k_slots) {
                const std::uint8_t* code = page + slot.index * k_stub_stride;
                if (code[3] != 0xB8) continue;
                void* fn = const_cast<std::uint8_t*>(code);
                switch (slot.index) {
                    case 0: table.open_process = reinterpret_cast<NtOpenProcessFn>(fn); break;
                    case 1: table.allocate = reinterpret_cast<NtAllocateVirtualMemoryFn>(fn); break;
                    case 2: table.free = reinterpret_cast<NtFreeVirtualMemoryFn>(fn); break;
                    case 3: table.protect = reinterpret_cast<NtProtectVirtualMemoryFn>(fn); break;
                    case 4: table.write = reinterpret_cast<NtWriteVirtualMemoryFn>(fn); break;
                    case 5: table.read = reinterpret_cast<NtReadVirtualMemoryFn>(fn); break;
                    case 6: table.create_thread = reinterpret_cast<NtCreateThreadExFn>(fn); break;
                    case 7: table.wait = reinterpret_cast<NtWaitForSingleObjectFn>(fn); break;
                    case 8: table.terminate_thread = reinterpret_cast<NtTerminateThreadFn>(fn); break;
                    case 9: table.close = reinterpret_cast<NtCloseFn>(fn); break;
                    case 10: table.query_information = reinterpret_cast<NtQueryInformationProcessFn>(fn); break;
                    default: break;
                }
            }
            table.direct = true;
            table.mode = L"x64 direct syscalls (" + std::to_wstring(direct_count) + L"/" +
                         std::to_wstring(std::size(k_slots)) + L")";
            return table;
        }

        VirtualFree(page, 0, MEM_RELEASE);
        table.mode = L"x64: no service numbers resolved, using ntdll exports";
        return table;
    }
    table.mode = L"x64: direct syscalls disabled, using ntdll exports";
#else
    (void)prefer_direct;
    (void)image_size;
    table.mode = L"x86: ntdll exports (WOW64 syscall gate not bypassed)";
#endif

    return table;
}

}  // namespace

std::wstring status_text(LONG status) {
    using Fn = ULONG(NTAPI*)(LONG);
    static Fn convert = []() -> Fn {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<Fn>(GetProcAddress(ntdll, "RtlNtStatusToDosError"))
                     : nullptr;
    }();

    const ULONG code = convert ? convert(status) : static_cast<ULONG>(status);
    std::wstring text = win32_text(code);
    wchar_t suffix[64];
    swprintf_s(suffix, L" (NTSTATUS 0x%08lX)", static_cast<unsigned long>(status));
    if (text.empty()) text = L"unknown NTSTATUS";
    return text + suffix;
}

Table& init(bool prefer_direct, std::wstring& error) {
    // The whole process uses one table; the first caller decides whether
    // direct syscalls are attempted. The injector initialises before it opens
    // anything, so the CLI switch works as expected.
    static const bool direct_preference = prefer_direct;
    static Table instance = build_table(direct_preference);
    error.clear();
    return instance;
}

Table& get() {
    std::wstring ignored;
    return init(true, ignored);
}

bool read_memory(HANDLE process, std::uintptr_t address, void* buffer,
                 std::size_t size, std::wstring& error) {
    SIZE_T got = 0;
    const LONG status = get().read(process, reinterpret_cast<const void*>(address),
                                     buffer, size, &got);
    if (!ok(status) || got != size) {
        error = L"NtReadVirtualMemory " + status_text(status) + L" at 0x" +
                [&] {
                    wchar_t text[32];
                    swprintf_s(text, L"%llX", static_cast<unsigned long long>(address));
                    return std::wstring(text);
                }();
        return false;
    }
    return true;
}

bool write_memory(HANDLE process, std::uintptr_t address, const void* buffer,
                  std::size_t size, std::wstring& error) {
    SIZE_T wrote = 0;
    const LONG status = get().write(process, reinterpret_cast<void*>(address),
                                      buffer, size, &wrote);
    if (!ok(status) || wrote != size) {
        error = L"NtWriteVirtualMemory " + status_text(status);
        return false;
    }
    return true;
}

bool protect_memory(HANDLE process, std::uintptr_t address, std::size_t size,
                    ULONG protection, ULONG& previous, std::wstring& error) {
    const std::uintptr_t page = address & ~static_cast<std::uintptr_t>(0xFFF);
    const std::size_t span = (address - page) + size;
    void* base = reinterpret_cast<void*>(page);
    SIZE_T region = span;
    const LONG status = get().protect(process, &base, &region, protection, &previous);
    if (!ok(status)) {
        error = L"NtProtectVirtualMemory " + status_text(status);
        return false;
    }
    return true;
}

bool free_memory(HANDLE process, std::uintptr_t address, std::size_t size,
                 std::wstring& error) {
    if (!address) return true;
    void* base = reinterpret_cast<void*>(address);
    SIZE_T region = size;
    const LONG status = get().free(process, &base, &region, MEM_RELEASE);
    if (!ok(status)) {
        error = L"NtFreeVirtualMemory " + status_text(status);
        return false;
    }
    return true;
}

HANDLE create_remote_thread(HANDLE process, std::uintptr_t start,
                            std::uintptr_t argument, std::wstring& error) {
    HANDLE thread = nullptr;
    const LONG status = get().create_thread(
        &thread, THREAD_ALL_ACCESS, nullptr, process,
        reinterpret_cast<void*>(start), reinterpret_cast<void*>(argument),
        0, 0, 0, 0, nullptr);
    if (!ok(status) || !thread) {
        error = L"NtCreateThreadEx " + status_text(status);
        return nullptr;
    }
    return thread;
}

bool wait_handle(HANDLE handle, std::uint32_t timeout_ms, bool& timed_out,
                 std::wstring& error) {
    timed_out = false;
    LARGE_INTEGER timeout{};
    timeout.QuadPart = -static_cast<LONGLONG>(timeout_ms) * 10000LL;
    const LONG status = get().wait(handle, FALSE, &timeout);
    if (status == k_status_timeout) {
        timed_out = true;
        return true;
    }
    if (!ok(status)) {
        error = L"NtWaitForSingleObject " + status_text(status);
        return false;
    }
    return true;
}

void close_handle(HANDLE handle) {
    if (handle) get().close(handle);
}

bool query_peb(HANDLE process, std::uintptr_t& peb, std::wstring& error) {
    PROCESS_BASIC_INFORMATION info{};
    ULONG length = 0;
    const LONG status = get().query_information(
        process, ProcessBasicInformation, &info, sizeof(info), &length);
    if (!ok(status) || !info.PebBaseAddress) {
        error = L"NtQueryInformationProcess(ProcessBasicInformation) " + status_text(status);
        return false;
    }
    peb = reinterpret_cast<std::uintptr_t>(info.PebBaseAddress);
    return true;
}

}  // namespace nt

