// Hides: EtwEventWrite* calls that go through patched IAT slots.
// Remains: direct/GetProcAddress calls, NtTraceEvent, other ETW APIs and
// kernel ETW providers.

#include "etw.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <vector>

namespace etw {
namespace {

#if defined(_WIN64)
constexpr std::size_t k_ptr = 8;
constexpr std::uintptr_t k_ordinal = 0x8000000000000000ull;
constexpr WORD k_magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#else
constexpr std::size_t k_ptr = 4;
constexpr std::uintptr_t k_ordinal = 0x80000000u;
constexpr WORD k_magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
#endif

struct Module {
    std::uintptr_t base = 0;
    std::uintptr_t size = 0;
    std::wstring name;
};

const char* const k_etw_names[] = {
    "EtwEventWrite",
    "EtwEventWriteEx",
    "EtwEventWriteFull",
    "EtwEventWriteNoRegistration",
    "EtwEventWriteTransfer",
    "EtwEventWriteString",
    "EtwEventWriteEndScenario",
    "EtwEventWriteStartScenario",
};

bool iequals(const char* a, const char* b) {
    while (*a && *b) {
        if (std::tolower(static_cast<unsigned char>(*a)) !=
            std::tolower(static_cast<unsigned char>(*b)))
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

std::wstring hex_value(std::uintptr_t value) {
    wchar_t buffer[32];
    swprintf_s(buffer, L"0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

std::vector<Module> modules(DWORD pid) {
    std::vector<Module> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            Module module;
            module.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            module.size = entry.modBaseSize;
            module.name = entry.szModule;
            if (module.base && module.size) result.push_back(std::move(module));
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

bool read_target(nt::Table& table, HANDLE process, std::uintptr_t address,
                 void* buffer, std::size_t size) {
    SIZE_T got = 0;
    const LONG status = table.read(process, reinterpret_cast<const void*>(address),
                                   buffer, size, &got);
    return nt::ok(status) && got == size;
}

bool read_pointer(nt::Table& table, HANDLE process, std::uintptr_t address,
                  std::uintptr_t& value) {
    return read_target(table, process, address, &value, k_ptr);
}

std::string read_c_string(nt::Table& table, HANDLE process, std::uintptr_t address,
                          std::size_t maximum) {
    if (!address || !maximum) return {};
    std::vector<char> buffer(maximum + 1, '\0');
    if (!read_target(table, process, address, buffer.data(), maximum)) return {};
    buffer[maximum] = '\0';
    return std::string(buffer.data());
}

std::uintptr_t allocate_page(nt::Table& table, HANDLE process) {
    std::uintptr_t address = 0;
    SIZE_T size = 4096;
    const LONG status = table.allocate(process, reinterpret_cast<PVOID*>(&address), 0,
                                       &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return nt::ok(status) ? address : 0;
}

bool make_return_zero_stub(nt::Table& table, HANDLE process, std::uintptr_t& stub) {
    if (stub) return true;
    const std::uintptr_t page = allocate_page(table, process);
    if (!page) return false;

    const std::uint8_t code[] = {0x33, 0xC0, 0xC3};  // xor eax, eax; ret
    SIZE_T wrote = 0;
    LONG status = table.write(process, reinterpret_cast<void*>(page), code,
                              sizeof(code), &wrote);
    if (!nt::ok(status) || wrote != sizeof(code)) {
        SIZE_T size = 0;
        std::uintptr_t free_at = page;
        table.free(process, reinterpret_cast<PVOID*>(&free_at), &size, MEM_RELEASE);
        return false;
    }

    ULONG previous = 0;
    void* base = reinterpret_cast<void*>(page);
    SIZE_T size = 4096;
    status = table.protect(process, &base, &size, PAGE_EXECUTE_READ, &previous);
    if (!nt::ok(status)) {
        SIZE_T free_size = 0;
        std::uintptr_t free_at = page;
        table.free(process, reinterpret_cast<PVOID*>(&free_at), &free_size, MEM_RELEASE);
        return false;
    }

    stub = page;
    return true;
}

struct Match {
    std::uintptr_t slot = 0;
    std::uint64_t original = 0;
    std::wstring module;
};

// Parses one module's import directory and collects IAT slots that currently
// point at ntdll's EtwEventWrite* exports.
void scan_module(nt::Table& table, HANDLE process, const Module& module,
                 std::uintptr_t target_ntdll, std::uintptr_t local_ntdll,
                 const std::vector<std::pair<const char*, std::uintptr_t>>& functions,
                 std::uintptr_t existing_stub, std::vector<Match>& matches,
                 const std::function<void(const std::wstring&)>& log) {
    IMAGE_DOS_HEADER dos{};
    if (!read_target(table, process, module.base, &dos, sizeof(dos))) return;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        dos.e_lfanew > 0x100000)
        return;

    const std::uintptr_t nt_address = module.base + dos.e_lfanew;
    if (nt_address + sizeof(IMAGE_NT_HEADERS) > module.base + module.size) return;

    IMAGE_NT_HEADERS nt{};
    if (!read_target(table, process, nt_address, &nt, sizeof(nt))) return;
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != k_magic) return;

    const IMAGE_DATA_DIRECTORY& imports =
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imports.VirtualAddress || imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) return;
    if (imports.VirtualAddress >= module.size) return;

    for (std::size_t index = 0; index < 256; ++index) {
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        const std::uintptr_t descriptor_address =
            module.base + imports.VirtualAddress + index * sizeof(descriptor);
        if (descriptor_address + sizeof(descriptor) > module.base + module.size) return;
        if (!read_target(table, process, descriptor_address, &descriptor,
                         sizeof(descriptor)))
            return;
        if (!descriptor.Name) return;

        if (descriptor.Name >= module.size) continue;
        const std::string dll = read_c_string(table, process, module.base + descriptor.Name, 260);
        if (!iequals(dll.c_str(), "ntdll.dll")) continue;
        if (!descriptor.FirstThunk || descriptor.FirstThunk >= module.size) continue;

        const std::uintptr_t lookup_base =
            module.base + (descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk
                                                         : descriptor.FirstThunk);
        const std::uintptr_t iat_base = module.base + descriptor.FirstThunk;

        for (std::size_t thunk = 0; thunk < 4096; ++thunk) {
            std::uintptr_t lookup = 0;
            if (!read_pointer(table, process, lookup_base + thunk * k_ptr, lookup)) return;
            if (!lookup) break;
            if (lookup & k_ordinal) continue;

            const std::uint32_t name_rva = static_cast<std::uint32_t>(lookup & 0x7FFFFFFF);
            if (name_rva >= module.size) continue;
            const std::string name = read_c_string(table, process,
                                                    module.base + name_rva + 2, 256);
            if (name.empty()) continue;

            for (const auto& [function_name, local_address] : functions) {
                if (name != function_name) continue;

                std::uintptr_t actual = 0;
                const std::uintptr_t slot = iat_base + thunk * k_ptr;
                if (!read_pointer(table, process, slot, actual)) return;
                if (slot + k_ptr > module.base + module.size) return;

                const std::uintptr_t expected =
                    target_ntdll + (local_address - local_ntdll);
                if (existing_stub && actual == existing_stub) break;
                if (actual != expected) {
                    log(L"etw: " + module.name + L" imports " +
                        std::wstring(function_name, function_name + std::strlen(function_name)) +
                        L" but the slot is not the ntdll export (" + hex_value(actual) +
                        L"), left alone");
                    break;
                }

                Match match;
                match.slot = slot;
                match.original = actual;
                match.module = module.name;
                matches.push_back(std::move(match));
                break;
            }
        }
    }
}

bool apply_patch(nt::Table& table, HANDLE process, const Match& match,
                 std::uintptr_t stub, std::wstring& error) {
    ULONG previous = 0;
    if (!nt::protect_memory(process, match.slot, k_ptr, PAGE_READWRITE, previous, error))
        return false;

    SIZE_T wrote = 0;
    const std::uintptr_t value = stub;
    const LONG status = table.write(process, reinterpret_cast<void*>(match.slot),
                                    &value, k_ptr, &wrote);
    bool good = nt::ok(status) && wrote == k_ptr;

    ULONG ignored = 0;
    std::wstring restore_error;
    if (!nt::protect_memory(process, match.slot, k_ptr, previous, ignored, restore_error) &&
        good) {
        error = restore_error;
        good = false;
    }

    if (!good && error.empty())
        error = L"NtWriteVirtualMemory " + nt::status_text(status);
    return good;
}

}  // namespace

std::size_t suppress(HANDLE process, DWORD pid, nt::Table& table, State& state,
                     const std::function<void(const std::wstring&)>& log) {
    const auto note = [&](const std::wstring& text) {
        if (log) log(text);
    };

    if (!state.process) state.process = process;

    HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!local_ntdll) {
        note(L"etw: ntdll is not loaded");
        return 0;
    }
    const std::uintptr_t local_base = reinterpret_cast<std::uintptr_t>(local_ntdll);

    std::vector<std::pair<const char*, std::uintptr_t>> functions;
    for (const char* name : k_etw_names) {
        const auto address = reinterpret_cast<std::uintptr_t>(
            GetProcAddress(local_ntdll, name));
        if (address) functions.emplace_back(name, address);
    }

    std::vector<Module> module_list = modules(pid);
    const auto ntdll = std::find_if(module_list.begin(), module_list.end(),
                                    [](const Module& module) {
                                        return _wcsicmp(module.name.c_str(), L"ntdll.dll") == 0;
                                    });
    if (ntdll == module_list.end()) {
        note(L"etw: ntdll is missing from the target module list");
        return 0;
    }

    std::vector<Match> matches;
    for (const Module& module : module_list) {
        if (_wcsicmp(module.name.c_str(), L"ntdll.dll") == 0) continue;
        scan_module(table, process, module, ntdll->base, local_base, functions,
                    state.stub, matches, note);
    }

    // Do not write anything until every slot has been identified. The stub
    // page is created once and reused by a second scan after LoadLibrary.
    if (matches.empty()) {
        note(state.patches.empty()
                 ? L"etw: no EtwEventWrite imports found"
                 : L"etw: no new EtwEventWrite imports; existing slots stay redirected");
        return 0;
    }
    if (!make_return_zero_stub(table, process, state.stub)) {
        note(L"etw: could not allocate the return-zero stub");
        return 0;
    }

    std::size_t applied = 0;
    for (const Match& match : matches) {
        const bool known = std::any_of(state.patches.begin(), state.patches.end(),
                                       [&](const Patch& patch) {
                                           return patch.slot == match.slot;
                                       });
        if (known) continue;

        std::wstring error;
        if (!apply_patch(table, process, match, state.stub, error)) {
            note(L"etw: " + match.module + L" slot " + hex_value(match.slot) +
                 L" not patched: " + error);
            continue;
        }

        Patch patch;
        patch.slot = match.slot;
        patch.original = match.original;
        patch.module = match.module;
        state.patches.push_back(std::move(patch));
        ++applied;
    }

    state.active = !state.patches.empty();
    note(L"etw: redirected " + std::to_wstring(applied) + L" new slot(s), total " +
         std::to_wstring(state.patches.size()) + L", stub " + hex_value(state.stub));
    return applied;
}

bool restore(State& state, const std::function<void(const std::wstring&)>& log) {
    const auto note = [&](const std::wstring& text) {
        if (log) log(text);
    };

    if (!state.process || (state.patches.empty() && !state.stub)) {
        state.active = false;
        return true;
    }

    nt::Table& table = nt::get();
    if (state.patches.empty()) {
        std::wstring error;
        if (state.stub) nt::free_memory(state.process, state.stub, 0, error);
        state.stub = 0;
        state.active = false;
        return true;
    }

    bool all = true;
    for (auto it = state.patches.rbegin(); it != state.patches.rend(); ++it) {
        std::wstring error;
        ULONG previous = 0;
        if (!nt::protect_memory(state.process, it->slot, k_ptr, PAGE_READWRITE,
                                previous, error)) {
            note(L"etw: restore protect failed at " + hex_value(it->slot) + L": " +
                 error);
            all = false;
            continue;
        }

        SIZE_T wrote = 0;
        const std::uintptr_t value = static_cast<std::uintptr_t>(it->original);
        const LONG status = table.write(state.process,
                                        reinterpret_cast<void*>(it->slot),
                                        &value, k_ptr, &wrote);
        ULONG ignored = 0;
        std::wstring restore_error;
        nt::protect_memory(state.process, it->slot, k_ptr, previous, ignored,
                           restore_error);
        if (!nt::ok(status) || wrote != k_ptr) {
            note(L"etw: restore write failed at " + hex_value(it->slot));
            all = false;
        }
    }

    if (!all) {
        note(L"etw: not every slot was restored; stub page is kept");
        return false;
    }

    if (state.stub) {
        std::wstring error;
        if (!nt::free_memory(state.process, state.stub, 0, error))
            note(L"etw: stub free failed: " + error);
    }

    state.stub = 0;
    state.patches.clear();
    state.active = false;
    note(L"etw: restored every redirected slot");
    return true;
}

}  // namespace etw
