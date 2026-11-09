// PEB lists: hides the module from loader list walks; the LDR entry and VAD remain.
// LdrpHashTable: hides it from name lookups; the entry and name buffers remain.
// RB indexes: hides it from loader address lookups; the image section/VAD remains.

#include "unlink.h"

#include "syscalls.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace loader_unlink {
namespace {

#if defined(_WIN64)
constexpr std::size_t k_peb_ldr = 0x18;
constexpr std::size_t k_ldr_in_load = 0x10;
constexpr std::size_t k_ldr_in_memory = 0x20;
constexpr std::size_t k_ldr_in_init = 0x30;

constexpr std::size_t k_entry_in_load = 0x00;
constexpr std::size_t k_entry_in_memory = 0x10;
constexpr std::size_t k_entry_in_init = 0x20;
constexpr std::size_t k_entry_base = 0x30;
constexpr std::size_t k_entry_size = 0x40;
constexpr std::size_t k_entry_base_name = 0x58;
constexpr std::size_t k_ptr = 8;
constexpr std::size_t k_hash_first = 0x60;
constexpr std::size_t k_hash_last = 0x140;
constexpr std::size_t k_rb_first = 0x80;
constexpr std::size_t k_rb_last = 0x1C0;
constexpr std::uintptr_t k_user_limit = 0x00007FFFFFFFFFFFull;
#else
constexpr std::size_t k_peb_ldr = 0x0C;
constexpr std::size_t k_ldr_in_load = 0x0C;
constexpr std::size_t k_ldr_in_memory = 0x14;
constexpr std::size_t k_ldr_in_init = 0x1C;

constexpr std::size_t k_entry_in_load = 0x00;
constexpr std::size_t k_entry_in_memory = 0x08;
constexpr std::size_t k_entry_in_init = 0x10;
constexpr std::size_t k_entry_base = 0x18;
constexpr std::size_t k_entry_size = 0x20;
constexpr std::size_t k_entry_base_name = 0x2C;
constexpr std::size_t k_ptr = 4;
constexpr std::size_t k_hash_first = 0x30;
constexpr std::size_t k_hash_last = 0xB0;
constexpr std::size_t k_rb_first = 0x40;
constexpr std::size_t k_rb_last = 0xF0;
constexpr std::uintptr_t k_user_limit = 0xFFFF0000;
#endif

#if defined(_WIN64)
struct RemoteUString {
    USHORT length;
    USHORT maximum;
    ULONG padding;
    std::uintptr_t buffer;
};
static_assert(sizeof(RemoteUString) == 16, "x64 UNICODE_STRING layout");
#else
struct RemoteUString {
    USHORT length;
    USHORT maximum;
    std::uintptr_t buffer;
};
static_assert(sizeof(RemoteUString) == 8, "x86 UNICODE_STRING layout");
#endif

using Log = std::function<void(const std::wstring&)>;

bool user_address(std::uintptr_t address) {
    return address >= 0x10000 && address < k_user_limit;
}

std::wstring hex_value(std::uintptr_t value) {
    wchar_t buffer[32];
    swprintf_s(buffer, L"0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

std::wstring lower(std::wstring text) {
    for (wchar_t& c : text) c = static_cast<wchar_t>(towlower(c));
    return text;
}

struct Entry {
    std::uintptr_t address = 0;
    std::uintptr_t base = 0;
    std::uintptr_t size = 0;
    std::wstring name;
};

struct Target {
    HANDLE process = nullptr;

    bool read(std::uintptr_t address, void* buffer, std::size_t size) const {
        if (!user_address(address) || !size) return false;
        if (address + size < address || address + size > k_user_limit) return false;
        std::wstring ignored;
        return nt::read_memory(process, address, buffer, size, ignored);
    }

    template <typename T>
    bool get(std::uintptr_t address, T& value) const {
        return read(address, &value, sizeof(value));
    }

    template <typename T>
    bool put(std::uintptr_t address, const T& value) const {
        if (!user_address(address)) return false;
        std::wstring ignored;
        return nt::write_memory(process, address, &value, sizeof(value), ignored);
    }
};

std::wstring read_name(const Target& target, std::uintptr_t address) {
    RemoteUString string{};
    if (!target.get(address, string)) return {};
    if (!string.length || string.length > 0x8000 || (string.length & 1)) return {};
    if (!user_address(string.buffer)) return {};

    std::wstring name(string.length / sizeof(wchar_t), L'\0');
    if (!target.read(string.buffer, name.data(), string.length)) return {};
    return name;
}

bool collect_entries(const Target& target, std::uintptr_t peb,
                     std::vector<Entry>& entries, std::wstring& error) {
    std::uintptr_t ldr = 0;
    if (!target.get(peb + k_peb_ldr, ldr) || !user_address(ldr)) {
        error = L"PEB->Ldr is not readable";
        return false;
    }

    const std::uintptr_t head = ldr + k_ldr_in_load;
    std::uintptr_t node = 0;
    if (!target.get(head, node)) {
        error = L"InLoadOrderModuleList head is not readable";
        return false;
    }

    for (int guard = 0; guard < 1024; ++guard) {
        if (node == head) return true;
        if (!user_address(node)) {
            error = L"InLoadOrderModuleList points outside user space";
            return false;
        }

        const std::uintptr_t entry_address = node - k_entry_in_load;
        Entry entry;
        entry.address = entry_address;
        if (!target.get(entry_address + k_entry_base, entry.base) ||
            !target.get(entry_address + k_entry_size, entry.size)) {
            error = L"loader entry fields are not readable at " + hex_value(entry_address);
            return false;
        }
        entry.name = read_name(target, entry_address + k_entry_base_name);
        if (entry.base) entries.push_back(std::move(entry));

        std::uintptr_t next = 0;
        if (!target.get(node, next) || !next) {
            error = L"InLoadOrderModuleList is not circular";
            return false;
        }
        node = next;
    }

    error = L"InLoadOrderModuleList did not terminate";
    return false;
}

const Entry* find_entry(const std::vector<Entry>& entries, std::uintptr_t base) {
    for (const Entry& entry : entries)
        if (entry.base == base) return &entry;
    return nullptr;
}

const Entry* find_by_name(const std::vector<Entry>& entries, const wchar_t* name) {
    const std::wstring wanted = lower(name);
    for (const Entry& entry : entries)
        if (lower(entry.name) == wanted) return &entry;
    return nullptr;
}

bool discover_hash(Target& target, const std::vector<Entry>& entries,
                   const Entry& ntdll, std::size_t& offset, int& hits) {
    offset = 0;
    hits = 0;

    // A hash node is a LIST_ENTRY at a fixed offset in every loader entry.
    // Validate both neighbours for most entries first, then follow the chain
    // and check that it ends in ntdll's LdrpHashTable. Ordinary module lists
    // fail the second test; the DDAG chain does too.
    for (std::size_t candidate = k_hash_first; candidate <= k_hash_last;
         candidate += k_ptr) {
        int consistent = 0;
        for (const Entry& entry : entries) {
            const std::uintptr_t node = entry.address + candidate;
            std::uintptr_t flink = 0;
            std::uintptr_t blink = 0;
            if (!target.get(node, flink) || !target.get(node + k_ptr, blink)) continue;
            if (!user_address(flink) || !user_address(blink)) continue;

            std::uintptr_t check = 0;
            if (!target.get(flink + k_ptr, check) || check != node) continue;
            if (!target.get(blink, check) || check != node) continue;
            ++consistent;
        }
        if (consistent < static_cast<int>(entries.size() * 3 / 4)) continue;

        int reached = 0;
        for (const Entry& entry : entries) {
            const std::uintptr_t node = entry.address + candidate;
            std::uintptr_t current = 0;
            if (!target.get(node, current)) continue;

            for (int depth = 0; depth < 128; ++depth) {
                if (current >= ntdll.base && current < ntdll.base + ntdll.size) {
                    ++reached;
                    break;
                }
                if (!user_address(current)) break;
                std::uintptr_t next = 0;
                if (!target.get(current, next)) break;
                if (!next || next == node) break;
                current = next;
            }
            if (reached >= 8) break;
        }

        if (reached > hits) {
            hits = reached;
            offset = candidate;
        }
    }

    return hits > 0;
}

bool cut_hash(Target& target, const Entry& entry, std::size_t offset,
              std::wstring& detail) {
    const std::uintptr_t node = entry.address + offset;
    std::uintptr_t flink = 0;
    std::uintptr_t blink = 0;
    if (!target.get(node, flink) || !target.get(node + k_ptr, blink) ||
        !user_address(flink) || !user_address(blink)) {
        detail = L"hash node links are not readable";
        return false;
    }

    if (!target.put(flink + k_ptr, blink) || !target.put(blink, flink)) {
        detail = L"could not rewrite the hash neighbours";
        return false;
    }

    std::uintptr_t check = 0;
    if (!target.get(flink + k_ptr, check) || check != blink ||
        !target.get(blink, check) || check != flink) {
        detail = L"hash neighbours did not accept the new links";
        return false;
    }

    // The entry itself stays alive (the image is running); emptying its node
    // avoids leaving a dangling two-way link in memory.
    const std::uintptr_t zero = 0;
    target.put(node, zero);
    target.put(node + k_ptr, zero);

    detail = L"hash node at " + hex_value(node) + L" cut";
    return true;
}

bool valid_node(std::uintptr_t pointer, std::size_t offset,
                const std::vector<std::uintptr_t>& addresses) {
    if (!user_address(pointer) || pointer < offset) return false;
    return std::binary_search(addresses.begin(), addresses.end(), pointer - offset);
}

bool writable_protection(DWORD protection) {
    const DWORD base = protection & 0xFF;
    return base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
           base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

// The tree object itself lives in ntdll's writable data. Its Root must be the
// node we walked up to, and its Min must be a loader entry node, which rejects
// unrelated pointers that happen to equal the root.
bool find_tree_object(Target& target, const Entry& ntdll, std::uintptr_t root,
                      std::size_t offset,
                      const std::vector<std::uintptr_t>& addresses,
                      std::uintptr_t& object) {
    const std::uintptr_t end = ntdll.base + ntdll.size;
    std::uintptr_t at = ntdll.base;

    while (at < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(target.process, reinterpret_cast<LPCVOID>(at), &info,
                           sizeof(info)) != sizeof(info))
            break;

        const std::uintptr_t region = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        const std::uintptr_t region_end = region + info.RegionSize;
        if (info.State == MEM_COMMIT && writable_protection(info.Protect) &&
            !(info.Protect & PAGE_GUARD)) {
            for (std::uintptr_t chunk = region; chunk < region_end; chunk += 0x10000) {
                const std::size_t span = static_cast<std::size_t>(
                    std::min<std::uintptr_t>(0x10000, region_end - chunk));
                std::vector<std::uint8_t> buffer(span);
                if (!target.read(chunk, buffer.data(), span)) continue;

                for (std::size_t at_offset = 0; at_offset + k_ptr <= span;
                     at_offset += k_ptr) {
                    std::uintptr_t value = 0;
                    std::memcpy(&value, buffer.data() + at_offset, k_ptr);
                    if (value != root) continue;

                    const std::uintptr_t candidate = chunk + at_offset;
                    std::uintptr_t check = 0;
                    std::uintptr_t minimum = 0;
                    if (!target.get(candidate, check) || check != root) continue;
                    if (!target.get(candidate + k_ptr, minimum)) continue;
                    if (!valid_node(minimum, offset, addresses)) continue;

                    object = candidate;
                    return true;
                }
            }
        }

        if (region_end <= at) break;
        at = region_end;
    }

    return false;
}

std::vector<std::uint8_t> call_stub() {
#if defined(_WIN64)
    return {
        0x48, 0x83, 0xEC, 0x28,              // sub rsp, 28h
        0x48, 0x8B, 0x01,                    // mov rax, [rcx]
        0x48, 0x8B, 0x51, 0x10,              // mov rdx, [rcx+10h]
        0x48, 0x8B, 0x49, 0x08,              // mov rcx, [rcx+8]
        0xFF, 0xD0,                          // call rax
        0x48, 0x83, 0xC4, 0x28,              // add rsp, 28h
        0xC3                                 // ret
    };
#else
    return {
        0x55,                                // push ebp
        0x8B, 0xEC,                          // mov ebp, esp
        0x8B, 0x75, 0x08,                    // mov esi, [ebp+8]
        0xFF, 0x76, 0x08,                    // push dword [esi+8]
        0xFF, 0x76, 0x04,                    // push dword [esi+4]
        0xFF, 0x16,                          // call dword [esi]
        0x5D,                                // pop ebp
        0xC2, 0x04, 0x00                     // ret 4
    };
#endif
}

// Runs a two-argument function inside the target. This is the only way to call
// ntdll's RtlRbRemoveNode on memory that belongs to another process.
bool call_in_target(HANDLE process, std::uintptr_t function, std::uintptr_t arg1,
                    std::uintptr_t arg2, std::wstring& error) {
    nt::Table& table = nt::get();

    std::uintptr_t block = 0;
    SIZE_T block_size = 64;
    LONG status = table.allocate(process, reinterpret_cast<PVOID*>(&block), 0,
                                 &block_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!nt::ok(status) || !block) {
        error = L"NtAllocateVirtualMemory (RB call block): " + nt::status_text(status);
        return false;
    }

    std::uintptr_t fields[3] = {function, arg1, arg2};
    std::wstring write_error;
    if (!nt::write_memory(process, block, fields, sizeof(fields), write_error)) {
        nt::free_memory(process, block, 0, write_error);
        error = write_error;
        return false;
    }

    std::uintptr_t code = 0;
    SIZE_T code_size = 4096;
    status = table.allocate(process, reinterpret_cast<PVOID*>(&code), 0, &code_size,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!nt::ok(status) || !code) {
        nt::free_memory(process, block, 0, write_error);
        error = L"NtAllocateVirtualMemory (RB stub): " + nt::status_text(status);
        return false;
    }

    const std::vector<std::uint8_t> stub = call_stub();
    if (!nt::write_memory(process, code, stub.data(), stub.size(), write_error)) {
        nt::free_memory(process, code, 0, write_error);
        nt::free_memory(process, block, 0, write_error);
        error = write_error;
        return false;
    }

    ULONG previous = 0;
    if (!nt::protect_memory(process, code, 4096, PAGE_EXECUTE_READ, previous, write_error)) {
        nt::free_memory(process, code, 0, write_error);
        nt::free_memory(process, block, 0, write_error);
        error = write_error;
        return false;
    }

    HANDLE thread = nt::create_remote_thread(process, code, block, error);
    if (!thread) {
        nt::free_memory(process, code, 0, write_error);
        nt::free_memory(process, block, 0, write_error);
        return false;
    }

    bool timed_out = false;
    bool waited = nt::wait_handle(thread, 15000, timed_out, error);
    bool terminated = false;
    if (timed_out) {
        error = L"RtlRbRemoveNode did not return in 15s";
        nt::get().terminate_thread(thread, 0);
        std::wstring ignored;
        bool ignored_timeout = false;
        terminated = nt::wait_handle(thread, 2000, ignored_timeout, ignored);
    }
    nt::close_handle(thread);

    const bool completed = waited && !timed_out;
    if (!completed && !terminated) {
        // The remote thread may still be executing in the stub. Freeing either
        // page now would turn a failed removal into a crash.
        error += L"; target thread left running, pages intentionally leaked";
        return false;
    }

    nt::free_memory(process, code, 0, write_error);
    nt::free_memory(process, block, 0, write_error);
    return completed;
}

// Reads the tree object after removal and walks it without using keys. This
// distinguishes "the call returned" from "the node actually left the tree".
bool tree_contains_node(Target& target, std::uintptr_t object,
                        std::uintptr_t wanted, std::uintptr_t& root,
                        std::uintptr_t& minimum, int& visited) {
    root = 0;
    minimum = 0;
    visited = 0;
    if (!target.get(object, root) || !target.get(object + k_ptr, minimum)) return false;
    if (!user_address(root)) return false;

    std::vector<std::uintptr_t> stack;
    stack.push_back(root);
    while (!stack.empty() && visited < 1024) {
        const std::uintptr_t node = stack.back();
        stack.pop_back();
        if (node == wanted) return true;
        if (!user_address(node)) continue;
        ++visited;

        std::uintptr_t left = 0;
        std::uintptr_t right = 0;
        if (!target.get(node, left) || !target.get(node + k_ptr, right)) continue;
        if (user_address(left)) stack.push_back(left);
        if (user_address(right)) stack.push_back(right);
    }
    return false;
}

bool remove_rb_node(Target& target, const Entry& target_entry, const Entry& ntdll,
                    size_t offset, std::uintptr_t object, std::wstring& detail) {
    HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!local_ntdll) {
        detail = L"ntdll is not loaded";
        return false;
    }
    const auto local_remove = reinterpret_cast<std::uintptr_t>(
        GetProcAddress(local_ntdll, "RtlRbRemoveNode"));
    if (!local_remove) {
        detail = L"RtlRbRemoveNode is not exported by this ntdll";
        return false;
    }

    const std::uintptr_t local_base = reinterpret_cast<std::uintptr_t>(local_ntdll);
    const std::uintptr_t remote_remove = ntdll.base + (local_remove - local_base);

    std::wstring error;
    if (!call_in_target(target.process, remote_remove, object,
                        target_entry.address + offset, error)) {
        detail = error;
        return false;
    }

    detail = L"RtlRbRemoveNode(tree " + hex_value(object) + L", node " +
             hex_value(target_entry.address + offset) + L") completed in target";
    return true;
}

bool remove_rb_trees(Target& target, const Entry& target_entry,
                     const Entry& ntdll, const std::vector<Entry>& entries,
                     const Log& log, std::wstring& detail) {
    std::vector<std::uintptr_t> addresses;
    addresses.reserve(entries.size());
    for (const Entry& entry : entries) addresses.push_back(entry.address);
    std::sort(addresses.begin(), addresses.end());

    struct Candidate {
        std::size_t offset = 0;
    };
    std::vector<Candidate> candidates;

    for (std::size_t offset = k_rb_first; offset <= k_rb_last; offset += k_ptr) {
        int valid = 0;
        bool structural = false;

        for (const Entry& entry : entries) {
            const std::uintptr_t node = entry.address + offset;
            std::uintptr_t left = 0;
            std::uintptr_t right = 0;
            std::uintptr_t parent = 0;
            if (!target.get(node, left) || !target.get(node + k_ptr, right) ||
                !target.get(node + 2 * k_ptr, parent))
                continue;

            parent &= ~static_cast<std::uintptr_t>(3);
            if (left && !valid_node(left, offset, addresses)) continue;
            if (right && !valid_node(right, offset, addresses)) continue;
            if (parent && !valid_node(parent, offset, addresses)) continue;

            if (left || right || parent) structural = true;
            ++valid;
        }

        if (structural && valid >= static_cast<int>(entries.size() * 3 / 4))
            candidates.push_back({offset});
    }

    if (candidates.empty()) {
        detail = L"no loader RB-tree node offset matched the entry layout";
        // Print the candidate window around the documented index nodes. This
        // is diagnostic output for a layout the validator refused to touch.
        std::wstring probe;
        wchar_t line[160];
        for (std::size_t offset = 0xB8; offset <= 0xF8; offset += k_ptr) {
            std::uintptr_t left = 0;
            std::uintptr_t right = 0;
            std::uintptr_t parent = 0;
            if (!target.get(target_entry.address + offset, left) ||
                !target.get(target_entry.address + offset + k_ptr, right) ||
                !target.get(target_entry.address + offset + 2 * k_ptr, parent))
                continue;
            if (!left && !right && !parent) continue;
            swprintf_s(line, L" 0x%zX={%llX,%llX,%llX}", offset,
                       static_cast<unsigned long long>(left),
                       static_cast<unsigned long long>(right),
                       static_cast<unsigned long long>(parent));
            probe += line;
        }
        if (!probe.empty()) log(L"unlink: RB entry window:" + probe);
        return false;
    }

    {
        std::wstring offsets;
        for (const Candidate& candidate : candidates)
            offsets += L" " + hex_value(candidate.offset);
        log(L"unlink: RB candidate offsets:" + offsets);
    }

    bool removed = false;
    std::vector<std::uintptr_t> used_objects;

    for (const Candidate& candidate : candidates) {
        const std::uintptr_t own_node = target_entry.address + candidate.offset;
        log(L"unlink: trying RB offset " + hex_value(candidate.offset) +
            L", own node " + hex_value(own_node));

        // Walk parent links to the root.
        std::uintptr_t current = own_node;
        std::uintptr_t root = 0;
        bool valid_chain = false;
        for (int depth = 0; depth < 64; ++depth) {
            std::uintptr_t parent = 0;
            if (!target.get(current + 2 * k_ptr, parent)) break;
            parent &= ~static_cast<std::uintptr_t>(3);
            if (!parent || parent == current) {
                root = current;
                valid_chain = true;
                break;
            }
            if (!valid_node(parent, candidate.offset, addresses)) break;
            current = parent;
        }
        if (!valid_chain) {
            log(L"unlink: RB offset " + hex_value(candidate.offset) +
                L" parent chain did not reach a root");
            continue;
        }
        log(L"unlink: RB offset " + hex_value(candidate.offset) + L" root " +
            hex_value(root) + L" (parent chain valid)");

        std::uintptr_t object = 0;
        if (!find_tree_object(target, ntdll, root, candidate.offset, addresses, object)) {
            log(L"unlink: RB offset " + hex_value(candidate.offset) +
                L" parent chain is valid but no RB tree object (Root+Min) was found");
            continue;
        }

        if (std::find(used_objects.begin(), used_objects.end(), object) !=
            used_objects.end())
            continue;

        log(L"unlink: RB node offset " + hex_value(candidate.offset) +
            L", root " + hex_value(root) + L", tree " + hex_value(object));

        std::wstring removal;
        if (remove_rb_node(target, target_entry, ntdll, candidate.offset, object,
                           removal)) {
            removed = true;
            used_objects.push_back(object);
            log(L"unlink: " + removal);

            std::uintptr_t root_after = 0;
            std::uintptr_t min_after = 0;
            int visited = 0;
            const bool still_there = tree_contains_node(
                target, object, target_entry.address + candidate.offset,
                root_after, min_after, visited);
            log(L"unlink: tree after remove: root " + hex_value(root_after) +
                L", min " + hex_value(min_after) + L", contains node: " +
                (still_there ? L"yes" : L"no") + L", visited " +
                std::to_wstring(visited));
        } else {
            log(L"unlink: RB removal failed: " + removal);
        }
    }

    if (!removed) {
        detail = L"no RB-tree index node was removed";
        return false;
    }
    detail = L"removed " + std::to_wstring(used_objects.size()) +
             L" RB-tree node(s)";
    return true;
}

bool unlink_one_list(Target& target, const Entry& entry, std::size_t offset,
                     std::wstring& detail) {
    const std::uintptr_t node = entry.address + offset;
    std::uintptr_t flink = 0;
    std::uintptr_t blink = 0;
    if (!target.get(node, flink) || !target.get(node + k_ptr, blink) ||
        !user_address(flink) || !user_address(blink)) {
        detail = L"links at " + hex_value(node) + L" are not readable";
        return false;
    }

    if (!target.put(flink + k_ptr, blink) || !target.put(blink, flink)) {
        detail = L"could not rewrite links at " + hex_value(node);
        return false;
    }

    std::uintptr_t check = 0;
    if (!target.get(flink + k_ptr, check) || check != blink ||
        !target.get(blink, check) || check != flink) {
        detail = L"neighbours did not accept links at " + hex_value(node);
        return false;
    }

    const std::uintptr_t zero = 0;
    target.put(node, zero);
    target.put(node + k_ptr, zero);
    detail = L"unlinked " + hex_value(node);
    return true;
}

std::wstring list_name(std::size_t offset) {
    if (offset == k_entry_in_load) return L"InLoadOrder";
    if (offset == k_entry_in_memory) return L"InMemoryOrder";
    return L"InInitializationOrder";
}

}  // namespace

Report hide(HANDLE process, std::uintptr_t base, const Config& config,
            const std::function<void(const std::wstring&)>& log) {
    Report report;
    const auto note = [&](const std::wstring& text) {
        if (log) log(text);
    };

    Target target;
    target.process = process;

    std::uintptr_t peb = 0;
    std::wstring error;
    if (!nt::query_peb(process, peb, error)) {
        report.detail = error;
        note(L"unlink: " + error);
        return report;
    }
    note(L"unlink: PEB " + hex_value(peb));

    std::vector<Entry> entries;
    if (!collect_entries(target, peb, entries, error)) {
        report.detail = error;
        note(L"unlink: " + error);
        return report;
    }
    note(L"unlink: loader entries " + std::to_wstring(entries.size()));

    const Entry* own = find_entry(entries, base);
    if (!own) {
        report.detail = L"the module is no longer present in InLoadOrderModuleList";
        note(L"unlink: " + report.detail);
        return report;
    }
    note(L"unlink: module entry " + hex_value(own->address) + L" (" + own->name + L")");

    const Entry* ntdll = find_by_name(entries, L"ntdll.dll");
    if (!ntdll) {
        report.detail = L"ntdll.dll is missing from the loader list";
        note(L"unlink: " + report.detail);
        return report;
    }

    std::wstring detail;

    if (config.unlink_hash) {
        std::size_t offset = 0;
        int hits = 0;
        if (!discover_hash(target, entries, *ntdll, offset, hits)) {
            note(L"unlink: hash slot offset not identified");
        } else {
            note(L"unlink: hash offset " + hex_value(offset) + L" (chains reach ntdll: " +
                 std::to_wstring(hits) + L")");
            if (cut_hash(target, *own, offset, detail)) {
                report.hash = true;
                note(L"unlink: " + detail);
            } else {
                note(L"unlink: hash unlink failed: " + detail);
            }
        }
    } else {
        note(L"unlink: hash unlink disabled");
    }

    if (config.unlink_rb) {
        if (remove_rb_trees(target, *own, *ntdll, entries, note, detail)) {
            report.rb_tree = true;
            note(L"unlink: " + detail);
        } else {
            note(L"unlink: " + detail);
        }
    } else {
        note(L"unlink: RB-tree unlink disabled");
    }

    if (config.unlink_peb) {
        const std::size_t offsets[] = {k_entry_in_load, k_entry_in_memory,
                                       k_entry_in_init};
        int done = 0;
        for (std::size_t offset : offsets) {
            if (unlink_one_list(target, *own, offset, detail)) {
                ++done;
                note(L"unlink: " + list_name(offset) + L" " + detail);
            } else {
                note(L"unlink: " + list_name(offset) + L" failed: " + detail);
            }
        }
        report.peb_lists = done == 3;
        if (!report.peb_lists)
            note(L"unlink: only " + std::to_wstring(done) + L"/3 loader lists were cut");
    } else {
        note(L"unlink: PEB list unlink disabled");
    }

    report.detail = L"PEB lists " + std::wstring(report.peb_lists ? L"3/3" : L"partial") +
                    L", hash " + (report.hash ? L"cut" : L"not cut") +
                    L", RB " + (report.rb_tree ? L"removed" : L"not removed");
    return report;
}

}  // namespace loader_unlink
