#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "syscalls.h"

namespace etw {

struct Patch {
    std::uintptr_t slot = 0;
    std::uint64_t original = 0;
    std::wstring module;
};

struct State {
    HANDLE process = nullptr;
    std::uintptr_t stub = 0;
    std::vector<Patch> patches;
    bool active = false;
};

// Redirects EtwEventWrite* imports in every module that imports them from
// ntdll to a 3-byte `xor eax,eax; ret` page in the target. Existing IATs only;
// delay imports and direct syscalls are outside this mechanism. Returns the
// number of newly redirected slots. Can be called again after the payload maps.
std::size_t suppress(HANDLE process, DWORD pid, nt::Table& table,
                     State& state,
                     const std::function<void(const std::wstring&)>& log);

// Restores every slot and frees the stub. If any slot cannot be restored the
// stub is kept alive so a live IAT never points at freed memory.
bool restore(State& state, const std::function<void(const std::wstring&)>& log);

}  // namespace etw
