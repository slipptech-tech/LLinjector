#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>

#include "config.h"

namespace loader_unlink {

struct Report {
    bool peb_lists = false;
    bool hash = false;
    bool rb_tree = false;
    std::wstring detail;
};

// Removes the loaded module from the target's loader structures.
// PEB/LDR_DATA_TABLE_ENTRY field offsets are the stable loader ABI; HashLinks
// and the RB node offsets are discovered per process because they move with
// Windows updates. Validation happens before any write, and the RB node is
// removed by the target itself through RtlRbRemoveNode.
Report hide(HANDLE process, std::uintptr_t base, const Config& config,
            const std::function<void(const std::wstring&)>& log);

}  // namespace loader_unlink
