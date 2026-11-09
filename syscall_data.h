#pragma once
//
// Runtime resolution in syscalls.cpp is authoritative; these values are
// only used when ntdll stubs are hooked or unreadable.

namespace ll_gen {

inline constexpr unsigned k_gadget_rva = 0x9D5F2u;  // syscall; ret

inline constexpr unsigned kNtOpenProcess = 0x26u;
inline constexpr unsigned kNtAllocateVirtualMemory = 0x18u;
inline constexpr unsigned kNtFreeVirtualMemory = 0x1Eu;
inline constexpr unsigned kNtProtectVirtualMemory = 0x50u;
inline constexpr unsigned kNtWriteVirtualMemory = 0x3Au;
inline constexpr unsigned kNtReadVirtualMemory = 0x3Fu;
inline constexpr unsigned kNtCreateThreadEx = 0xC2u;
inline constexpr unsigned kNtWaitForSingleObject = 0x4u;
inline constexpr unsigned kNtTerminateThread = 0x53u;
inline constexpr unsigned kNtClose = 0xFu;
inline constexpr unsigned kNtQueryInformationProcess = 0x19u;

}  // namespace ll_gen
