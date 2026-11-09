#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <string>

// Thin NT layer used by the injector. On x64 every function is called through
// a per-boot trampoline that puts a service number into eax and jumps to a
// `syscall; ret` inside ntdll. The numbers and the gadget are resolved from the
// running ntdll at startup; the generated header is only a fallback. On x86 the
// same table is filled with ntdll exports, because entering the WOW64 syscall
// gate from an arbitrary stub is a different mechanism entirely.
namespace nt {

inline constexpr LONG k_status_success = 0;
inline constexpr LONG k_status_timeout = 0x00000102;
inline constexpr LONG k_status_pending = 0x00000103;
inline constexpr LONG k_status_buffer_too_small = 0xC0000023;
inline constexpr LONG k_status_info_length_mismatch = 0xC0000004;

inline bool ok(LONG status) { return status >= 0; }

std::wstring status_text(LONG status);

using NtOpenProcessFn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID);
using NtAllocateVirtualMemoryFn = LONG(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using NtFreeVirtualMemoryFn = LONG(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
using NtProtectVirtualMemoryFn = LONG(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
using NtWriteVirtualMemoryFn = LONG(NTAPI*)(HANDLE, PVOID, const void*, SIZE_T, PSIZE_T);
using NtReadVirtualMemoryFn = LONG(NTAPI*)(HANDLE, const void*, PVOID, SIZE_T, PSIZE_T);
using NtCreateThreadExFn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                        PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
using NtWaitForSingleObjectFn = LONG(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
using NtTerminateThreadFn = LONG(NTAPI*)(HANDLE, LONG);
using NtCloseFn = LONG(NTAPI*)(HANDLE);
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct ClientId {
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
};

struct Table {
    NtOpenProcessFn open_process = nullptr;
    NtAllocateVirtualMemoryFn allocate = nullptr;
    NtFreeVirtualMemoryFn free = nullptr;
    NtProtectVirtualMemoryFn protect = nullptr;
    NtWriteVirtualMemoryFn write = nullptr;
    NtReadVirtualMemoryFn read = nullptr;
    NtCreateThreadExFn create_thread = nullptr;
    NtWaitForSingleObjectFn wait = nullptr;
    NtTerminateThreadFn terminate_thread = nullptr;
    NtCloseFn close = nullptr;
    NtQueryInformationProcessFn query_information = nullptr;

    bool direct = false;
    std::wstring mode;
};

// Initialises the singleton table. `prefer_direct` is honoured on the first
// call; later calls just return the existing table. error is empty on success.
Table& init(bool prefer_direct, std::wstring& error);
Table& get();

// Convenience wrappers that translate the NT status to a readable string.
bool read_memory(HANDLE process, std::uintptr_t address, void* buffer,
                 std::size_t size, std::wstring& error);
bool write_memory(HANDLE process, std::uintptr_t address, const void* buffer,
                  std::size_t size, std::wstring& error);
bool protect_memory(HANDLE process, std::uintptr_t address, std::size_t size,
                    ULONG protection, ULONG& previous, std::wstring& error);
bool free_memory(HANDLE process, std::uintptr_t address, std::size_t size,
                 std::wstring& error);

HANDLE create_remote_thread(HANDLE process, std::uintptr_t start,
                            std::uintptr_t argument, std::wstring& error);

bool wait_handle(HANDLE handle, std::uint32_t timeout_ms, bool& timed_out,
                 std::wstring& error);

void close_handle(HANDLE handle);

bool query_peb(HANDLE process, std::uintptr_t& peb, std::wstring& error);

}  // namespace nt
