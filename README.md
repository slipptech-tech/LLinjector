# LLInjector

DLL loader via `LoadLibraryExW` with full user-mode stealth:
removes from PEB lists, `LdrpHashTable`, and two loader RB-trees,
suppresses `EtwEventWrite*` through the IAT, cleans up deleted blocks, and attempts to delete
the temporary file copy. Delivery is via `NtCreateThreadEx` using the syscall table,
without `CreateRemoteThread`.

This is not an "invisible" injection. At the end of the document, there's a section
["Residual Traces"](#остаточные-следы) that lists what exactly remains
after `LoadLibraryExW` and why it cannot be closed from user mode.

## Build

```
build.bat
```

The script finds Visual Studio using `vswhere` (starting with the newest version), runs `tools/gen_syscalls.ps1`, and then builds x64 and x86 in two separate parts of the toolchain.
The generator takes the SSN and RVA of the syscall gadget from the current `ntdll.dll`. At runtime, SSNs are first searched by parsing `ntdll` stubs, then the generated header is used, followed by Halo's Gate. 
There are no hardcoded SSNs or gadget RVAs.

# Usage
Without parameters, a window opens. With parameters, it works in console mode.
```
LLInjector.exe --list
LLInjector.exe --pid 1234 --dll "C:pathtolibrary.dll"
LLInjector.exe --name notepad --dll "C:pathtolibrary.dll" --quiet
```
| Parameter | Meaning |
| --- | --- |
| `--list` | list of processes with PID and bitness |
| `--pid <n>` | specific process |
| `--name <name>` | search by name: exact match first, then substring |
| `--dll <path>` | what to load |
| `--no-peb` | don't touch the three PEB lists |
| `--no-hash` | don't slice the `LdrpHashTable` |
| `--no-rbtree` | don't remove RB nodes |
| `--no-etw` | don't redirect `EtwEventWrite*` |
| `--no-stage` | load the original file, without a temporary copy |
| `--keep-staged` | don't try to delete the temporary copy |
| `--no-syscalls` | don't build a direct-syscall table (x64) |
| `--no-terminate` | don't terminate the thread on `DllMain` timeout |
| `--quiet` | don't wait for Enter at the end |
| `--no-elevate` | don't restart the GUI with UAC

### DLL Dependencies

`LoadLibraryExW` is called with `LOAD_WITH_ALTERED_SEARCH_PATH`, which makes the DLL's own folder the search base for its dependencies. Standard `LoadLibraryW` looks for dependencies in the target exe folder, System32, Windows, the current folder, and PATH; the loaded DLL's folder is not in this list. Hence the typical `ERROR_MOD_NOT_FOUND (126)` for a DLL that lies next to its `dep.dll`.

Staging prefers the source DLL folder precisely for this reason: neighboring dependencies remain available. If the folder is read-only, `%TEMP%` is used.

### CS2

CS2 in Trusted Mode will not load an unsigned DLL and will return `126`. Launching requires the `-allow_third_party_software` flag; this is a game limitation, not an injector one.

## What the Stealth Pass Does

### 1. Delivery

- `OpenProcess` with required privileges, enabling `SeDebugPrivilege`.
- Checking x64/x86 target and DLL.
- `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + `NtProtectVirtualMemory` for the parameters block and loader stub.
- The thread is created via `NtCreateThreadEx` (x64 — via runtime syscall table, x86 — via `ntdll` export). The start function is a stub that calls `LoadLibraryExW` with the DLL path and stores the result/`GetLastError`.
- `NtWaitForSingleObject` waits for completion. Upon timeout, the thread can be terminated with `NtTerminateThread`.
- `CreateRemoteThread` is absent in code.

What it hides: the very fact of calling the Win32 API for remote thread creation.
What remains: kernel thread callbacks, ETW-TI, thread record and its start address, image-load callback from `LoadLibraryExW`.

### 2. PEB

All three `PEB->Ldr` lists are removed:

- `InLoadOrderModuleList`;
- `InMemoryOrderModuleList`;
- `InInitializationOrderModuleList`.

PEB/LDR offsets are fetched by bitness (this is a stable loader ABI) rather than by OS version.

What it hides: the module disappears from loader-list traversals (Toolhelp, naive enumeration).
What remains: the `LDR_DATA_TABLE_ENTRY` itself, its `FullDllName`/`BaseDllName`, `EntryPoint`, `DdagNode`, and VAD/image section.

### 3. LdrpHashTable

The `HashLinks` offset is determined dynamically: candidates in `LDR_DATA_TABLE_ENTRY` are iterated, verifying that the bucket chain reaches `ntdll`. Then the node is unlinked from the bucket.

What it hides: `GetModuleHandleW`/name-based search no longer finds the module.
What remains: the entry and name/path strings in the loader-heap; other loader caches.

### 4. Loader RB-Trees

Two nodes (`BaseAddressIndexNode` and `MappingInfoIndexNode`) and their tree objects in `ntdll` data are found dynamically. The parent chain to the root, `Root`, and `Min` are verified. Removal is performed **inside the target** via `RtlRbRemoveNode`, rather than by writing pointers from the outside. After the call, it is verified that the node is no longer in the tree.

What it hides: loader address search (`LdrFindEntryForAddress`).
What remains: the image section/VAD, through which `RtlPcToFileHeader` and `GetModuleHandleEx(FROM_ADDRESS)` still find the base.

### 5. ETW

The IATs of all target modules are scanned. For imports from `ntdll` named `EtwEventWrite`, `EtwEventWriteEx`, `EtwEventWriteFull`, `EtwEventWriteNoRegistration`, `EtwEventWriteTransfer`, `EtwEventWriteString`, `EtwEventWriteEndScenario`, `EtwEventWriteStartScenario`, the slot is redirected to a page containing `xor eax, eax; ret`. The `ntdll` code is not patched.

Before loading the DLL, 19 slots are found in system modules; after loading, a rescan is performed: the verification DLL adds one more slot. On a successful path, the stub remains allocated because IAT slots point to it.

What it hides: events flowing through these IAT imports.
What remains: direct calls via `GetProcAddress`, `NtTraceEvent`, other ETW APIs, kernel providers, and the very presence of an anonymous RX page.

### 6. Cleanup

- All remote blocks (`loader-stub`, parameters, result) are freed after the thread completes.
- A temporary copy is created via `CREATE_NEW` + `CopyFileW`; the source file is not modified.
- After loading, `DeleteFileW` is executed, followed by `NtSetInformationFile(FileDispositionInformationEx, 64)` with flags `DELETE | POSIX_SEMANTICS`.

What it hides: nothing on its own.
What remains: `LoadLibraryExW` holds the image section, so deletion returns `5` / `0xC0000121` (`STATUS_CANNOT_DELETE`), and the file remains.

## Empirical Verification

The verification DLL, after loading, waits 8 seconds and writes `%TEMP%\LLInjector_verify_<pid>.txt`. It checks the name, address, Toolhelp, `LdrFindEntryForAddress`, `RtlPcToFileHeader`, and its own `EtwEventWrite` IAT import.

### x64, Full Pass

Command: `build\LLInjector.exe --pid <notepad> --dll build\verify_payload_x64.dll --quiet`.

| Check | Result |
| --- | --- |
| `GetModuleHandleW(name)` | `0`, error `126` |
| `CreateToolhelp32Snapshot` | module absent (`0`) |
| `LdrFindEntryForAddress` | `0xC0000135` (`STATUS_DLL_NOT_FOUND`), entry `0` |
| `RtlPcToFileHeader` | module base (image section) |
| `GetModuleHandleEx(FROM_ADDRESS)` | module base (image section) |
| IAT `EtwEventWrite` | `0` (stub) |
| `PebLists` / hash / RB | `3/3`, hash cut, 2 RB nodes removed |
| RB after removal | `contains node: no` for both trees |
| `DeleteFileW` / POSIX | `5` / `0xC0000121`; `file_exists=1` |
| Syscall mode | x64 direct syscalls `11/11` |

### x86, Full Pass

Same for `SysWOW64\notepad.exe` and `build\LLInjector_x86.exe`: `by_name=0`, `toolhelp=0`, `ldr_find_status=0xC0000135`, `etw_return=0`, RB nodes removed, `file_exists=1`. NT Mode: `x86: ntdll exports`.

### Disabling Techniques

Running with `--no-peb --no-hash --no-rbtree --no-etw --no-stage` on x64 yielded the expected reverse behavior:

| Check | Result |
| --- | --- |
| `GetModuleHandleW(name)` | module base |
| `toolhelp` | `1` |
| `LdrFindEntryForAddress` | `0`, entry found |
| `EtwEventWrite` | `0x57` (`ERROR_INVALID_PARAMETER`, real ntdll) |
| File | source file, staging was not used |

A separate run with `--no-etw` returned `etw_return=0x57` and did not redirect the IAT, meaning the switch indeed disables the corresponding technique.

### Standard Test DLL

`build\test_payload_x64.dll` and `build\test_payload_x86.dll` create `%TEMP%\LLInjector_payload_<pid>.txt`. For both bitnesses, the marker appeared, and `DllMain` executed inside the foreign process.

### What `by_address` Means

`GetModuleHandleEx(FROM_ADDRESS)` and `RtlPcToFileHeader` return the base, even though `LdrFindEntryForAddress` already returns `0xC0000135`. This is not an RB removal bug: the RB nodes are indeed unlinked, and `RtlPcToFileHeader` returns the base via the image section. `GetModuleHandleEx(FROM_ADDRESS)` behaves similarly on this build, meaning it finds the image not via loader indices. You cannot remove the VAD while the DLL code is executing. Therefore, `by_address=base` is an expected residual trace, not an indication that the RB technique failed.

## Residual Traces

Below is what remains after a successful pass. These are not "flaws waiting to be fixed": most reside outside the user-mode loader and cannot be concealed by `LoadLibraryExW`.

### NTFS and File System

- The temporary copy remains on disk. `DeleteFileW` returns `5` (access denied), and POSIX deletion via `NtSetInformationFile(FileDispositionInformationEx)` returns `0xC0000121` (`STATUS_CANNOT_DELETE`). The reason is the image section held by the loader while the DLL is mapped. Renaming is possible, deletion is not.
- The path `build\llinj_<pid>_<tick>_<attempt>.dll` (or `%TEMP%`) remains, along with the file name, its size, creation/write time, and the NTFS record in the MFT.
- Even if the file could eventually be deleted, records remain in `$MFT`, `$LogFile`, USN journal, shadow copies, backups, Prefetch/ShimCache/Amcache (depending on policy), as well as EDR/AV telemetry that observed the creation and opening of the file.
- `FullDllName` and `BaseDllName` strings remain in the target loader heap; they can be found by memory scanning, even after unlinking the lists.
- The user's original file is neither modified nor deleted; the copy is a separate file.

### VAD and Image Section

- `LoadLibraryExW` creates an image section and maps it into the process. A kernel VAD entry remains with the `SEC_IMAGE` type and the file name. This is visible via `NtQueryVirtualMemory(MemoryMappedFilenameInformation)` and equivalent APIs.
- `RtlPcToFileHeader` and `GetModuleHandleEx(FROM_ADDRESS)` find the base through this section. In the check: `pc_to_file` and `by_address` equal the module base.
- `LdrFindEntryForAddress` no longer finds the module (`0xC0000135`) because it uses loader indices. This does not invalidate the VAD.
- Valid PE headers, sections, strings, IAT (including the redirected ETW slot), and executable code remain at the address. A memory scanner can find the image and determine it is a DLL even if it is not in the lists.
- `LoadLibraryExW` provides no way to close the image section without unloading the DLL. Unloading while code is running means executing from freed memory and crashing the process. Therefore, you cannot "delete the file and VAD while keeping the code alive" via `LoadLibraryExW`.

### LdrpHashTable and RB-Trees

- The three PEB lists, hash bucket, and both RB nodes are indeed modified. This is confirmed: `GetModuleHandleW` — `0/126`, Toolhelp — `0`, `LdrFindEntryForAddress` — `0xC0000135`, `tree after remove: contains node: no`.
- The `LDR_DATA_TABLE_ENTRY` itself is not freed. It retains pointers to `FullDllName`, `BaseDllName`, `DdagNode`, `LoadContext`, `OriginalBase`, `LoadTime`, `BaseNameHashValue`, `EntryPoint`, and other fields. We sever links, but do not clear or free the entry: the loader and DLL code may still reference it.
- `LdrpHashTable` is an array of buckets in `ntdll`; after unlinking a node, the bucket contains fewer elements, but the memory itself and the orphaned node remain. A scanner that took a dump before injection will notice the difference; a post-injection scanner may find the entry via residual pointers.
- `LdrpLoadedDllHandleCache` and other loader caches/indices are not separately cleaned. On this build, `GetModuleHandleW` already returns `0`, but relying on the absence of other caches is unsafe: the set of structures depends on the Windows version.
- The kernel has already received an image-load notification at the moment of `LoadLibraryExW`. Unlinking user lists does not remove this event nor undo copy-on-write telemetry.

### ETW

- Only the IAT slots of the eight `EtwEventWrite*` names in modules existing at scan time are redirected. On a successful path, the stub remains, and the IAT points to an anonymous RX page.
- Not covered: direct calls to `EtwEventWrite` via `GetProcAddress`, calls via function pointers, modules loaded later (aside from the rescan right after `LoadLibrary`), `NtTraceEvent`, `EventWrite`/`EventWriteEx` from `advapi32`, other ETW APIs, and providers that do not import these functions.
- Kernel ETW providers (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-Image`, Threat-Intelligence, etc.) operate below the user IAT and see thread creation/image loading regardless of the patch.
- The patch is visible: the IAT slot points to a page absent from the module list; the page has RX permissions and contains `33 C0 C3`. This is an anomaly for a scanner.
- With `--no-etw`, the check returns `0x57` from the real `ntdll`, meaning disabling the technique restores standard behavior.

### Kernel-Level and External Checks

- `NtCreateThreadEx` still passes through the kernel (`PspCreateThread`). `PsSetCreateThreadNotifyRoutine`, ETW-TI, and EDR callbacks trigger; the thread exists, has a start address, a stack, and a kernel record.
- `LoadLibraryExW` triggers the image-load callback (`PsSetLoadImageNotifyRoutine`), and minifilters/AV see the path, base, size, and lack of signature. This happens prior to all unlinks.
- A privileged process/driver can read the VAD, PE image, IAT, loader-heap, and thread memory via `ReadProcessMemory`, `NtQueryVirtualMemory`, `NtQueryInformationProcess`, etc. User-mode lists are not required for this.
- An EDR may maintain its own copy of module lists captured prior to injection and compare them; unlinking references only increases the discrepancy.
- Integrity/signature control tools see the unsigned DLL and the anonymous RX page. In CS2 Trusted Mode, this is blocked separately.
- Post-facto: process dumps, crash dumps, hibernation/pagefiles, loader logs, Prefetch, and network logs may contain the path and image.

### Why `LoadLibraryExW` Cannot Close This

`LoadLibraryExW` is a user-mode wrapper around creating an image section, mapping it into a process, and adding an entry to loader structures. It:

- does not own kernel image-load/thread callbacks and cannot cancel them;
- does not remove the VAD/image section while the DLL is mapped;
- cannot delete a file held by an image section;
- does not clear kernel ETW sessions and ETW-TI;
- does not delete `LDR_DATA_TABLE_ENTRY` and name strings from the loader-heap;
- does not hide the PE image itself from a memory scanner.

The unlink pass removes **available user-mode references** to the module. It does not render the load invisible or cancel already occurred kernel events. This is why the report honestly logs `by_address`/`pc_to_file`, `file_exists=1`, and `STATUS_CANNOT_DELETE`, rather than claiming "everything is hidden."

## Limitations

- `LoadLibraryExW` only: the DLL must have a standard entry point and be compatible with the target process; dependencies must be located nearby, in system folders, or in the target's PATH.
- Protected processes and anti-cheats may block `OpenProcess`/memory writing. The injector does not bypass their protection.
- If `DllMain` hangs, waiting aborts on timeout; with `--no-terminate`, the thread remains.
- Re-injecting an already loaded DLL does not trigger `DllMain` again.
- The x86 build uses `ntdll` exports rather than direct syscalls; the WOW64 syscall gate is not bypassed.
- For GUI, UAC is requested at startup; `--no-elevate` retains the current token. `SeDebugPrivilege` is enabled explicitly if present in the token.
