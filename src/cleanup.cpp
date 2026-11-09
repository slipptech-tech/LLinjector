// Hides: nothing by itself; frees remote stubs and tries to unlink the staged
// file. Remains: LoadLibrary keeps the image section mapped, so deletion returns
// STATUS_CANNOT_DELETE and the file, its path and the NTFS record stay.

#include "cleanup.h"

#include <vector>

namespace cleanup {
namespace {

std::wstring error_text(DWORD code) {
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
    if (text.empty()) text = L"unknown error";
    wchar_t suffix[32];
    swprintf_s(suffix, L" (%lu)", code);
    return text + suffix;
}

std::wstring source_directory(const std::wstring& path) {
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    return path.substr(0, slash + 1);
}

std::wstring temp_directory() {
    DWORD needed = GetTempPathW(0, nullptr);
    if (!needed) return {};
    std::wstring buffer(static_cast<std::size_t>(needed) + 1, L'\0');
    const DWORD written = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (!written || written >= buffer.size()) return {};
    buffer.resize(written);
    return buffer;
}

// CREATE_NEW reserves a name without touching an existing file. The file is
// then overwritten by CopyFileW; after that only the loader opens it.
bool reserve_and_copy(const std::wstring& directory, const std::wstring& source,
                      std::wstring& path, std::wstring& error) {
    if (directory.empty()) return false;

    const unsigned long long tick = GetTickCount64();
    const DWORD pid = GetCurrentProcessId();

    for (int attempt = 0; attempt < 16; ++attempt) {
        wchar_t name[96];
        swprintf_s(name, L"llinj_%lu_%llx_%d.dll", pid, tick, attempt);
        const std::wstring candidate = directory + name;

        HANDLE file = CreateFileW(candidate.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            const DWORD code = GetLastError();
            if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS) continue;
            error = L"CreateFileW " + error_text(code);
            return false;
        }
        CloseHandle(file);

        if (!CopyFileW(source.c_str(), candidate.c_str(), FALSE)) {
            const DWORD code = GetLastError();
            DeleteFileW(candidate.c_str());
            error = L"CopyFileW " + error_text(code);
            return false;
        }

        path = candidate;
        return true;
    }

    error = L"could not reserve a staged file name";
    return false;
}

}  // namespace

bool stage(const std::wstring& source, StagedFile& out, std::wstring& error) {
    out = {};
    out.source = source;

    std::wstring path;
    std::wstring first_error;
    if (reserve_and_copy(source_directory(source), source, path, first_error)) {
        out.path = path;
        out.created = true;
        return true;
    }

    // The source folder may be read-only (Program Files, a game directory).
    // Keep the extension and let the loader use the temp folder instead.
    std::wstring temp_error;
    if (reserve_and_copy(temp_directory(), source, path, temp_error)) {
        out.path = path;
        out.created = true;
        return true;
    }

    error = first_error;
    if (!temp_error.empty()) error += L"; temp: " + temp_error;
    return false;
}

bool remove(StagedFile& file, std::wstring& detail) {
    if (!file.created || file.path.empty()) {
        file.deleted = true;
        detail = L"staging was not used";
        return true;
    }

    std::wstring attempts;
    DWORD last_error = 0;

    if (!DeleteFileW(file.path.c_str())) {
        last_error = GetLastError();
        attempts += L"DeleteFile=" + error_text(last_error);

        if (last_error != ERROR_FILE_NOT_FOUND) {
            // A mapped image refuses a plain delete while the section lives.
            // POSIX semantics remove the name even with the image mapped and
            // the loader's handle still open; the mapping keeps running.
            const DWORD attributes = GetFileAttributesW(file.path.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES)
                SetFileAttributesW(file.path.c_str(), FILE_ATTRIBUTE_NORMAL);
        }
    }

    if (GetFileAttributesW(file.path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        HANDLE handle = CreateFileW(
            file.path.c_str(), DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            // Native FileDispositionInformationEx (64) is what backs the
            // Win32 FileDispositionInfoEx; calling it directly avoids the
            // older Win32 enum path on pre-RS2 builds.
            struct IoStatusBlock {
                LONG status;
                ULONG_PTR information;
            } iosb{};
            DWORD flags = FILE_DISPOSITION_FLAG_DELETE |
                          FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
            using NtSetInformationFileFn = LONG(NTAPI*)(HANDLE, void*, void*,
                                                        ULONG, ULONG);
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            const auto set_info = ntdll
                ? reinterpret_cast<NtSetInformationFileFn>(
                      GetProcAddress(ntdll, "NtSetInformationFile"))
                : nullptr;
            if (set_info) {
                const LONG status = set_info(handle, &iosb, &flags,
                                             sizeof(flags), 64 /*FileDispositionInformationEx*/);
                if (status < 0) {
                    attempts += L"; NtSetInformationFile=0x" +
                                [&] {
                                    wchar_t text[32];
                                    swprintf_s(text, L"%08lX",
                                               static_cast<unsigned long>(status));
                                    return std::wstring(text);
                                }();
                }
            } else {
                FILE_DISPOSITION_INFO_EX disposition{};
                disposition.Flags = flags;
                if (!SetFileInformationByHandle(handle, FileDispositionInfoEx,
                                                &disposition,
                                                sizeof(disposition))) {
                    attempts += L"; SetFileInformationByHandle=" +
                                error_text(GetLastError());
                }
            }
            CloseHandle(handle);
        } else {
            attempts += L"; open(DELETE)=" + error_text(GetLastError());
        }
    }

    file.last_error = GetLastError();
    if (GetFileAttributesW(file.path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        file.deleted = true;
        detail = L"staged copy removed: " + file.path;
        return true;
    }

    file.deleted = false;
    detail = L"staged copy is still present: " + file.path + L" (" +
             (attempts.empty() ? error_text(file.last_error) : attempts) + L")";
    return false;
}

}  // namespace cleanup
