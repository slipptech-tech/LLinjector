#pragma once

#include <windows.h>

#include <string>

namespace cleanup {

struct StagedFile {
    std::wstring source;
    std::wstring path;
    bool created = false;
    bool deleted = false;
    DWORD last_error = 0;
};

// Copies the payload to a fresh file name. The source directory is tried
// first so sibling dependencies keep resolving; %TEMP% is the fallback when
// the source directory is not writable. The caller's file is never touched.
bool stage(const std::wstring& source, StagedFile& out, std::wstring& error);

// Deletes the staged copy and verifies the name is gone. A mapped image whose
// file was opened with FILE_SHARE_DELETE (the loader does that) is removed from
// the namespace even though the sections stay mapped.
bool remove(StagedFile& file, std::wstring& detail);

}  // namespace cleanup
