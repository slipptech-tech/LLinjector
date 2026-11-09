@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem --- locate the MSVC toolchain -----------------------------------------------
rem vswhere always returns the newest installed instance, so a Visual Studio
rem 2026 install wins over 2022 without hardcoding either one.

set "VSDIR="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -products * ^
      -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
      -property installationPath`) do set "VSDIR=%%i"
)

if not defined VSDIR (
  for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2026\Professional"
    "C:\Program Files\Microsoft Visual Studio\2026\Community"
    "C:\Program Files\Microsoft Visual Studio\2026\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\18\Professional"
    "C:\Program Files\Microsoft Visual Studio\18\Community"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
  ) do (
    if not defined VSDIR if exist "%%~P\VC\Auxiliary\Build\vcvars64.bat" set "VSDIR=%%~P"
  )
)

if not defined VSDIR (
  echo [x] Visual Studio with the C++ x64 toolset was not found.
  exit /b 1
)

if not exist "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" (
  echo [x] vcvars64.bat missing under "%VSDIR%"
  exit /b 1
)

echo toolchain: "%VSDIR%"

echo.
echo [0/3] generating syscall data from the live ntdll
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\gen_syscalls.ps1
if errorlevel 1 (
  echo [x] syscall generator failed
  exit /b 1
)

if not exist build mkdir build
if not exist build\obj mkdir build\obj
if not exist build\obj\x64 mkdir build\obj\x64
if not exist build\obj\x86 mkdir build\obj\x86

set "CFLAGS=/nologo /std:c++20 /O2 /W4 /EHsc /permissive- /utf-8 /DUNICODE /D_UNICODE /MD"
set "LDFLAGS=/nologo /SUBSYSTEM:WINDOWS /MANIFEST:NO /DEBUG:NONE /OPT:REF /OPT:ICF"
set "LIBS=comctl32.lib comdlg32.lib shell32.lib user32.lib gdi32.lib advapi32.lib"
set "SOURCES=src\syscalls.cpp src\injector.cpp src\unlink.cpp src\etw.cpp src\cleanup.cpp src\main.cpp"

echo.
echo [1/3] x64: LLInjector, verification payload, normal payload
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cl %CFLAGS% /Fo:build\obj\x64\ /c %SOURCES%
if errorlevel 1 exit /b 1
link %LDFLAGS% /MACHINE:X64 /OUT:build\LLInjector.exe ^
     build\obj\x64\syscalls.obj build\obj\x64\injector.obj build\obj\x64\unlink.obj ^
     build\obj\x64\etw.obj build\obj\x64\cleanup.obj build\obj\x64\main.obj %LIBS%
if errorlevel 1 exit /b 1
mt.exe -nologo -manifest app.manifest -outputresource:"build\LLInjector.exe;#1"
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fo:build\obj\x64\verify_payload.obj /c test\verify_payload.cpp
if errorlevel 1 exit /b 1
link /nologo /DLL /MACHINE:X64 /OUT:build\verify_payload_x64.dll ^
     build\obj\x64\verify_payload.obj ntdll.lib
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fo:build\obj\x64\payload.obj /c test\payload.cpp
if errorlevel 1 exit /b 1
link /nologo /DLL /MACHINE:X64 /OUT:build\test_payload_x64.dll ^
     build\obj\x64\payload.obj
if errorlevel 1 exit /b 1

echo.
echo [2/3] x86: LLInjector_x86, verification payload, normal payload
call "%VSDIR%\VC\Auxiliary\Build\vcvars32.bat" >nul || exit /b 1
cl %CFLAGS% /Fo:build\obj\x86\ /c %SOURCES%
if errorlevel 1 exit /b 1
link %LDFLAGS% /MACHINE:X86 /OUT:build\LLInjector_x86.exe ^
     build\obj\x86\syscalls.obj build\obj\x86\injector.obj build\obj\x86\unlink.obj ^
     build\obj\x86\etw.obj build\obj\x86\cleanup.obj build\obj\x86\main.obj %LIBS%
if errorlevel 1 exit /b 1
mt.exe -nologo -manifest app.manifest -outputresource:"build\LLInjector_x86.exe;#1"
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fo:build\obj\x86\verify_payload.obj /c test\verify_payload.cpp
if errorlevel 1 exit /b 1
link /nologo /DLL /MACHINE:X86 /OUT:build\verify_payload_x86.dll ^
     build\obj\x86\verify_payload.obj ntdll.lib
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fo:build\obj\x86\payload.obj /c test\payload.cpp
if errorlevel 1 exit /b 1
link /nologo /DLL /MACHINE:X86 /OUT:build\test_payload_x86.dll ^
     build\obj\x86\payload.obj
if errorlevel 1 exit /b 1

echo.
echo [3/3] build complete:
dir /b build\*.exe build\*.dll
endlocal
