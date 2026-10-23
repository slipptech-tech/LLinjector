// LLInjector - loads a DLL into a chosen process with a remote LoadLibraryExW.
//
// The window reads like a two-step form: pick a process in the list, pick a DLL
// in a file dialog, press the button. Command line flags exist so the same
// engine can be driven from a script; with no flags it opens the window.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

#include "inject.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")

namespace {

enum : int {
    IDC_FILTER = 101,
    IDC_REFRESH,
    IDC_LIST,
    IDC_DLL,
    IDC_BROWSE,
    IDC_INJECT,
    IDC_LOG,
};

struct Options {
    bool gui = true;
    bool list = false;
    bool help = false;
    bool quiet = false;
    bool no_elevate = false;
    bool has_pid = false;
    DWORD pid = 0;
    std::wstring name;
    std::wstring dll;
};

HINSTANCE g_instance = nullptr;

HWND g_main = nullptr;
HWND g_filter_label = nullptr;
HWND g_filter = nullptr;
HWND g_refresh = nullptr;
HWND g_list = nullptr;
HWND g_dll_label = nullptr;
HWND g_dll = nullptr;
HWND g_browse = nullptr;
HWND g_inject = nullptr;
HWND g_log = nullptr;

HFONT g_font = nullptr;
HFONT g_mono = nullptr;
int g_dpi = 96;

std::vector<ProcessEntry> g_processes;
std::wstring g_log_text;

HANDLE g_console = INVALID_HANDLE_VALUE;
bool g_own_console = false;

int scaled(int value) {
    return MulDiv(value, g_dpi, 96);
}

std::wstring text_of(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
    return text;
}

std::wstring lowered(std::wstring text) {
    for (wchar_t& c : text) c = static_cast<wchar_t>(std::towlower(c));
    return text;
}

HFONT make_font(int points, const wchar_t* face, bool bold) {
    LOGFONTW info{};
    info.lfHeight = -MulDiv(points, g_dpi, 72);
    info.lfWeight = bold ? FW_SEMIBOLD : FW_NORMAL;
    info.lfCharSet = DEFAULT_CHARSET;
    info.lfQuality = CLEARTYPE_QUALITY;
    lstrcpynW(info.lfFaceName, face, LF_FACESIZE);
    return CreateFontIndirectW(&info);
}

// ---------------------------------------------------------------- console ---

bool has_redirected_stdout() {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    return GetConsoleMode(out, &mode) == 0;   // a console handle would succeed
}

bool attach_console() {
    // When the caller redirected output (a pipe or a file), honour that handle
    // instead of opening the console device.
    if (has_redirected_stdout()) {
        g_console = GetStdHandle(STD_OUTPUT_HANDLE);
        return true;
    }

    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        if (!AllocConsole()) return false;
        g_own_console = true;
    }

    HANDLE console = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
    if (console == INVALID_HANDLE_VALUE) return false;
    g_console = console;
    SetStdHandle(STD_OUTPUT_HANDLE, console);
    return true;
}

void con_write(const std::wstring& text) {
    if (g_console == INVALID_HANDLE_VALUE) return;

    DWORD mode = 0;
    if (GetConsoleMode(g_console, &mode)) {
        std::wstring out;
        out.reserve(text.size() + 8);
        for (wchar_t c : text) {
            if (c == L'\n') out += L'\r';
            out += c;
        }
        DWORD written = 0;
        WriteConsoleW(g_console, out.c_str(), static_cast<DWORD>(out.size()),
                      &written, nullptr);
        return;
    }

    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                           static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        utf8.data(), needed, nullptr, nullptr);
    DWORD written = 0;
    WriteFile(g_console, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

void pause_if_own_console(bool quiet) {
    if (!g_own_console || quiet) return;
    con_write(L"\nНажмите Enter, чтобы закрыть...");
    HANDLE input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (input == INVALID_HANDLE_VALUE) return;
    wchar_t buffer[8];
    DWORD read = 0;
    ReadConsoleW(input, buffer, ARRAYSIZE(buffer), &read, nullptr);
    CloseHandle(input);
}

// -------------------------------------------------------------- elevation ---

bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;

    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation,
                                        sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

enum class Elevation { Launched, Cancelled, Failed };

Elevation relaunch_elevated() {
    wchar_t self[MAX_PATH * 2] = {};
    if (!GetModuleFileNameW(nullptr, self, ARRAYSIZE(self))) return Elevation::Failed;

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOASYNC;
    info.lpVerb = L"runas";
    info.lpFile = self;
    info.lpParameters = L"--elevated";
    info.nShow = SW_SHOWNORMAL;

    if (ShellExecuteExW(&info)) return Elevation::Launched;
    return GetLastError() == ERROR_CANCELLED ? Elevation::Cancelled : Elevation::Failed;
}

// -------------------------------------------------------------------- gui ---

void log_line(const std::wstring& text) {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t stamp[64];
    swprintf_s(stamp, L"[%02u:%02u:%02u]  ", now.wHour, now.wMinute, now.wSecond);

    // The control is rebuilt from this buffer instead of appended to. A fresh
    // multiline edit already holds an empty paragraph, so appending leaves a
    // stray blank line at the top.
    g_log_text += std::wstring(stamp) + text + L"\r\n";

    if (g_log) {
        SetWindowTextW(g_log, g_log_text.c_str());
        const WPARAM end = static_cast<WPARAM>(g_log_text.size());
        SendMessageW(g_log, EM_SETSEL, end, static_cast<LPARAM>(end));
        SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
    }
    OutputDebugStringW((text + L"\n").c_str());
}

void layout_window() {
    RECT client{};
    GetClientRect(g_main, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;

    const int margin = scaled(12);
    const int gap = scaled(8);
    const int row = scaled(26);
    const int button_width = scaled(112);

    // filter row
    MoveWindow(g_filter_label, margin, margin + scaled(5), scaled(56), row, TRUE);
    const int filter_x = margin + scaled(60);
    MoveWindow(g_filter, filter_x, margin,
               width - filter_x - margin - button_width - gap, row, TRUE);
    MoveWindow(g_refresh, width - margin - button_width, margin, button_width, row, TRUE);

    const int list_top = margin + row + gap;

    // bottom rows, anchored to the client edge
    const int inject_height = scaled(34);
    const int inject_width = scaled(190);
    const int inject_y = height - margin - inject_height;
    const int dll_y = inject_y - gap - row;
    const int log_height = scaled(150);
    const int log_y = dll_y - gap - log_height;

    MoveWindow(g_list, margin, list_top, width - 2 * margin,
               (log_y - gap - list_top > 0) ? log_y - gap - list_top : 0, TRUE);

    MoveWindow(g_dll_label, margin, dll_y + scaled(5), scaled(36), row, TRUE);
    const int dll_x = margin + scaled(40);
    MoveWindow(g_dll, dll_x, dll_y, width - dll_x - margin - button_width - gap, row, TRUE);
    MoveWindow(g_browse, width - margin - button_width, dll_y, button_width, row, TRUE);

    MoveWindow(g_log, margin, log_y, width - 2 * margin, log_height, TRUE);
    MoveWindow(g_inject, width - margin - inject_width, inject_y, inject_width,
               inject_height, TRUE);

    // Leave room for the vertical scrollbar, otherwise the last column pushes
    // the list into horizontal scrolling even though it fits the client area.
    const int list_width = width - 2 * margin - scaled(4) - GetSystemMetrics(SM_CXVSCROLL);
    const int col_pid = scaled(74);
    const int col_name = scaled(200);
    const int col_arch = scaled(66);
    int col_path = list_width - col_pid - col_name - col_arch;
    if (col_path < scaled(120)) col_path = scaled(120);

    ListView_SetColumnWidth(g_list, 0, col_pid);
    ListView_SetColumnWidth(g_list, 1, col_name);
    ListView_SetColumnWidth(g_list, 2, col_arch);
    ListView_SetColumnWidth(g_list, 3, col_path);
}

const ProcessEntry* find_process(DWORD pid) {
    for (const ProcessEntry& process : g_processes)
        if (process.pid == pid) return &process;
    return nullptr;
}

void populate_list() {
    if (!g_list) return;

    DWORD keep_pid = 0;
    const int selected = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (selected >= 0) {
        LVITEMW item{};
        item.mask = LVIF_PARAM;
        item.iItem = selected;
        if (ListView_GetItem(g_list, &item)) keep_pid = static_cast<DWORD>(item.lParam);
    }

    const std::wstring needle = lowered(text_of(g_filter));

    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_list);

    int row = 0;
    int restore = -1;
    for (const ProcessEntry& process : g_processes) {
        if (!needle.empty() &&
            lowered(process.name).find(needle) == std::wstring::npos)
            continue;

        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<wchar_t*>(L"");
        item.lParam = static_cast<LPARAM>(process.pid);

        const int index = ListView_InsertItem(g_list, &item);
        if (index < 0) continue;

        wchar_t pid_text[16];
        swprintf_s(pid_text, L"%lu", process.pid);
        ListView_SetItemText(g_list, index, 0, pid_text);
        ListView_SetItemText(g_list, index, 1, const_cast<wchar_t*>(process.name.c_str()));
        ListView_SetItemText(g_list, index, 2, const_cast<wchar_t*>(process.arch.c_str()));
        ListView_SetItemText(g_list, index, 3, const_cast<wchar_t*>(process.path.c_str()));

        if (process.pid == keep_pid) restore = index;
        ++row;
    }

    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list, nullptr, TRUE);

    if (restore >= 0) {
        ListView_SetItemState(g_list, restore, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(g_list, restore, FALSE);
    }
}

void refresh_processes() {
    g_processes = list_processes();

    std::sort(g_processes.begin(), g_processes.end(),
              [](const ProcessEntry& a, const ProcessEntry& b) {
                  const int order = _wcsicmp(a.name.c_str(), b.name.c_str());
                  return order != 0 ? order < 0 : a.pid < b.pid;
              });

    populate_list();
    log_line(L"список процессов обновлён: " + std::to_wstring(g_processes.size()));
}

void browse_dll() {
    wchar_t file[MAX_PATH * 2] = {};
    const std::wstring current = text_of(g_dll);
    if (!current.empty()) lstrcpynW(file, current.c_str(), ARRAYSIZE(file));

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g_main;
    dialog.lpstrFilter = L"Библиотеки (*.dll)\0*.dll\0Все файлы (*.*)\0*.*\0";
    dialog.lpstrFile = file;
    dialog.nMaxFile = ARRAYSIZE(file);
    dialog.lpstrTitle = L"Выберите DLL для загрузки в процесс";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR |
                   OFN_HIDEREADONLY;

    if (GetOpenFileNameW(&dialog)) {
        SetWindowTextW(g_dll, file);
        log_line(std::wstring(L"выбрана DLL: ") + file);
    }
}

void show_box(const std::wstring& text, UINT icon) {
    MessageBoxW(g_main, text.c_str(), L"DLL Injector", MB_OK | icon);
}

void do_inject() {
    const int selected = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (selected < 0) {
        show_box(L"Сначала выберите процесс в списке.", MB_ICONINFORMATION);
        return;
    }

    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = selected;
    if (!ListView_GetItem(g_list, &item)) return;
    const DWORD pid = static_cast<DWORD>(item.lParam);

    const std::wstring dll = text_of(g_dll);
    if (dll.empty()) {
        show_box(L"Укажите путь к DLL.", MB_ICONINFORMATION);
        return;
    }
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        show_box(L"Файл не найден:\n" + dll, MB_ICONWARNING);
        return;
    }

    const ProcessEntry* process = find_process(pid);
    const std::wstring name = process ? process->name : L"?";

    log_line(L"--- инъекция ---");
    log_line(L"процесс: " + name + L" (pid " + std::to_wstring(pid) + L")");
    log_line(L"DLL: " + dll);

    EnableWindow(g_inject, FALSE);
    const InjectResult result = inject_loadlibrary(
        pid, dll, [](const std::wstring& step) { log_line(step); }, name);
    EnableWindow(g_inject, TRUE);

    if (result.ok) {
        log_line(result.detail);
        if (result.already_loaded)
            show_box(result.detail, MB_ICONINFORMATION);
        else
            show_box(L"DLL загружена в " + name + L" (pid " + std::to_wstring(pid) +
                        L").\n\n" + result.detail,
                    MB_ICONINFORMATION);
        return;
    }

    log_line(L"ошибка: " + result.detail);
    show_box(L"Инъекция не удалась.\n\n" + result.detail, MB_ICONERROR);
}

void create_children() {
    g_font = make_font(9, L"Segoe UI", false);
    g_mono = make_font(9, L"Consolas", false);

    g_filter_label = CreateWindowExW(0, L"STATIC", L"Фильтр:", WS_CHILD | WS_VISIBLE,
                                     0, 0, 0, 0, g_main, nullptr, g_instance, nullptr);
    g_filter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL,
                               0, 0, 0, 0, g_main,
                               reinterpret_cast<HMENU>(IDC_FILTER), g_instance, nullptr);
    g_refresh = CreateWindowExW(0, L"BUTTON", L"Обновить",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                0, 0, 0, 0, g_main,
                                reinterpret_cast<HMENU>(IDC_REFRESH), g_instance, nullptr);
    g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                             WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                                 LVS_SHOWSELALWAYS,
                             0, 0, 0, 0, g_main,
                             reinterpret_cast<HMENU>(IDC_LIST), g_instance, nullptr);
    g_dll_label = CreateWindowExW(0, L"STATIC", L"DLL:", WS_CHILD | WS_VISIBLE,
                                  0, 0, 0, 0, g_main, nullptr, g_instance, nullptr);
    g_dll = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL,
                            0, 0, 0, 0, g_main,
                            reinterpret_cast<HMENU>(IDC_DLL), g_instance, nullptr);
    g_browse = CreateWindowExW(0, L"BUTTON", L"Обзор...",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                               0, 0, 0, 0, g_main,
                               reinterpret_cast<HMENU>(IDC_BROWSE), g_instance, nullptr);
    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                                ES_AUTOVSCROLL | ES_LEFT | WS_VSCROLL,
                            0, 0, 0, 0, g_main,
                            reinterpret_cast<HMENU>(IDC_LOG), g_instance, nullptr);
    g_inject = CreateWindowExW(0, L"BUTTON", L"Инжектировать",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                               0, 0, 0, 0, g_main,
                               reinterpret_cast<HMENU>(IDC_INJECT), g_instance, nullptr);

    for (HWND control : {g_filter_label, g_filter, g_refresh, g_list, g_dll_label,
                         g_dll, g_browse, g_inject}) {
        if (control && g_font)
            SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    }
    if (g_log && g_mono)
        SendMessageW(g_log, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono), TRUE);

    ListView_SetExtendedListViewStyle(
        g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    const wchar_t* titles[] = {L"PID", L"Процесс", L"Арх.", L"Путь"};
    for (int i = 0; i < 4; ++i) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.pszText = const_cast<wchar_t*>(titles[i]);
        column.cx = scaled(100);
        column.iSubItem = i;
        ListView_InsertColumn(g_list, i, &column);
    }

    layout_window();
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
        case WM_CREATE:
            g_main = window;
            create_children();
            refresh_processes();
            log_line(L"Выберите процесс, укажите DLL и нажмите «Инжектировать».");
            return 0;

        case WM_SIZE:
            layout_window();
            return 0;

        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
            info->ptMinTrackSize.x = scaled(620);
            info->ptMinTrackSize.y = scaled(520);
            return 0;
        }

        case WM_COMMAND: {
            const int id = LOWORD(wparam);
            const int code = HIWORD(wparam);

            if (id == IDC_REFRESH) {
                refresh_processes();
                return 0;
            }
            if (id == IDC_BROWSE) {
                browse_dll();
                return 0;
            }
            if (id == IDC_INJECT) {
                do_inject();
                return 0;
            }
            if (id == IDC_FILTER && code == EN_CHANGE) {
                populate_list();
                return 0;
            }
            break;
        }

        case WM_NOTIFY: {
            const auto* header = reinterpret_cast<NMHDR*>(lparam);
            if (header->idFrom == IDC_LIST && header->code == NM_DBLCLK) {
                if (text_of(g_dll).empty())
                    browse_dll();
                else
                    do_inject();
                return 0;
            }
            break;
        }

        case WM_DROPFILES: {
            const HDROP drop = reinterpret_cast<HDROP>(wparam);
            wchar_t path[MAX_PATH * 2] = {};
            if (DragQueryFileW(drop, 0, path, ARRAYSIZE(path))) {
                const std::wstring dropped = path;
                if (dropped.size() > 4 &&
                    lowered(dropped.substr(dropped.size() - 4)) == L".dll") {
                    SetWindowTextW(g_dll, dropped.c_str());
                    log_line(L"перетащена DLL: " + dropped);
                } else {
                    show_box(L"Нужен файл с расширением .dll", MB_ICONINFORMATION);
                }
            }
            DragFinish(drop);
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            break;
    }

    return DefWindowProcW(window, message, wparam, lparam);
}

int run_gui() {
    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    HDC screen = GetDC(nullptr);
    g_dpi = screen ? GetDeviceCaps(screen, LOGPIXELSY) : 96;
    if (screen) ReleaseDC(nullptr, screen);
    if (g_dpi <= 0) g_dpi = 96;

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = g_instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hIconSm = window_class.hIcon;
    window_class.lpszClassName = L"LLInjectorWindow";

    if (!RegisterClassExW(&window_class)) return 1;

    const std::wstring title =
        L"DLL Injector — загрузка библиотеки в процесс [" + self_arch() + L"]";

    HWND window = CreateWindowExW(WS_EX_ACCEPTFILES, window_class.lpszClassName,
                                  title.c_str(), WS_OVERLAPPEDWINDOW,
                                  CW_USEDEFAULT, CW_USEDEFAULT, scaled(880), scaled(660),
                                  nullptr, nullptr, g_instance, nullptr);
    if (!window) return 1;

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}

// -------------------------------------------------------------------- cli ---

std::wstring process_label(const ProcessEntry& process) {
    return process.name + L" (pid " + std::to_wstring(process.pid) + L")";
}

DWORD resolve_target(const Options& options, std::wstring& resolved_name) {
    std::vector<ProcessEntry> processes = list_processes();

    if (options.has_pid) {
        for (const ProcessEntry& process : processes) {
            if (process.pid == options.pid) {
                resolved_name = process.name;
                break;
            }
        }
        return options.pid;
    }

    const std::wstring wanted = lowered(options.name);

    // Exact name first, so "cs2" does not accidentally match "cs2_benchmark".
    for (const ProcessEntry& process : processes) {
        if (lowered(process.name) == wanted) {
            resolved_name = process.name;
            return process.pid;
        }
    }
    for (const ProcessEntry& process : processes) {
        if (lowered(process.name).find(wanted) != std::wstring::npos) {
            resolved_name = process.name;
            return process.pid;
        }
    }
    return 0;
}

int run_cli(const Options& options) {
    if (!attach_console()) return 1;

    if (options.help) {
        con_write(
            L"LLInjector " + self_arch() + L"\n\n"
            L"  LLInjector.exe                        открыть окно (с запросом UAC)\n"
            L"  LLInjector.exe --list                 список процессов\n"
            L"  LLInjector.exe --pid <n> --dll <файл> загрузить DLL в процесс\n"
            L"  LLInjector.exe --name <имя> --dll <файл>\n\n"
            L"  --quiet        не ждать Enter в конце\n"
            L"  --no-elevate   не запрашивать права администратора (окно)\n\n"
            L"Процесс и DLL должны быть одной разрядности с инжектором.\n");
        pause_if_own_console(options.quiet);
        return 0;
    }

    if (options.list) {
        std::vector<ProcessEntry> processes = list_processes();
        std::sort(processes.begin(), processes.end(),
                  [](const ProcessEntry& a, const ProcessEntry& b) {
                      const int order = _wcsicmp(a.name.c_str(), b.name.c_str());
                      return order != 0 ? order < 0 : a.pid < b.pid;
                  });

        for (const ProcessEntry& process : processes) {
            wchar_t line[64];
            swprintf_s(line, L"%7lu  %-5s  ", process.pid,
                       process.arch.empty() ? L"?" : process.arch.c_str());
            con_write(std::wstring(line) + process.name + L"\n");
        }
        con_write(L"\nвсего: " + std::to_wstring(processes.size()) + L"\n");
        pause_if_own_console(options.quiet);
        return 0;
    }

    if (options.dll.empty()) {
        con_write(L"не указан --dll\n");
        pause_if_own_console(options.quiet);
        return 2;
    }

    std::wstring process_name;
    const DWORD pid = resolve_target(options, process_name);
    if (!pid) {
        con_write(L"процесс не найден\n");
        pause_if_own_console(options.quiet);
        return 1;
    }

    con_write(L"процесс: " + process_name + L" (pid " + std::to_wstring(pid) + L")\n");
    con_write(L"DLL: " + options.dll + L"\n");

    const InjectResult result = inject_loadlibrary(
        pid, options.dll, [](const std::wstring& step) { con_write(L"  " + step + L"\n"); },
        process_name);

    if (result.ok) {
        con_write(L"\nуспех: " + result.detail + L"\n");
        pause_if_own_console(options.quiet);
        return 0;
    }

    con_write(L"\nошибка: " + result.detail + L"\n");
    pause_if_own_console(options.quiet);
    return 1;
}

bool parse_options(Options& options, int& exit_code) {
    exit_code = 0;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        exit_code = 2;
        return false;
    }

    bool cli = false;
    for (int i = 1; i < argc; ++i) {
        const std::wstring argument = argv[i];
        const bool has_value = (i + 1) < argc;
        const std::wstring value = has_value ? argv[i + 1] : L"";

        if (argument == L"--list") {
            options.list = true;
            cli = true;
        } else if (argument == L"--pid" && has_value) {
            options.pid = static_cast<DWORD>(wcstoul(value.c_str(), nullptr, 10));
            options.has_pid = true;
            cli = true;
            ++i;
        } else if (argument == L"--name" && has_value) {
            options.name = value;
            cli = true;
            ++i;
        } else if (argument == L"--dll" && has_value) {
            options.dll = value;
            cli = true;
            ++i;
        } else if (argument == L"--quiet") {
            options.quiet = true;
        } else if (argument == L"--no-elevate") {
            options.no_elevate = true;
        } else if (argument == L"--elevated") {
            // Set by the relaunched instance; nothing to do.
        } else if (argument == L"--help" || argument == L"-h" || argument == L"/?") {
            options.help = true;
            cli = true;
        } else {
            // Unknown switches are an error, but a stray value is ignored so a
            // dropped file does not turn into a dead end.
            if (argument.rfind(L"--", 0) == 0) {
                con_write(L"неизвестный параметр: " + argument + L"\n");
                exit_code = 2;
                LocalFree(argv);
                return false;
            }
        }
    }

    LocalFree(argv);
    options.gui = !cli;
    return true;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    g_instance = instance;

    Options options;
    int exit_code = 0;
    if (!parse_options(options, exit_code)) {
        if (exit_code != 0 && !attach_console()) return exit_code;
        pause_if_own_console(false);
        return exit_code;
    }

    if (options.gui) {
        if (!options.no_elevate && !is_elevated()) {
            switch (relaunch_elevated()) {
                case Elevation::Launched:
                    return 0;
                case Elevation::Cancelled:
                    return 0;
                case Elevation::Failed:
                    break;   // run anyway; same-integrity targets stay reachable
            }
        }
        return run_gui();
    }

    return run_cli(options);
}
