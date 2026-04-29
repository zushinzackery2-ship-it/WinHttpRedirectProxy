#include "pch.h"
#include "winhttp_controller_window.hpp"

namespace WinHttpRedirectController
{
    namespace
    {
        constexpr UINT_PTR kRefreshTimerId = 1;
        constexpr UINT kRefreshIntervalMs = 200;

        constexpr int kSessionListViewId = 1001;
        constexpr int kDllPathEditId = 1002;
        constexpr int kBrowseButtonId = 1003;
        constexpr int kLoadButtonId = 1004;

        ControllerWindowState* GetWindowState(HWND window)
        {
            return reinterpret_cast<ControllerWindowState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        }

        std::wstring GetWindowTextString(HWND window)
        {
            const auto length = GetWindowTextLengthW(window);
            std::wstring text(static_cast<std::size_t>(length + 1), L'\0');
            if (length > 0)
            {
                GetWindowTextW(window, text.data(), length + 1);
            }
            text.resize(static_cast<std::size_t>(length));
            return text;
        }

        HFONT CreateUiFont()
        {
            NONCLIENTMETRICSW metrics = {};
            metrics.cbSize = sizeof(metrics);
            if (!SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0))
            {
                return nullptr;
            }

            return CreateFontIndirectW(&metrics.lfMessageFont);
        }

        HFONT CreateTitleFont()
        {
            LOGFONTW font = {};
            font.lfHeight = -24;
            font.lfWeight = FW_SEMIBOLD;
            wcscpy_s(font.lfFaceName, L"Segoe UI");
            return CreateFontIndirectW(&font);
        }

        void ApplyControlFont(HWND window, HFONT font)
        {
            const auto effectiveFont = font != nullptr
                ? font
                : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            SendMessageW(window, WM_SETFONT, reinterpret_cast<WPARAM>(effectiveFont), TRUE);
        }

        void UpdateWindowCaption(ControllerWindowState& state)
        {
            SetWindowTextW(state.mainWindow, kControllerWindowTitle);
        }

        void UpdateStatusText(ControllerWindowState& state)
        {
            auto status = std::wstring(L"Pipe: ") + WINHTTP_REDIRECT_PROXY_PIPE_NAME;
            status += L" | Control: " + std::to_wstring(CountControlRows(state.visibleRows));
            status += L" | Memory IPC: " + std::to_wstring(CountMemoryIpcRows(state.visibleRows));

            SetWindowTextW(state.statusLabel, status.c_str());
        }

        void UpdateLoadButtonState(ControllerWindowState& state)
        {
            const auto selection = ListView_GetNextItem(state.sessionListView, -1, LVNI_SELECTED);
            const auto pathLength = GetWindowTextLengthW(state.dllPathEdit);
            const bool enabled = selection != -1
                && static_cast<std::size_t>(selection) < state.visibleRows.size()
                && state.visibleRows[static_cast<std::size_t>(selection)].controlSession != nullptr
                && pathLength > 0;
            EnableWindow(state.loadButton, enabled ? TRUE : FALSE);
            UpdateStatusText(state);
        }

        void LayoutControls(ControllerWindowState& state)
        {
            RECT clientRect = {};
            GetClientRect(state.mainWindow, &clientRect);

            constexpr int margin = 12;
            constexpr int titleHeight = 34;
            constexpr int subtitleHeight = 20;
            constexpr int labelHeight = 20;
            constexpr int rowHeight = 32;
            constexpr int sessionHeight = 220;
            constexpr int statusHeight = 22;
            constexpr int buttonWidth = 132;

            const int width = clientRect.right - clientRect.left;
            const int height = clientRect.bottom - clientRect.top;
            const int contentWidth = width - margin * 2;
            const int editWidth = contentWidth - buttonWidth * 2 - margin * 2;
            const int contentTop = margin + titleHeight + subtitleHeight + margin;
            const int logTop = contentTop + labelHeight + sessionHeight + margin + labelHeight + rowHeight + margin + labelHeight;
            const int logHeight = std::max(140, height - logTop - margin - statusHeight - margin);

            MoveWindow(state.titleLabel, margin, margin, contentWidth, titleHeight, TRUE);
            MoveWindow(state.subtitleLabel, margin, margin + titleHeight - 4, contentWidth, subtitleHeight, TRUE);
            MoveWindow(state.sessionLabel, margin, contentTop, contentWidth, labelHeight, TRUE);
            MoveWindow(state.sessionListView, margin, contentTop + labelHeight, contentWidth, sessionHeight, TRUE);
            MoveWindow(state.dllLabel, margin, contentTop + labelHeight + sessionHeight + margin, contentWidth, labelHeight, TRUE);
            MoveWindow(state.dllPathEdit, margin, contentTop + labelHeight + sessionHeight + margin + labelHeight, editWidth, rowHeight, TRUE);
            MoveWindow(
                state.browseButton,
                margin + editWidth + margin,
                contentTop + labelHeight + sessionHeight + margin + labelHeight,
                buttonWidth,
                rowHeight,
                TRUE);
            MoveWindow(
                state.loadButton,
                margin + editWidth + margin + buttonWidth + margin,
                contentTop + labelHeight + sessionHeight + margin + labelHeight,
                buttonWidth,
                rowHeight,
                TRUE);
            MoveWindow(state.logLabel, margin, logTop - labelHeight, contentWidth, labelHeight, TRUE);
            MoveWindow(state.logEdit, margin, logTop, contentWidth, logHeight, TRUE);
            MoveWindow(state.statusLabel, margin, height - margin - statusHeight, contentWidth, statusHeight, TRUE);

            ListView_SetColumnWidth(state.sessionListView, 0, 110);
            ListView_SetColumnWidth(state.sessionListView, 2, 190);
            ListView_SetColumnWidth(state.sessionListView, 1, std::max(220, contentWidth - 320));
        }

        bool CreateMainControls(ControllerWindowState& state)
        {
            state.titleLabel = CreateWindowExW(0, L"STATIC", kControllerWindowTitle, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, state.mainWindow, nullptr, nullptr, nullptr);
            state.subtitleLabel = CreateWindowExW(0, L"STATIC", kControllerWindowSubtitle, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, state.mainWindow, nullptr, nullptr, nullptr);
            state.sessionLabel = CreateWindowExW(0, L"STATIC", L"Connected Processes", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, state.mainWindow, nullptr, nullptr, nullptr);
            state.sessionListView = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                WC_LISTVIEWW,
                nullptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                0,
                0,
                0,
                0,
                state.mainWindow,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSessionListViewId)),
                nullptr,
                nullptr);
            state.dllLabel = CreateWindowExW(0, L"STATIC", L"DLL Path", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, state.mainWindow, nullptr, nullptr, nullptr);
            state.dllPathEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                nullptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                0,
                0,
                0,
                0,
                state.mainWindow,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDllPathEditId)),
                nullptr,
                nullptr);
            state.browseButton = CreateWindowExW(0, L"BUTTON", L"Browse DLL...", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, state.mainWindow, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kBrowseButtonId)), nullptr, nullptr);
            state.loadButton = CreateWindowExW(0, L"BUTTON", L"Load To Selected", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 0, 0, state.mainWindow, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kLoadButtonId)), nullptr, nullptr);
            state.logLabel = CreateWindowExW(0, L"STATIC", L"Activity", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, state.mainWindow, nullptr, nullptr, nullptr);
            state.logEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                nullptr,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                0,
                0,
                0,
                0,
                state.mainWindow,
                nullptr,
                nullptr,
                nullptr);
            state.statusLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, state.mainWindow, nullptr, nullptr, nullptr);
            if (state.titleLabel == nullptr
                || state.subtitleLabel == nullptr
                || state.sessionLabel == nullptr
                || state.sessionListView == nullptr
                || state.dllLabel == nullptr
                || state.dllPathEdit == nullptr
                || state.browseButton == nullptr
                || state.loadButton == nullptr
                || state.logLabel == nullptr
                || state.logEdit == nullptr
                || state.statusLabel == nullptr)
            {
                return false;
            }

            state.uiFont = CreateUiFont();
            state.titleFont = CreateTitleFont();
            ApplyControlFont(state.titleLabel, state.titleFont);
            ApplyControlFont(state.subtitleLabel, state.uiFont);
            ApplyControlFont(state.sessionLabel, state.uiFont);
            ApplyControlFont(state.sessionListView, state.uiFont);
            ApplyControlFont(state.dllLabel, state.uiFont);
            ApplyControlFont(state.dllPathEdit, state.uiFont);
            ApplyControlFont(state.browseButton, state.uiFont);
            ApplyControlFont(state.loadButton, state.uiFont);
            ApplyControlFont(state.logLabel, state.uiFont);
            ApplyControlFont(state.logEdit, state.uiFont);
            ApplyControlFont(state.statusLabel, state.uiFont);

            SetWindowTheme(state.sessionListView, L"Explorer", nullptr);
            ListView_SetExtendedListViewStyle(
                state.sessionListView,
                LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);

            LVCOLUMNW column = {};
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            column.cx = 110;
            column.pszText = const_cast<wchar_t*>(L"PID");
            ListView_InsertColumn(state.sessionListView, 0, &column);
            column.cx = 720;
            column.iSubItem = 1;
            column.pszText = const_cast<wchar_t*>(L"Process");
            ListView_InsertColumn(state.sessionListView, 1, &column);
            column.cx = 190;
            column.iSubItem = 2;
            column.pszText = const_cast<wchar_t*>(L"Channel");
            ListView_InsertColumn(state.sessionListView, 2, &column);

            UpdateWindowCaption(state);
            LayoutControls(state);
            UpdateLoadButtonState(state);
            return true;
        }

        void RefreshSessionListView(ControllerWindowState& state)
        {
            const auto revision = state.controllerState->sessionsRevision.load();
            auto rows = BuildControllerDisplayRows(*state.controllerState);
            const auto signature = BuildControllerDisplaySignature(revision, rows);
            if (signature == state.renderedEndpointSignature)
            {
                return;
            }

            DWORD selectedPid = 0;
            const auto selection = ListView_GetNextItem(state.sessionListView, -1, LVNI_SELECTED);
            if (selection != -1 && static_cast<std::size_t>(selection) < state.visibleRows.size())
            {
                selectedPid = state.visibleRows[static_cast<std::size_t>(selection)].pid;
            }

            state.visibleRows = std::move(rows);
            ListView_DeleteAllItems(state.sessionListView);

            int selectedIndex = -1;
            for (std::size_t index = 0; index < state.visibleRows.size(); ++index)
            {
                const auto& row = state.visibleRows[index];

                LVITEMW item = {};
                item.mask = LVIF_TEXT;
                item.iItem = static_cast<int>(index);
                auto pidText = std::to_wstring(row.pid);
                item.pszText = pidText.data();
                ListView_InsertItem(state.sessionListView, &item);
                ListView_SetItemText(
                    state.sessionListView,
                    static_cast<int>(index),
                    1,
                    const_cast<wchar_t*>(row.processPath.c_str()));
                ListView_SetItemText(
                    state.sessionListView,
                    static_cast<int>(index),
                    2,
                    const_cast<wchar_t*>(row.channelText.c_str()));
                if (selectedPid != 0 && row.pid == selectedPid)
                {
                    selectedIndex = static_cast<int>(index);
                }
            }

            if (selectedIndex == -1 && !state.visibleRows.empty())
            {
                selectedIndex = 0;
            }
            if (selectedIndex != -1)
            {
                ListView_SetItemState(
                    state.sessionListView,
                    selectedIndex,
                    LVIS_SELECTED | LVIS_FOCUSED,
                    LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(state.sessionListView, selectedIndex, FALSE);
            }

            state.renderedEndpointSignature = signature;
            UpdateLoadButtonState(state);
        }

        void RefreshLogEdit(ControllerWindowState& state)
        {
            const auto revision = state.controllerState->logRevision.load();
            if (revision == state.renderedLogRevision)
            {
                return;
            }

            const auto text = SnapshotLogText(*state.controllerState);
            SetWindowTextW(state.logEdit, text.c_str());
            SendMessageW(state.logEdit, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
            SendMessageW(state.logEdit, EM_SCROLLCARET, 0, 0);
            state.renderedLogRevision = revision;
        }

        std::shared_ptr<AgentSession> GetSelectedSession(ControllerWindowState& state)
        {
            const auto selection = ListView_GetNextItem(state.sessionListView, -1, LVNI_SELECTED);
            if (selection == -1 || static_cast<std::size_t>(selection) >= state.visibleRows.size())
            {
                return nullptr;
            }

            return state.visibleRows[static_cast<std::size_t>(selection)].controlSession;
        }

        void BeginAsyncLoadRequest(ControllerWindowState& state)
        {
            const auto session = GetSelectedSession(state);
            if (session == nullptr)
            {
                MessageBoxW(state.mainWindow, L"请选择一个已连接进程。", L"WinHttpRedirectProxy Controller", MB_ICONWARNING);
                return;
            }

            const auto dllPath = GetWindowTextString(state.dllPathEdit);
            if (dllPath.empty())
            {
                MessageBoxW(state.mainWindow, L"请先选择 DLL。", L"WinHttpRedirectProxy Controller", MB_ICONWARNING);
                return;
            }

            if (!QueueLoadDllRequest(session, dllPath))
            {
                MessageBoxW(state.mainWindow, L"无法加入加载队列。", L"WinHttpRedirectProxy Controller", MB_ICONERROR);
                return;
            }

            DWORD pid = 0;
            std::wstring processPath;
            GetSessionIdentity(session, pid, processPath);
            AppendLogLine(
                *state.controllerState,
                L"[load-queued] pid=" + std::to_wstring(pid) + L" path=" + dllPath);
            RefreshControllerWindow(state);
        }
    }

    void RefreshControllerWindow(ControllerWindowState& state)
    {
        RefreshSessionListView(state);
        RefreshLogEdit(state);
        UpdateStatusText(state);
    }

    void CleanupControllerWindowState(ControllerWindowState& state)
    {
        state.controllerState->stopRequested = true;
        if (state.controllerState->stopEvent != nullptr)
        {
            SetEvent(state.controllerState->stopEvent);
        }
        if (state.acceptThread != nullptr)
        {
            CloseHandle(state.acceptThread);
            state.acceptThread = nullptr;
        }
        if (state.uiFont != nullptr)
        {
            DeleteObject(state.uiFont);
            state.uiFont = nullptr;
        }
        if (state.titleFont != nullptr)
        {
            DeleteObject(state.titleFont);
            state.titleFont = nullptr;
        }
    }

    LRESULT CALLBACK ControllerWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (message == WM_NCCREATE)
        {
            const auto* createStruct = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(createStruct->lpCreateParams));
            return TRUE;
        }

        auto* state = GetWindowState(window);
        if (state == nullptr)
        {
            return DefWindowProcW(window, message, wParam, lParam);
        }

        switch (message)
        {
        case WM_CREATE:
            state->mainWindow = window;
            if (!CreateMainControls(*state))
            {
                return -1;
            }
            SetTimer(window, kRefreshTimerId, kRefreshIntervalMs, nullptr);
            return 0;

        case WM_SIZE:
            LayoutControls(*state);
            return 0;

        case WM_GETMINMAXINFO:
            reinterpret_cast<MINMAXINFO*>(lParam)->ptMinTrackSize = POINT { 860, 620 };
            return 0;

        case WM_TIMER:
            RefreshControllerWindow(*state);
            return 0;

        case WM_NOTIFY:
            if (reinterpret_cast<const NMHDR*>(lParam)->idFrom == kSessionListViewId)
            {
                UpdateLoadButtonState(*state);
                return 0;
            }
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == kBrowseButtonId && HIWORD(wParam) == BN_CLICKED)
            {
                std::wstring dllPath;
                if (TrySelectDllPath(state->mainWindow, *state->controllerState, dllPath))
                {
                    SetWindowTextW(state->dllPathEdit, dllPath.c_str());
                    UpdateLoadButtonState(*state);
                }
                return 0;
            }
            if (LOWORD(wParam) == kLoadButtonId && HIWORD(wParam) == BN_CLICKED)
            {
                BeginAsyncLoadRequest(*state);
                return 0;
            }
            if (LOWORD(wParam) == kDllPathEditId && HIWORD(wParam) == EN_CHANGE)
            {
                UpdateLoadButtonState(*state);
                return 0;
            }
            break;

        case WM_CLOSE:
            DestroyWindow(window);
            return 0;

        case WM_DESTROY:
            KillTimer(window, kRefreshTimerId);
            state->controllerState->stopRequested = true;
            if (state->controllerState->stopEvent != nullptr)
            {
                SetEvent(state->controllerState->stopEvent);
            }
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(window, message, wParam, lParam);
    }
}
