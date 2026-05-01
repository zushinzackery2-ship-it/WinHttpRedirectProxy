#include "pch.h"
#include "controller_window.hpp"
#include "controller_window_layout.hpp"
#include "controller_session.hpp"

namespace WinHttpRedirectController
{
    namespace
    {
        constexpr UINT_PTR kRefreshTimerId = 1;
        constexpr UINT kRefreshIntervalMs = 200;

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

        WinHttpRedirectProxyIpc::ConnectToPipe(100);

        if (state.acceptThread != nullptr)
        {
            WaitForSingleObject(state.acceptThread, 3000);
            CloseHandle(state.acceptThread);
            state.acceptThread = nullptr;
        }

        {
            std::vector<HANDLE> threads;
            {
                std::lock_guard<std::mutex> lock(state.controllerState->sessionThreadsMutex);
                threads = std::move(state.controllerState->sessionThreads);
            }
            for (auto handle : threads)
            {
                if (handle != nullptr)
                {
                    WaitForSingleObject(handle, 3000);
                    CloseHandle(handle);
                }
            }
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
