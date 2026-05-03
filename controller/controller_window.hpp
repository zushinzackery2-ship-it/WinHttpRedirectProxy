#pragma once

#include <Windows.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "controller_view_model.hpp"

namespace WinHttpRedirectController
{
    inline constexpr wchar_t kControllerWindowTitle[] = L"WinHttpRedirectProxy Controller";
    inline constexpr wchar_t kControllerWindowSubtitle[] = L"Named Pipe GUI Controller";

    inline constexpr int kSessionListViewId = 1001;
    inline constexpr int kDllPathEditId = 1002;
    inline constexpr int kBrowseButtonId = 1003;
    inline constexpr int kLoadButtonId = 1004;

    struct ControllerWindowState
    {
        std::shared_ptr<ControllerState> controllerState = std::make_shared<ControllerState>();
        HWND mainWindow = nullptr;
        HWND titleLabel = nullptr;
        HWND subtitleLabel = nullptr;
        HWND sessionLabel = nullptr;
        HWND sessionListView = nullptr;
        HWND dllLabel = nullptr;
        HWND dllPathEdit = nullptr;
        HWND browseButton = nullptr;
        HWND loadButton = nullptr;
        HWND logLabel = nullptr;
        HWND logEdit = nullptr;
        HWND statusLabel = nullptr;
        HFONT uiFont = nullptr;
        HFONT titleFont = nullptr;
        HANDLE acceptThread = nullptr;
        std::vector<ControllerDisplayRow> visibleRows;
        std::wstring renderedEndpointSignature;
        std::uint64_t renderedLogRevision = 0;
    };

    LRESULT CALLBACK ControllerWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam);
    void RefreshControllerWindow(ControllerWindowState& state);
    void CleanupControllerWindowState(ControllerWindowState& state);
}
