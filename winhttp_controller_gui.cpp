#include "pch.h"
#include "winhttp_controller_gui.hpp"
#include "winhttp_controller_window.hpp"

namespace WinHttpRedirectController
{
    int RunGui(HINSTANCE instance, int commandShow)
    {
        INITCOMMONCONTROLSEX initCommonControls = {};
        initCommonControls.dwSize = sizeof(initCommonControls);
        initCommonControls.dwICC = ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES;
        InitCommonControlsEx(&initCommonControls);

        ControllerWindowState state = {};

        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = &ControllerWindowProc;
        windowClass.hInstance = instance;
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = L"WinHttpRedirectProxyControllerWindow";
        if (RegisterClassExW(&windowClass) == 0)
        {
            return 1;
        }

        const auto window = CreateWindowExW(
            0,
            windowClass.lpszClassName,
            L"WinHttpRedirectProxy Controller",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1080,
            720,
            nullptr,
            nullptr,
            instance,
            &state);
        if (window == nullptr)
        {
            return 2;
        }

        auto* acceptContext = new AcceptThreadContext();
        acceptContext->state = state.controllerState;
        state.acceptThread = CreateThread(nullptr, 0, &AcceptThreadProc, acceptContext, 0, nullptr);
        if (state.acceptThread == nullptr)
        {
            delete acceptContext;
            DestroyWindow(window);
            return 3;
        }

        ShowWindow(window, commandShow);
        UpdateWindow(window);
        RefreshControllerWindow(state);

        MSG message = {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        CleanupControllerWindowState(state);
        return static_cast<int>(message.wParam);
    }
}
