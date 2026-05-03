#include "pch.h"
#include "controller_window.hpp"
#include "controller_window_layout.hpp"

namespace WinHttpRedirectController
{
    namespace
    {
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

        SetWindowTextW(state.mainWindow, kControllerWindowTitle);
        LayoutControls(state);
        UpdateLoadButtonState(state);
        return true;
    }
}
