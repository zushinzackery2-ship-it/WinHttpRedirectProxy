#pragma once

#include <Windows.h>

namespace WinHttpRedirectController
{
    struct ControllerWindowState;

    bool CreateMainControls(ControllerWindowState& state);
    void LayoutControls(ControllerWindowState& state);
    void UpdateLoadButtonState(ControllerWindowState& state);
}
