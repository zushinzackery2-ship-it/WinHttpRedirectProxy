#include "pch.h"
#include "controller_gui.hpp"

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previousInstance, PWSTR commandLine, int commandShow)
{
    (void)previousInstance;
    (void)commandLine;
    return WinHttpRedirectController::RunGui(instance, commandShow);
}
