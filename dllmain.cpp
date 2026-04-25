#include "pch.h"
#include "winhttp_redirect_proxy.hpp"

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    return WinHttpRedirectProxy::HandleDllMain(instance, reason, reserved);
}
