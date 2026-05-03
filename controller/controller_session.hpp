#pragma once

#include <Windows.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace WinHttpRedirectController
{
    struct ControllerState;
    struct AgentSession;

    void HandleSessionMessage(
        ControllerState& state,
        const std::shared_ptr<AgentSession>& session,
        const std::vector<std::uint8_t>& buffer);
    DWORD WINAPI SessionThreadProc(void* parameter);
    DWORD WINAPI AcceptThreadProc(void* parameter);
}
