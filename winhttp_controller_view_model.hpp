#pragma once

#include <Windows.h>

#include <memory>
#include <string>
#include <vector>

#include "winhttp_controller_state.hpp"

namespace WinHttpRedirectController
{
    struct ControllerDisplayRow
    {
        DWORD pid = 0;
        std::wstring processPath;
        std::wstring channelText;
        std::shared_ptr<AgentSession> controlSession;
        bool hasMemoryIpc = false;
    };

    std::vector<ControllerDisplayRow> BuildControllerDisplayRows(ControllerState& state);
    std::wstring BuildControllerDisplaySignature(
        std::uint64_t sessionsRevision,
        const std::vector<ControllerDisplayRow>& rows);
    std::size_t CountControlRows(const std::vector<ControllerDisplayRow>& rows);
    std::size_t CountMemoryIpcRows(const std::vector<ControllerDisplayRow>& rows);
}
