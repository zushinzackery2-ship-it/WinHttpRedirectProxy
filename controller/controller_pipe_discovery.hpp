#pragma once

#include <Windows.h>

#include <string>
#include <vector>

namespace WinHttpRedirectController
{
    struct MemoryIpcEndpoint
    {
        DWORD pid = 0;
        std::wstring pipeName;
    };

    std::vector<MemoryIpcEndpoint> DiscoverMemoryIpcEndpoints();
}
