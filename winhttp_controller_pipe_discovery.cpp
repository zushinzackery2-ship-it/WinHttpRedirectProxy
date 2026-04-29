#include "pch.h"
#include "winhttp_controller_pipe_discovery.hpp"

namespace WinHttpRedirectController
{
    namespace
    {
        constexpr wchar_t kMemoryPipePrefix[] = L"WinHttpRedirectProxyMemory-";

        bool TryParseMemoryPipeName(const std::wstring& pipeName, DWORD& pid)
        {
            pid = 0;
            if (pipeName.rfind(kMemoryPipePrefix, 0) != 0)
            {
                return false;
            }

            const wchar_t* numberText = pipeName.c_str() + std::size(kMemoryPipePrefix) - 1;
            if (*numberText == L'\0')
            {
                return false;
            }

            wchar_t* end = nullptr;
            errno = 0;
            const unsigned long value = wcstoul(numberText, &end, 10);
            if (errno != 0 || end == numberText || (end != nullptr && *end != L'\0') || value == 0 || value > MAXDWORD)
            {
                return false;
            }

            pid = static_cast<DWORD>(value);
            return true;
        }
    }

    std::vector<MemoryIpcEndpoint> DiscoverMemoryIpcEndpoints()
    {
        std::vector<MemoryIpcEndpoint> endpoints;

        WIN32_FIND_DATAW findData = {};
        HANDLE findHandle = FindFirstFileW(LR"(\\.\pipe\WinHttpRedirectProxyMemory-*)", &findData);
        if (findHandle == INVALID_HANDLE_VALUE)
        {
            return endpoints;
        }

        do
        {
            DWORD pid = 0;
            const std::wstring pipeName(findData.cFileName);
            if (TryParseMemoryPipeName(pipeName, pid))
            {
                endpoints.push_back(MemoryIpcEndpoint { pid, pipeName });
            }
        } while (FindNextFileW(findHandle, &findData));

        FindClose(findHandle);

        std::sort(
            endpoints.begin(),
            endpoints.end(),
            [](const MemoryIpcEndpoint& left, const MemoryIpcEndpoint& right)
            {
                return left.pid < right.pid;
            });
        endpoints.erase(
            std::unique(
                endpoints.begin(),
                endpoints.end(),
                [](const MemoryIpcEndpoint& left, const MemoryIpcEndpoint& right)
                {
                    return left.pid == right.pid;
                }),
            endpoints.end());

        return endpoints;
    }
}
