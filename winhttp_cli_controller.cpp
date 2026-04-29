#include "pch.h"
#include "winhttp_ipc.hpp"

namespace
{
    void PrintUsage()
    {
        std::fwprintf(stderr, L"Usage:\n");
        std::fwprintf(stderr, L"  winhttp_cli_controller.exe load <pid> <dll-path>\n");
    }

    bool ParsePid(const wchar_t* text, DWORD& pid)
    {
        if (text == nullptr || text[0] == L'\0')
        {
            return false;
        }

        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long value = wcstoul(text, &end, 0);
        if (errno != 0 || end == text || (end != nullptr && *end != L'\0') || value == 0 || value > MAXDWORD)
        {
            return false;
        }

        pid = static_cast<DWORD>(value);
        return true;
    }

    bool IsLoadReply(const std::vector<std::uint8_t>& buffer, WinHttpRedirectProxyIpc::LoadDllReplyPayload& reply, DWORD& replyPid)
    {
        if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader) + sizeof(reply))
        {
            return false;
        }

        const auto* header = reinterpret_cast<const WinHttpRedirectProxyIpc::MessageHeader*>(buffer.data());
        if (header->kind != static_cast<std::uint32_t>(WinHttpRedirectProxyIpc::MessageKind::LoadDllReply))
        {
            return false;
        }

        const auto* payload = reinterpret_cast<const WinHttpRedirectProxyIpc::LoadDllReplyPayload*>(
            buffer.data() + sizeof(WinHttpRedirectProxyIpc::MessageHeader));
        reply = *payload;
        replyPid = header->pid;
        return true;
    }

    void PrintAgentMessage(const std::vector<std::uint8_t>& buffer)
    {
        if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader))
        {
            return;
        }

        const auto* header = reinterpret_cast<const WinHttpRedirectProxyIpc::MessageHeader*>(buffer.data());
        const auto kind = static_cast<WinHttpRedirectProxyIpc::MessageKind>(header->kind);
        if (kind == WinHttpRedirectProxyIpc::MessageKind::AgentLog
            && buffer.size() >= sizeof(WinHttpRedirectProxyIpc::MessageHeader) + sizeof(WinHttpRedirectProxyIpc::AgentLogPayload))
        {
            const auto* payload = reinterpret_cast<const WinHttpRedirectProxyIpc::AgentLogPayload*>(
                buffer.data() + sizeof(WinHttpRedirectProxyIpc::MessageHeader));
            std::printf("[agent-log] pid=%lu %s\n", static_cast<unsigned long>(header->pid), payload->text);
        }
    }

    int RunLoad(DWORD targetPid, const std::wstring& dllPath)
    {
        if (dllPath.empty() || GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            std::fwprintf(stderr, L"DLL not found: %ls\n", dllPath.c_str());
            return 2;
        }

        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        std::vector<std::uint8_t> buffer;
        for (;;)
        {
            pipeHandle = WinHttpRedirectProxyIpc::CreatePipeServerInstance();
            if (pipeHandle == INVALID_HANDLE_VALUE)
            {
                std::fwprintf(stderr, L"CreatePipeServerInstance failed: %lu\n", GetLastError());
                return 3;
            }

            std::printf("listening targetPid=%lu pipe=%ls\n", static_cast<unsigned long>(targetPid), WINHTTP_REDIRECT_PROXY_PIPE_NAME);
            if (!WinHttpRedirectProxyIpc::WaitForPipeClient(pipeHandle))
            {
                std::fwprintf(stderr, L"WaitForPipeClient failed: %lu\n", GetLastError());
                WinHttpRedirectProxyIpc::ClosePipe(pipeHandle);
                return 4;
            }

            buffer.clear();
            if (!WinHttpRedirectProxyIpc::ReadMessage(pipeHandle, buffer)
                || buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader))
            {
                std::fwprintf(stderr, L"failed to read agent hello\n");
                WinHttpRedirectProxyIpc::ClosePipe(pipeHandle);
                return 5;
            }

            const auto* header = reinterpret_cast<const WinHttpRedirectProxyIpc::MessageHeader*>(buffer.data());
            if (header->pid != targetPid)
            {
                std::printf("skipping pid=%lu expected=%lu\n",
                    static_cast<unsigned long>(header->pid),
                    static_cast<unsigned long>(targetPid));
                WinHttpRedirectProxyIpc::ClosePipe(pipeHandle);
                continue;
            }

            break;
        }

        std::printf("connected pid=%lu\n", static_cast<unsigned long>(targetPid));
        if (!WinHttpRedirectProxyIpc::SendLoadDllRequest(pipeHandle, GetCurrentProcessId(), dllPath))
        {
            std::fwprintf(stderr, L"SendLoadDllRequest failed: %lu\n", GetLastError());
            WinHttpRedirectProxyIpc::ClosePipe(pipeHandle);
            return 7;
        }

        std::wprintf(L"load-request path=%ls\n", dllPath.c_str());
        for (;;)
        {
            buffer.clear();
            if (!WinHttpRedirectProxyIpc::ReadMessage(pipeHandle, buffer))
            {
                std::fwprintf(stderr, L"failed while waiting for load reply\n");
                WinHttpRedirectProxyIpc::ClosePipe(pipeHandle);
                return 8;
            }

            WinHttpRedirectProxyIpc::LoadDllReplyPayload reply = {};
            DWORD replyPid = 0;
            if (IsLoadReply(buffer, reply, replyPid))
            {
                std::wprintf(L"load-reply pid=%lu status=%u win32=%u text=%ls path=%ls\n",
                    static_cast<unsigned long>(replyPid),
                    reply.status,
                    reply.win32Error,
                    reply.text,
                    reply.dllPath);
                WinHttpRedirectProxyIpc::ClosePipe(pipeHandle);
                return reply.status == 0 ? 0 : 9;
            }

            PrintAgentMessage(buffer);
        }
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 4 || _wcsicmp(argv[1], L"load") != 0)
    {
        PrintUsage();
        return 1;
    }

    DWORD targetPid = 0;
    if (!ParsePid(argv[2], targetPid))
    {
        PrintUsage();
        return 1;
    }

    return RunLoad(targetPid, argv[3]);
}