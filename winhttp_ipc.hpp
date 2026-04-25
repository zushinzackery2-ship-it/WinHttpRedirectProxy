#pragma once

#ifndef WINHTTP_REDIRECT_PROXY_PIPE_NAME
#define WINHTTP_REDIRECT_PROXY_PIPE_NAME L"\\\\.\\pipe\\WinHttpRedirectProxyControl"
#endif

#ifndef WINHTTP_REDIRECT_PROXY_MAX_PATH_CHARS
#define WINHTTP_REDIRECT_PROXY_MAX_PATH_CHARS 1024
#endif

#ifndef WINHTTP_REDIRECT_PROXY_MAX_TEXT_CHARS
#define WINHTTP_REDIRECT_PROXY_MAX_TEXT_CHARS 256
#endif

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace WinHttpRedirectProxyIpc
{
    inline constexpr std::uint32_t kMagic = 0x58525057;

    enum class MessageKind : std::uint32_t
    {
        Invalid = 0,
        AgentHello = 1,
        AgentLog = 2,
        LoadDllRequest = 3,
        LoadDllReply = 4,
    };

    struct MessageHeader
    {
        std::uint32_t magic;
        std::uint32_t kind;
        std::uint32_t size;
        std::uint32_t pid;
    };

    struct AgentHelloPayload
    {
        wchar_t processPath[WINHTTP_REDIRECT_PROXY_MAX_PATH_CHARS];
    };

    struct AgentLogPayload
    {
        char text[WINHTTP_REDIRECT_PROXY_MAX_TEXT_CHARS];
    };

    struct LoadDllRequestPayload
    {
        wchar_t dllPath[WINHTTP_REDIRECT_PROXY_MAX_PATH_CHARS];
    };

    struct LoadDllReplyPayload
    {
        std::uint32_t status;
        std::uint32_t win32Error;
        wchar_t dllPath[WINHTTP_REDIRECT_PROXY_MAX_PATH_CHARS];
        wchar_t text[WINHTTP_REDIRECT_PROXY_MAX_TEXT_CHARS];
    };

    template <std::size_t Count>
    inline void CopyWideText(wchar_t (&destination)[Count], const std::wstring& text)
    {
        wcsncpy_s(destination, Count, text.c_str(), _TRUNCATE);
    }

    template <std::size_t Count>
    inline void CopyAnsiText(char (&destination)[Count], const char* text)
    {
        strncpy_s(destination, Count, text != nullptr ? text : "", _TRUNCATE);
    }

    inline bool WriteAll(HANDLE pipeHandle, const void* buffer, DWORD size)
    {
        const auto* bytes = static_cast<const std::uint8_t*>(buffer);
        DWORD totalWritten = 0;
        while (totalWritten < size)
        {
            DWORD bytesWritten = 0;
            if (!WriteFile(
                    pipeHandle,
                    bytes + totalWritten,
                    size - totalWritten,
                    &bytesWritten,
                    nullptr)
                || bytesWritten == 0)
            {
                return false;
            }

            totalWritten += bytesWritten;
        }

        return true;
    }

    inline bool ReadAll(HANDLE pipeHandle, void* buffer, DWORD size)
    {
        auto* bytes = static_cast<std::uint8_t*>(buffer);
        DWORD totalRead = 0;
        while (totalRead < size)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(
                    pipeHandle,
                    bytes + totalRead,
                    size - totalRead,
                    &bytesRead,
                    nullptr)
                || bytesRead == 0)
            {
                return false;
            }

            totalRead += bytesRead;
        }

        return true;
    }

    inline bool WriteMessage(
        HANDLE pipeHandle,
        MessageKind kind,
        std::uint32_t pid,
        const void* payload,
        std::uint32_t payloadSize)
    {
        MessageHeader header = {};
        header.magic = kMagic;
        header.kind = static_cast<std::uint32_t>(kind);
        header.size = static_cast<std::uint32_t>(sizeof(header) + payloadSize);
        header.pid = pid;

        if (!WriteAll(pipeHandle, &header, static_cast<DWORD>(sizeof(header))))
        {
            return false;
        }

        if (payloadSize == 0)
        {
            return true;
        }

        return WriteAll(pipeHandle, payload, payloadSize);
    }

    inline bool ReadMessage(HANDLE pipeHandle, std::vector<std::uint8_t>& buffer)
    {
        MessageHeader header = {};
        if (!ReadAll(pipeHandle, &header, static_cast<DWORD>(sizeof(header))))
        {
            return false;
        }

        if (header.magic != kMagic || header.size < sizeof(header))
        {
            return false;
        }

        buffer.resize(header.size);
        std::memcpy(buffer.data(), &header, sizeof(header));

        const auto payloadSize = static_cast<DWORD>(header.size - sizeof(header));
        if (payloadSize == 0)
        {
            return true;
        }

        return ReadAll(pipeHandle, buffer.data() + sizeof(header), payloadSize);
    }

    inline HANDLE ConnectToPipe(DWORD timeoutMs)
    {
        if (!WaitNamedPipeW(WINHTTP_REDIRECT_PROXY_PIPE_NAME, timeoutMs))
        {
            return INVALID_HANDLE_VALUE;
        }

        return CreateFileW(
            WINHTTP_REDIRECT_PROXY_PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    }

    inline HANDLE CreatePipeServerInstance()
    {
        SECURITY_DESCRIPTOR securityDescriptor = {};
        if (!InitializeSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION))
        {
            return INVALID_HANDLE_VALUE;
        }

        if (!SetSecurityDescriptorDacl(&securityDescriptor, TRUE, nullptr, FALSE))
        {
            return INVALID_HANDLE_VALUE;
        }

        SECURITY_ATTRIBUTES securityAttributes = {};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.lpSecurityDescriptor = &securityDescriptor;
        securityAttributes.bInheritHandle = FALSE;

        return CreateNamedPipeW(
            WINHTTP_REDIRECT_PROXY_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            &securityAttributes);
    }

    inline bool WaitForPipeClient(HANDLE pipeHandle)
    {
        return ConnectNamedPipe(pipeHandle, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
    }

    inline void ClosePipe(HANDLE& pipeHandle)
    {
        if (pipeHandle == nullptr || pipeHandle == INVALID_HANDLE_VALUE)
        {
            pipeHandle = INVALID_HANDLE_VALUE;
            return;
        }

        FlushFileBuffers(pipeHandle);
        DisconnectNamedPipe(pipeHandle);
        CloseHandle(pipeHandle);
        pipeHandle = INVALID_HANDLE_VALUE;
    }

    inline bool SendAgentHello(HANDLE pipeHandle, std::uint32_t pid, const std::wstring& processPath)
    {
        AgentHelloPayload payload = {};
        CopyWideText(payload.processPath, processPath);
        return WriteMessage(
            pipeHandle,
            MessageKind::AgentHello,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }

    inline bool SendAgentLog(HANDLE pipeHandle, std::uint32_t pid, const char* text)
    {
        AgentLogPayload payload = {};
        CopyAnsiText(payload.text, text);
        return WriteMessage(
            pipeHandle,
            MessageKind::AgentLog,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }

    inline bool SendLoadDllRequest(HANDLE pipeHandle, std::uint32_t pid, const std::wstring& dllPath)
    {
        LoadDllRequestPayload payload = {};
        CopyWideText(payload.dllPath, dllPath);
        return WriteMessage(
            pipeHandle,
            MessageKind::LoadDllRequest,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }

    inline bool SendLoadDllReply(
        HANDLE pipeHandle,
        std::uint32_t pid,
        std::uint32_t status,
        std::uint32_t win32Error,
        const std::wstring& dllPath,
        const std::wstring& text)
    {
        LoadDllReplyPayload payload = {};
        payload.status = status;
        payload.win32Error = win32Error;
        CopyWideText(payload.dllPath, dllPath);
        CopyWideText(payload.text, text);
        return WriteMessage(
            pipeHandle,
            MessageKind::LoadDllReply,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }
}
