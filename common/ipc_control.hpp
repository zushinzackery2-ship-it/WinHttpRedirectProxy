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

#include "ipc_pipe_transport.hpp"

namespace WinHttpRedirectProxyIpc
{
    inline constexpr std::uint32_t kMagic = 0x58525057;
    inline constexpr std::uint32_t kProtocolVersion = 1;
    inline constexpr std::uint32_t kFeatureBootstrapAfterLoad = 0x1;

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
#ifdef WINHTTP_REDIRECT_PROXY_ENABLE_PROTOCOL_VERSION
        std::uint32_t protocolVersion;
        std::uint32_t featureFlags;
#endif
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

        return WinHttpRedirectIpc::WriteMessage(pipeHandle, header, payload, payloadSize);
    }

    inline bool ReadMessage(HANDLE pipeHandle, std::vector<std::uint8_t>& buffer)
    {
        return WinHttpRedirectIpc::ReadMessage<MessageHeader>(
            pipeHandle,
            buffer,
            kMagic,
            sizeof(MessageHeader));
    }

    inline HANDLE ConnectToPipe(DWORD timeoutMs)
    {
        return WinHttpRedirectIpc::ConnectToNamedPipe(WINHTTP_REDIRECT_PROXY_PIPE_NAME, timeoutMs);
    }

    inline HANDLE CreatePipeServerInstance()
    {
        return WinHttpRedirectIpc::CreateNamedPipeServer(WINHTTP_REDIRECT_PROXY_PIPE_NAME, 4096, 4096);
    }

    inline bool SendAgentHello(HANDLE pipeHandle, std::uint32_t pid, const std::wstring& processPath)
    {
        AgentHelloPayload payload = {};
        CopyWideText(payload.processPath, processPath);
#ifdef WINHTTP_REDIRECT_PROXY_ENABLE_PROTOCOL_VERSION
        payload.protocolVersion = kProtocolVersion;
        payload.featureFlags = kFeatureBootstrapAfterLoad;
#endif
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

    inline bool WaitForPipeClient(HANDLE pipeHandle)
    {
        return WinHttpRedirectIpc::WaitForPipeClient(pipeHandle);
    }

    inline void ClosePipe(HANDLE& pipeHandle)
    {
        WinHttpRedirectIpc::ClosePipe(pipeHandle);
    }
}
