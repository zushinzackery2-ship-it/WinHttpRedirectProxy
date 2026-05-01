#pragma once

#ifndef WINHTTP_REDIRECT_PROXY_MEMORY_PIPE_PREFIX
#define WINHTTP_REDIRECT_PROXY_MEMORY_PIPE_PREFIX L"\\\\.\\pipe\\WinHttpRedirectProxyMemory-"
#endif

#ifndef WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES
#define WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES 16384
#endif

#ifndef WINHTTP_REDIRECT_PROXY_SHARED_MEMORY_BYTES
#define WINHTTP_REDIRECT_PROXY_SHARED_MEMORY_BYTES 1048576
#endif

#ifndef WINHTTP_REDIRECT_PROXY_SHARED_NAME_CHARS
#define WINHTTP_REDIRECT_PROXY_SHARED_NAME_CHARS 128
#endif

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <string>
#include <vector>

#include "ipc_pipe_transport.hpp"

namespace WinHttpRedirectMemoryIpc
{
    inline constexpr std::uint32_t kMagic = 0x4D505257;
    inline constexpr std::uint32_t kSharedMemoryMagic = 0x53495052;
    inline constexpr std::uint32_t kSharedMemoryVersion = 1;

    enum class MessageKind : std::uint32_t
    {
        Invalid = 0,
        MemoryReadRequest = 1,
        MemoryReadReply = 2,
        MemoryWriteRequest = 3,
        MemoryWriteReply = 4,
        SharedMemoryConnectRequest = 5,
        SharedMemoryConnectReply = 6,
    };

    enum class AccessKind : std::uint32_t
    {
        Invalid = 0,
        Read = 1,
        Write = 2,
    };

    enum class OperationStatus : std::uint32_t
    {
        Success = 0,
        InvalidParameter = 1,
        SizeTooLarge = 2,
        AddressOverflow = 3,
        QueryFailed = 4,
        ProtectionDenied = 5,
        ExceptionCaught = 6,
        BadMessage = 7,
        Unsupported = 8,
    };

    enum class SharedMemoryCommand : std::uint32_t
    {
        None = 0,
        Read = 1,
        Write = 2,
        Close = 3,
    };

    struct MessageHeader
    {
        std::uint32_t magic;
        std::uint32_t kind;
        std::uint32_t size;
        std::uint32_t pid;
    };

    struct MemoryReadRequestPayload
    {
        std::uint64_t requestId;
        std::uint64_t address;
        std::uint32_t size;
        std::uint32_t reserved;
    };

    struct MemoryWriteRequestPayload
    {
        std::uint64_t requestId;
        std::uint64_t address;
        std::uint32_t size;
        std::uint32_t reserved;
        std::uint8_t data[WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES];
    };

    struct MemoryReplyPayload
    {
        std::uint64_t requestId;
        std::uint64_t address;
        std::uint64_t faultAddress;
        std::uint64_t instructionPointer;
        std::uint64_t regionBaseAddress;
        std::uint64_t regionSize;
        std::uint32_t requestedSize;
        std::uint32_t transferredSize;
        std::uint32_t status;
        std::uint32_t win32Error;
        std::uint32_t exceptionCode;
        std::uint32_t pageProtect;
        std::uint32_t pageState;
        std::uint32_t pageType;
        std::uint32_t accessKind;
        std::uint32_t cacheHits;
        std::uint32_t cacheMisses;
        std::uint32_t dataSize;
        std::uint8_t data[WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES];
    };

    struct SharedMemoryConnectRequestPayload
    {
        std::uint64_t requestId;
        std::uint64_t sessionId;
        std::uint32_t clientPid;
        std::uint32_t maxTransferSize;
        wchar_t mappingName[WINHTTP_REDIRECT_PROXY_SHARED_NAME_CHARS];
        wchar_t requestEventName[WINHTTP_REDIRECT_PROXY_SHARED_NAME_CHARS];
        wchar_t replyEventName[WINHTTP_REDIRECT_PROXY_SHARED_NAME_CHARS];
    };

    struct SharedMemoryConnectReplyPayload
    {
        std::uint64_t requestId;
        std::uint64_t sessionId;
        std::uint32_t status;
        std::uint32_t win32Error;
        std::uint32_t maxTransferSize;
        std::uint32_t reserved;
    };

    struct SharedMemoryBlock
    {
        std::uint32_t magic;
        std::uint32_t version;
        std::uint32_t maxTransferSize;
        std::uint32_t reserved;
        std::uint64_t requestId;
        std::uint32_t command;
        std::uint32_t requestedSize;
        std::uint64_t address;
        std::uint64_t faultAddress;
        std::uint64_t instructionPointer;
        std::uint64_t regionBaseAddress;
        std::uint64_t regionSize;
        std::uint32_t transferredSize;
        std::uint32_t status;
        std::uint32_t win32Error;
        std::uint32_t exceptionCode;
        std::uint32_t pageProtect;
        std::uint32_t pageState;
        std::uint32_t pageType;
        std::uint32_t accessKind;
        std::uint32_t cacheHits;
        std::uint32_t cacheMisses;
        std::uint32_t dataSize;
        std::uint32_t reserved2;
        std::uint8_t requestData[WINHTTP_REDIRECT_PROXY_SHARED_MEMORY_BYTES];
        std::uint8_t replyData[WINHTTP_REDIRECT_PROXY_SHARED_MEMORY_BYTES];
    };

    inline std::wstring BuildPipeName(std::uint32_t pid)
    {
        return std::wstring(WINHTTP_REDIRECT_PROXY_MEMORY_PIPE_PREFIX) + std::to_wstring(pid);
    }

    inline std::wstring BuildSharedObjectName(const wchar_t* suffix, std::uint32_t clientPid, std::uint64_t sessionId)
    {
        return std::wstring(L"Local\\WinHttpRedirectProxyMemory-")
            + suffix
            + L"-"
            + std::to_wstring(clientPid)
            + L"-"
            + std::to_wstring(sessionId);
    }

    inline void CopySharedName(wchar_t* destination, const std::wstring& source)
    {
        if (destination == nullptr)
        {
            return;
        }

        destination[0] = L'\0';
        wcsncpy_s(destination, WINHTTP_REDIRECT_PROXY_SHARED_NAME_CHARS, source.c_str(), _TRUNCATE);
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

    inline HANDLE ConnectToPipe(std::uint32_t pid, DWORD timeoutMs)
    {
        return WinHttpRedirectIpc::ConnectToNamedPipe(BuildPipeName(pid), timeoutMs);
    }

    inline HANDLE CreatePipeServerInstance(std::uint32_t pid)
    {
        return WinHttpRedirectIpc::CreateNamedPipeServer(BuildPipeName(pid));
    }

    inline bool SendMemoryReadRequest(
        HANDLE pipeHandle,
        std::uint32_t pid,
        std::uint64_t requestId,
        std::uint64_t address,
        std::uint32_t size)
    {
        MemoryReadRequestPayload payload = {};
        payload.requestId = requestId;
        payload.address = address;
        payload.size = size;
        return WriteMessage(
            pipeHandle,
            MessageKind::MemoryReadRequest,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }

    inline bool SendMemoryWriteRequest(
        HANDLE pipeHandle,
        std::uint32_t pid,
        std::uint64_t requestId,
        std::uint64_t address,
        const void* data,
        std::uint32_t size)
    {
        if (size > WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES)
        {
            return false;
        }

        MemoryWriteRequestPayload payload = {};
        payload.requestId = requestId;
        payload.address = address;
        payload.size = size;
        if (size != 0 && data != nullptr)
        {
            std::memcpy(payload.data, data, size);
        }

        return WriteMessage(
            pipeHandle,
            MessageKind::MemoryWriteRequest,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }

    inline bool SendMemoryReply(
        HANDLE pipeHandle,
        MessageKind kind,
        std::uint32_t pid,
        const MemoryReplyPayload& payload)
    {
        return WriteMessage(
            pipeHandle,
            kind,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }

    inline bool SendSharedMemoryConnectRequest(
        HANDLE pipeHandle,
        std::uint32_t pid,
        const SharedMemoryConnectRequestPayload& payload)
    {
        return WriteMessage(
            pipeHandle,
            MessageKind::SharedMemoryConnectRequest,
            pid,
            &payload,
            static_cast<std::uint32_t>(sizeof(payload)));
    }

    inline bool SendSharedMemoryConnectReply(
        HANDLE pipeHandle,
        std::uint32_t pid,
        const SharedMemoryConnectReplyPayload& payload)
    {
        return WriteMessage(
            pipeHandle,
            MessageKind::SharedMemoryConnectReply,
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
