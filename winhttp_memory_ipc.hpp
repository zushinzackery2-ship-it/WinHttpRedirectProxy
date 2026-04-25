#pragma once

#ifndef WINHTTP_REDIRECT_PROXY_MEMORY_PIPE_PREFIX
#define WINHTTP_REDIRECT_PROXY_MEMORY_PIPE_PREFIX L"\\\\.\\pipe\\WinHttpRedirectProxyMemory-"
#endif

#ifndef WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES
#define WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES 16384
#endif

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace WinHttpRedirectMemoryIpc
{
    inline constexpr std::uint32_t kMagic = 0x4D505257;

    enum class MessageKind : std::uint32_t
    {
        Invalid = 0,
        MemoryReadRequest = 1,
        MemoryReadReply = 2,
        MemoryWriteRequest = 3,
        MemoryWriteReply = 4,
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

    inline std::wstring BuildPipeName(std::uint32_t pid)
    {
        return std::wstring(WINHTTP_REDIRECT_PROXY_MEMORY_PIPE_PREFIX) + std::to_wstring(pid);
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

    inline HANDLE ConnectToPipe(std::uint32_t pid, DWORD timeoutMs)
    {
        const auto pipeName = BuildPipeName(pid);
        if (!WaitNamedPipeW(pipeName.c_str(), timeoutMs))
        {
            return INVALID_HANDLE_VALUE;
        }

        return CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    }

    inline HANDLE CreatePipeServerInstance(std::uint32_t pid)
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

        const auto pipeName = BuildPipeName(pid);
        return CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            8192,
            8192,
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
}
