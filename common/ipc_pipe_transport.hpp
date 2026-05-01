#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace WinHttpRedirectIpc
{
    inline constexpr std::uint32_t kMaxMessageSize = 1 * 1024 * 1024;
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

    template <typename HeaderT>
    inline bool WriteMessage(
        HANDLE pipeHandle,
        const HeaderT& header,
        const void* payload,
        std::uint32_t payloadSize)
    {
        if (!WriteAll(pipeHandle, &header, static_cast<DWORD>(sizeof(header))))
        {
            return false;
        }

        if (payloadSize == 0 || payload == nullptr)
        {
            return true;
        }

        return WriteAll(pipeHandle, payload, payloadSize);
    }

    template <typename HeaderT>
    inline bool ReadMessage(
        HANDLE pipeHandle,
        std::vector<std::uint8_t>& buffer,
        std::uint32_t expectedMagic,
        std::size_t headerSize)
    {
        buffer.resize(headerSize);
        if (!ReadAll(pipeHandle, buffer.data(), static_cast<DWORD>(headerSize)))
        {
            return false;
        }

        const auto* header = reinterpret_cast<const HeaderT*>(buffer.data());
        if (header->magic != expectedMagic || header->size < headerSize || header->size > kMaxMessageSize)
        {
            return false;
        }

        buffer.resize(header->size);
        const auto payloadSize = static_cast<DWORD>(header->size - headerSize);
        if (payloadSize == 0)
        {
            return true;
        }

        return ReadAll(pipeHandle, buffer.data() + headerSize, payloadSize);
    }

    inline SECURITY_ATTRIBUTES CreateOpenSecurityAttributes(SECURITY_DESCRIPTOR& descriptor)
    {
        InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&descriptor, TRUE, nullptr, FALSE);

        SECURITY_ATTRIBUTES attributes = {};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = &descriptor;
        attributes.bInheritHandle = FALSE;
        return attributes;
    }

    inline HANDLE CreateNamedPipeServer(
        const std::wstring& pipeName,
        DWORD inBufferSize = 8192,
        DWORD outBufferSize = 8192)
    {
        SECURITY_DESCRIPTOR descriptor = {};
        SECURITY_ATTRIBUTES attributes = CreateOpenSecurityAttributes(descriptor);

        return CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            inBufferSize,
            outBufferSize,
            0,
            &attributes);
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

    inline HANDLE ConnectToNamedPipe(const std::wstring& pipeName, DWORD timeoutMs)
    {
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
}
