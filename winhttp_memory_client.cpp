#include "pch.h"
#include "winhttp_memory_ipc.hpp"

#include <cwctype>
#include <string>

namespace
{
    void PrintUsage()
    {
        std::printf("Usage:\n");
        std::printf("  winhttp_memory_client.exe read <pid> <address> <size>\n");
        std::printf("  winhttp_memory_client.exe write <pid> <address> <hex bytes...>\n");
        std::printf("Examples:\n");
        std::printf("  winhttp_memory_client.exe read 1234 0x140000000 64\n");
        std::printf("  winhttp_memory_client.exe write 1234 0x140000000 90 90 CC\n");
    }

    bool ParseUnsigned64(const wchar_t* text, std::uint64_t& value)
    {
        if (text == nullptr || text[0] == L'\0')
        {
            return false;
        }

        wchar_t* end = nullptr;
        errno = 0;
        const auto parsed = _wcstoui64(text, &end, 0);
        if (errno != 0 || end == text || (end != nullptr && *end != L'\0'))
        {
            return false;
        }

        value = parsed;
        return true;
    }

    bool AppendHexToken(const wchar_t* text, std::wstring& digits)
    {
        if (text == nullptr || text[0] == L'\0')
        {
            return false;
        }

        std::wstring token(text);
        if (token.size() >= 2 && token[0] == L'0' && (token[1] == L'x' || token[1] == L'X'))
        {
            token.erase(0, 2);
        }

        if (token.empty())
        {
            return false;
        }

        for (const auto character : token)
        {
            if (!iswxdigit(character))
            {
                return false;
            }

            digits.push_back(character);
        }

        return true;
    }

    bool ParseHexBytes(int argc, wchar_t* argv[], int startIndex, std::vector<std::uint8_t>& bytes)
    {
        std::wstring digits;
        for (int index = startIndex; index < argc; ++index)
        {
            if (!AppendHexToken(argv[index], digits))
            {
                return false;
            }
        }

        if (digits.empty() || (digits.size() % 2) != 0)
        {
            return false;
        }

        bytes.clear();
        bytes.reserve(digits.size() / 2);
        for (std::size_t index = 0; index < digits.size(); index += 2)
        {
            wchar_t pair[3] = { digits[index], digits[index + 1], L'\0' };
            wchar_t* end = nullptr;
            const auto value = wcstoul(pair, &end, 16);
            if (end == pair || (end != nullptr && *end != L'\0'))
            {
                return false;
            }

            bytes.push_back(static_cast<std::uint8_t>(value));
        }

        return true;
    }

    const char* DescribeStatus(std::uint32_t status)
    {
        using Status = WinHttpRedirectMemoryIpc::OperationStatus;
        switch (static_cast<Status>(status))
        {
        case Status::Success:
            return "success";
        case Status::InvalidParameter:
            return "invalid-parameter";
        case Status::SizeTooLarge:
            return "size-too-large";
        case Status::AddressOverflow:
            return "address-overflow";
        case Status::QueryFailed:
            return "query-failed";
        case Status::ProtectionDenied:
            return "protection-denied";
        case Status::ExceptionCaught:
            return "exception-caught";
        case Status::BadMessage:
            return "bad-message";
        default:
            return "unknown";
        }
    }

    void PrintHexDump(const std::uint8_t* data, std::uint32_t size)
    {
        for (std::uint32_t offset = 0; offset < size; offset += 16)
        {
            std::printf("%08X  ", offset);
            for (std::uint32_t column = 0; column < 16; ++column)
            {
                const auto index = offset + column;
                if (index < size)
                {
                    std::printf("%02X ", data[index]);
                }
                else
                {
                    std::printf("   ");
                }
            }

            std::printf(" ");
            for (std::uint32_t column = 0; column < 16; ++column)
            {
                const auto index = offset + column;
                if (index < size)
                {
                    const auto value = data[index];
                    std::printf("%c", value >= 32 && value <= 126 ? value : '.');
                }
            }

            std::printf("\n");
        }
    }

    void PrintReply(const WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        std::printf("status=%s\n", DescribeStatus(reply.status));
        std::printf("request=%llu\n", static_cast<unsigned long long>(reply.requestId));
        std::printf("address=0x%llX\n", static_cast<unsigned long long>(reply.address));
        std::printf("requested=%u transferred=%u\n", reply.requestedSize, reply.transferredSize);
        std::printf("fault=0x%llX rip=0x%llX\n",
            static_cast<unsigned long long>(reply.faultAddress),
            static_cast<unsigned long long>(reply.instructionPointer));
        std::printf("win32=%u exception=0x%X\n", reply.win32Error, reply.exceptionCode);
        std::printf("region=0x%llX size=0x%llX protect=0x%X state=0x%X type=0x%X\n",
            static_cast<unsigned long long>(reply.regionBaseAddress),
            static_cast<unsigned long long>(reply.regionSize),
            reply.pageProtect,
            reply.pageState,
            reply.pageType);
        std::printf("cache hits=%u misses=%u\n", reply.cacheHits, reply.cacheMisses);
        if (reply.dataSize != 0)
        {
            PrintHexDump(reply.data, reply.dataSize);
        }
    }

    bool ReceiveReply(
        HANDLE pipeHandle,
        WinHttpRedirectMemoryIpc::MessageKind expectedKind,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        std::vector<std::uint8_t> buffer;
        if (!WinHttpRedirectMemoryIpc::ReadMessage(pipeHandle, buffer))
        {
            return false;
        }

        if (buffer.size() < sizeof(WinHttpRedirectMemoryIpc::MessageHeader) + sizeof(reply))
        {
            return false;
        }

        const auto* header = reinterpret_cast<const WinHttpRedirectMemoryIpc::MessageHeader*>(buffer.data());
        if (header->kind != static_cast<std::uint32_t>(expectedKind))
        {
            return false;
        }

        const auto* payload = reinterpret_cast<const WinHttpRedirectMemoryIpc::MemoryReplyPayload*>(
            buffer.data() + sizeof(WinHttpRedirectMemoryIpc::MessageHeader));
        reply = *payload;
        return true;
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 5)
    {
        PrintUsage();
        return 1;
    }

    std::uint64_t pidValue = 0;
    std::uint64_t address = 0;
    if (!ParseUnsigned64(argv[2], pidValue) || !ParseUnsigned64(argv[3], address))
    {
        PrintUsage();
        return 2;
    }

    if (pidValue > MAXDWORD)
    {
        std::printf("pid out of range\n");
        return 3;
    }

    const auto pid = static_cast<std::uint32_t>(pidValue);
    const auto requestId = static_cast<std::uint64_t>(GetTickCount64());

    HANDLE pipeHandle = WinHttpRedirectMemoryIpc::ConnectToPipe(pid, 1000);
    if (pipeHandle == INVALID_HANDLE_VALUE)
    {
        std::printf("connect failed, error=%u\n", GetLastError());
        return 4;
    }

    const std::wstring command(argv[1]);
    WinHttpRedirectMemoryIpc::MemoryReplyPayload reply = {};
    int exitCode = 0;
    if (_wcsicmp(command.c_str(), L"read") == 0)
    {
        std::uint64_t sizeValue = 0;
        if (!ParseUnsigned64(argv[4], sizeValue))
        {
            PrintUsage();
            CloseHandle(pipeHandle);
            return 5;
        }

        if (!WinHttpRedirectMemoryIpc::SendMemoryReadRequest(
                pipeHandle,
                GetCurrentProcessId(),
                requestId,
                address,
                static_cast<std::uint32_t>(sizeValue))
            || !ReceiveReply(
                pipeHandle,
                WinHttpRedirectMemoryIpc::MessageKind::MemoryReadReply,
                reply))
        {
            std::printf("read request failed, error=%u\n", GetLastError());
            CloseHandle(pipeHandle);
            return 6;
        }
    }
    else if (_wcsicmp(command.c_str(), L"write") == 0)
    {
        std::vector<std::uint8_t> bytes;
        if (!ParseHexBytes(argc, argv, 4, bytes))
        {
            PrintUsage();
            CloseHandle(pipeHandle);
            return 7;
        }

        if (!WinHttpRedirectMemoryIpc::SendMemoryWriteRequest(
                pipeHandle,
                GetCurrentProcessId(),
                requestId,
                address,
                bytes.data(),
                static_cast<std::uint32_t>(bytes.size()))
            || !ReceiveReply(
                pipeHandle,
                WinHttpRedirectMemoryIpc::MessageKind::MemoryWriteReply,
                reply))
        {
            std::printf("write request failed, error=%u\n", GetLastError());
            CloseHandle(pipeHandle);
            return 8;
        }
    }
    else
    {
        PrintUsage();
        CloseHandle(pipeHandle);
        return 9;
    }

    PrintReply(reply);
    if (reply.status != static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success))
    {
        exitCode = 10;
    }

    CloseHandle(pipeHandle);
    return exitCode;
}
