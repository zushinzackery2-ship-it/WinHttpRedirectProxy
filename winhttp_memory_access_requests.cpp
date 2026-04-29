#include "pch.h"
#include "winhttp_redirect_runtime.hpp"
#include "winhttp_memory_runtime_internal.hpp"

#include <limits>

namespace WinHttpRedirectProxy::MemoryRuntime
{
    bool PrepareMemoryReply(
        std::uint64_t requestId,
        std::uint64_t address,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::AccessKind accessKind,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        reply = {};
        reply.requestId = requestId;
        reply.address = address;
        reply.requestedSize = size;
        reply.accessKind = static_cast<std::uint32_t>(accessKind);

        if (size == 0)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::InvalidParameter);
            reply.win32Error = ERROR_INVALID_PARAMETER;
            return false;
        }

        if (size > WINHTTP_REDIRECT_PROXY_MAX_MEMORY_BYTES)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::SizeTooLarge);
            reply.win32Error = ERROR_INVALID_PARAMETER;
            return false;
        }

        const auto maxAddress = std::numeric_limits<std::uintptr_t>::max();
        if (static_cast<std::uintptr_t>(address) > maxAddress - static_cast<std::uintptr_t>(size))
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::AddressOverflow);
            reply.win32Error = ERROR_ARITHMETIC_OVERFLOW;
            return false;
        }

        return true;
    }

    void FinalizeFailure(WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        if (reply.faultAddress == 0)
        {
            reply.faultAddress = reply.address;
        }

        PopulateRegionInfo(static_cast<std::uintptr_t>(reply.faultAddress), reply);
        InvalidateRegionCache(static_cast<std::uintptr_t>(reply.faultAddress));
        AppendMemoryAccessLog("fail", reply);
    }

    void HandleMemoryReadRequest(
        const WinHttpRedirectMemoryIpc::MemoryReadRequestPayload& request,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        if (!PrepareMemoryReply(
                request.requestId,
                request.address,
                request.size,
                WinHttpRedirectMemoryIpc::AccessKind::Read,
                reply))
        {
            FinalizeFailure(reply);
            return;
        }

        if (!ValidateRange(
                static_cast<std::uintptr_t>(request.address),
                request.size,
                WinHttpRedirectMemoryIpc::AccessKind::Read,
                reply))
        {
            FinalizeFailure(reply);
            return;
        }

        if (!ExecuteProtectedRead(
                static_cast<std::uintptr_t>(request.address),
                reply.data,
                request.size,
                reply))
        {
            FinalizeFailure(reply);
            return;
        }

        reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);
        reply.transferredSize = request.size;
        reply.dataSize = request.size;
        PopulateRegionInfo(static_cast<std::uintptr_t>(request.address), reply);
    }

    void HandleMemoryWriteRequest(
        const WinHttpRedirectMemoryIpc::MemoryWriteRequestPayload& request,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        if (!PrepareMemoryReply(
                request.requestId,
                request.address,
                request.size,
                WinHttpRedirectMemoryIpc::AccessKind::Write,
                reply))
        {
            FinalizeFailure(reply);
            return;
        }

        if (!ValidateRange(
                static_cast<std::uintptr_t>(request.address),
                request.size,
                WinHttpRedirectMemoryIpc::AccessKind::Write,
                reply))
        {
            FinalizeFailure(reply);
            return;
        }

        if (!ExecuteProtectedWrite(
                static_cast<std::uintptr_t>(request.address),
                request.data,
                request.size,
                reply))
        {
            FinalizeFailure(reply);
            return;
        }

        reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);
        reply.transferredSize = request.size;
        PopulateRegionInfo(static_cast<std::uintptr_t>(request.address), reply);
    }

    void SendBadReply(HANDLE pipeHandle, WinHttpRedirectMemoryIpc::MessageKind replyKind)
    {
        WinHttpRedirectMemoryIpc::MemoryReplyPayload reply = {};
        reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::BadMessage);
        reply.win32Error = ERROR_INVALID_DATA;
        WinHttpRedirectMemoryIpc::SendMemoryReply(
            pipeHandle,
            replyKind,
            GetCurrentProcessId(),
            reply);
    }

    void ProcessMemoryPipeClient(HANDLE pipeHandle)
    {
        std::size_t requestCount = 0;

        for (;;)
        {
            std::vector<std::uint8_t> buffer;
            if (!WinHttpRedirectMemoryIpc::ReadMessage(pipeHandle, buffer))
            {
                const DWORD lastError = GetLastError();
                AppendRuntimeLog(
                    "memory-ipc client session end requests=" + std::to_string(requestCount)
                    + " readError=" + std::to_string(lastError));
                return;
            }

            requestCount++;

            if (buffer.size() < sizeof(WinHttpRedirectMemoryIpc::MessageHeader))
            {
                AppendRuntimeLog(
                    "memory-ipc short message requests=" + std::to_string(requestCount)
                    + " size=" + std::to_string(buffer.size()));
                return;
            }

            const auto* header = reinterpret_cast<const WinHttpRedirectMemoryIpc::MessageHeader*>(buffer.data());
            WinHttpRedirectMemoryIpc::MemoryReplyPayload reply = {};
            if (header->kind == static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::MessageKind::MemoryReadRequest))
            {
                if (buffer.size() < sizeof(WinHttpRedirectMemoryIpc::MessageHeader)
                    + sizeof(WinHttpRedirectMemoryIpc::MemoryReadRequestPayload))
                {
                    AppendRuntimeLog(
                        "memory-ipc bad read request payload requests=" + std::to_string(requestCount)
                        + " size=" + std::to_string(buffer.size()));
                    SendBadReply(pipeHandle, WinHttpRedirectMemoryIpc::MessageKind::MemoryReadReply);
                    return;
                }

                const auto* request = reinterpret_cast<const WinHttpRedirectMemoryIpc::MemoryReadRequestPayload*>(
                    buffer.data() + sizeof(WinHttpRedirectMemoryIpc::MessageHeader));
                HandleMemoryReadRequest(*request, reply);
                if (!WinHttpRedirectMemoryIpc::SendMemoryReply(
                        pipeHandle,
                        WinHttpRedirectMemoryIpc::MessageKind::MemoryReadReply,
                        GetCurrentProcessId(),
                        reply))
                {
                    AppendRuntimeLog(
                        "memory-ipc send read reply failed requests=" + std::to_string(requestCount)
                        + " error=" + std::to_string(GetLastError()));
                    return;
                }

                continue;
            }

            if (header->kind == static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::MessageKind::MemoryWriteRequest))
            {
                if (buffer.size() < sizeof(WinHttpRedirectMemoryIpc::MessageHeader)
                    + sizeof(WinHttpRedirectMemoryIpc::MemoryWriteRequestPayload))
                {
                    AppendRuntimeLog(
                        "memory-ipc bad write request payload requests=" + std::to_string(requestCount)
                        + " size=" + std::to_string(buffer.size()));
                    SendBadReply(pipeHandle, WinHttpRedirectMemoryIpc::MessageKind::MemoryWriteReply);
                    return;
                }

                const auto* request = reinterpret_cast<const WinHttpRedirectMemoryIpc::MemoryWriteRequestPayload*>(
                    buffer.data() + sizeof(WinHttpRedirectMemoryIpc::MessageHeader));
                HandleMemoryWriteRequest(*request, reply);
                if (!WinHttpRedirectMemoryIpc::SendMemoryReply(
                        pipeHandle,
                        WinHttpRedirectMemoryIpc::MessageKind::MemoryWriteReply,
                        GetCurrentProcessId(),
                        reply))
                {
                    AppendRuntimeLog(
                        "memory-ipc send write reply failed requests=" + std::to_string(requestCount)
                        + " error=" + std::to_string(GetLastError()));
                    return;
                }

                continue;
            }

            if (header->kind == static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::MessageKind::SharedMemoryConnectRequest))
            {
                if (buffer.size() < sizeof(WinHttpRedirectMemoryIpc::MessageHeader)
                    + sizeof(WinHttpRedirectMemoryIpc::SharedMemoryConnectRequestPayload))
                {
                    AppendRuntimeLog(
                        "memory-ipc bad shared-memory connect payload requests=" + std::to_string(requestCount)
                        + " size=" + std::to_string(buffer.size()));
                    WinHttpRedirectMemoryIpc::SharedMemoryConnectReplyPayload badReply = {};
                    badReply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::BadMessage);
                    badReply.win32Error = ERROR_INVALID_DATA;
                    WinHttpRedirectMemoryIpc::SendSharedMemoryConnectReply(
                        pipeHandle,
                        GetCurrentProcessId(),
                        badReply);
                    return;
                }

                const auto* request = reinterpret_cast<const WinHttpRedirectMemoryIpc::SharedMemoryConnectRequestPayload*>(
                    buffer.data() + sizeof(WinHttpRedirectMemoryIpc::MessageHeader));
                ProcessSharedMemoryConnectRequest(pipeHandle, *request);
                return;
            }

            AppendRuntimeLog(
                "memory-ipc unknown message kind requests=" + std::to_string(requestCount)
                + " kind=" + std::to_string(header->kind));
            return;
        }
    }
}
