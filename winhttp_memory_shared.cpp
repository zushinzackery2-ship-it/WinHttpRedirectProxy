#include "pch.h"
#include "winhttp_redirect_runtime.hpp"
#include "winhttp_memory_runtime_internal.hpp"

#include <limits>

namespace WinHttpRedirectProxy::MemoryRuntime
{
    namespace
    {
        constexpr DWORD kSharedSessionIdleTimeoutMs = 120000;
        constexpr DWORD kSharedSessionPollTimeoutMs = 1000;

        struct SharedMemorySession
        {
            HANDLE MappingHandle = nullptr;
            HANDLE RequestEvent = nullptr;
            HANDLE ReplyEvent = nullptr;
            WinHttpRedirectMemoryIpc::SharedMemoryBlock* Block = nullptr;
            std::uint32_t MaxTransferSize = 0;
        };

        void CloseSharedMemorySession(SharedMemorySession& session)
        {
            if (session.Block != nullptr)
            {
                UnmapViewOfFile(session.Block);
                session.Block = nullptr;
            }
            if (session.MappingHandle != nullptr)
            {
                CloseHandle(session.MappingHandle);
                session.MappingHandle = nullptr;
            }
            if (session.RequestEvent != nullptr)
            {
                CloseHandle(session.RequestEvent);
                session.RequestEvent = nullptr;
            }
            if (session.ReplyEvent != nullptr)
            {
                CloseHandle(session.ReplyEvent);
                session.ReplyEvent = nullptr;
            }
        }

        void CopyReplyToSharedBlock(
            WinHttpRedirectMemoryIpc::SharedMemoryBlock& block,
            const WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
        {
            block.faultAddress = reply.faultAddress;
            block.instructionPointer = reply.instructionPointer;
            block.regionBaseAddress = reply.regionBaseAddress;
            block.regionSize = reply.regionSize;
            block.transferredSize = reply.transferredSize;
            block.status = reply.status;
            block.win32Error = reply.win32Error;
            block.exceptionCode = reply.exceptionCode;
            block.pageProtect = reply.pageProtect;
            block.pageState = reply.pageState;
            block.pageType = reply.pageType;
            block.accessKind = reply.accessKind;
            block.cacheHits = reply.cacheHits;
            block.cacheMisses = reply.cacheMisses;
            block.dataSize = reply.dataSize;
        }

        bool IsPipeClientDisconnected(HANDLE pipeHandle)
        {
            if (pipeHandle == nullptr || pipeHandle == INVALID_HANDLE_VALUE)
            {
                return true;
            }

            DWORD bytesAvailable = 0;
            if (PeekNamedPipe(pipeHandle, nullptr, 0, nullptr, &bytesAvailable, nullptr))
            {
                return false;
            }

            const DWORD error = GetLastError();
            return error == ERROR_BROKEN_PIPE
                || error == ERROR_PIPE_NOT_CONNECTED
                || error == ERROR_NO_DATA
                || error == ERROR_BAD_PIPE;
        }

        bool PrepareSharedMemoryReply(
            const WinHttpRedirectMemoryIpc::SharedMemoryBlock& block,
            std::uint32_t maxTransferSize,
            WinHttpRedirectMemoryIpc::AccessKind accessKind,
            WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
        {
            reply = {};
            reply.requestId = block.requestId;
            reply.address = block.address;
            reply.requestedSize = block.requestedSize;
            reply.accessKind = static_cast<std::uint32_t>(accessKind);

            if (block.requestedSize == 0)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::InvalidParameter);
                reply.win32Error = ERROR_INVALID_PARAMETER;
                return false;
            }
            if (block.requestedSize > maxTransferSize || block.requestedSize > WINHTTP_REDIRECT_PROXY_SHARED_MEMORY_BYTES)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::SizeTooLarge);
                reply.win32Error = ERROR_INVALID_PARAMETER;
                return false;
            }

            const auto maxAddress = std::numeric_limits<std::uintptr_t>::max();
            if (static_cast<std::uintptr_t>(block.address) > maxAddress - static_cast<std::uintptr_t>(block.requestedSize))
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::AddressOverflow);
                reply.win32Error = ERROR_ARITHMETIC_OVERFLOW;
                return false;
            }
            return true;
        }
        bool OpenSharedMemorySession(
            const WinHttpRedirectMemoryIpc::SharedMemoryConnectRequestPayload& request,
            SharedMemorySession& session,
            WinHttpRedirectMemoryIpc::SharedMemoryConnectReplyPayload& reply)
        {
            session = {};
            reply = {};
            reply.requestId = request.requestId;
            reply.sessionId = request.sessionId;
            reply.maxTransferSize = (std::min)(
                request.maxTransferSize,
                static_cast<std::uint32_t>(WINHTTP_REDIRECT_PROXY_SHARED_MEMORY_BYTES));

            if (reply.maxTransferSize == 0)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::InvalidParameter);
                reply.win32Error = ERROR_INVALID_PARAMETER;
                return false;
            }

            session.MappingHandle = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, request.mappingName);
            if (session.MappingHandle == nullptr)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
                reply.win32Error = GetLastError();
                return false;
            }

            session.Block = static_cast<WinHttpRedirectMemoryIpc::SharedMemoryBlock*>(
                MapViewOfFile(session.MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(WinHttpRedirectMemoryIpc::SharedMemoryBlock)));
            if (session.Block == nullptr)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
                reply.win32Error = GetLastError();
                CloseSharedMemorySession(session);
                return false;
            }

            session.RequestEvent = OpenEventW(SYNCHRONIZE, FALSE, request.requestEventName);
            if (session.RequestEvent == nullptr)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
                reply.win32Error = GetLastError();
                CloseSharedMemorySession(session);
                return false;
            }

            session.ReplyEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, request.replyEventName);
            if (session.ReplyEvent == nullptr)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
                reply.win32Error = GetLastError();
                CloseSharedMemorySession(session);
                return false;
            }

            if (session.Block->magic != WinHttpRedirectMemoryIpc::kSharedMemoryMagic
                || session.Block->version != WinHttpRedirectMemoryIpc::kSharedMemoryVersion)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::BadMessage);
                reply.win32Error = ERROR_INVALID_DATA;
                CloseSharedMemorySession(session);
                return false;
            }

            session.MaxTransferSize = reply.maxTransferSize;
            session.Block->maxTransferSize = reply.maxTransferSize;
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);
            return true;
        }

        bool ProcessSharedMemoryRequest(SharedMemorySession& session)
        {
            auto& block = *session.Block;
            MemoryBarrier();

            const auto command = static_cast<WinHttpRedirectMemoryIpc::SharedMemoryCommand>(block.command);
            WinHttpRedirectMemoryIpc::MemoryReplyPayload reply = {};

            if (command == WinHttpRedirectMemoryIpc::SharedMemoryCommand::Close)
            {
                reply.requestId = block.requestId;
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);
                CopyReplyToSharedBlock(block, reply);
                MemoryBarrier();
                SetEvent(session.ReplyEvent);
                return false;
            }

            if (command == WinHttpRedirectMemoryIpc::SharedMemoryCommand::Read)
            {
                if (PrepareSharedMemoryReply(block, session.MaxTransferSize, WinHttpRedirectMemoryIpc::AccessKind::Read, reply)
                    && ValidateRange(static_cast<std::uintptr_t>(block.address), block.requestedSize, WinHttpRedirectMemoryIpc::AccessKind::Read, reply)
                    && ExecuteProtectedRead(static_cast<std::uintptr_t>(block.address), block.replyData, block.requestedSize, reply))
                {
                    reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);
                    reply.transferredSize = block.requestedSize;
                    reply.dataSize = block.requestedSize;
                    PopulateRegionInfo(static_cast<std::uintptr_t>(block.address), reply);
                }
                else
                {
                    FinalizeFailure(reply);
                }

                CopyReplyToSharedBlock(block, reply);
                MemoryBarrier();
                SetEvent(session.ReplyEvent);
                return true;
            }

            if (command == WinHttpRedirectMemoryIpc::SharedMemoryCommand::Write)
            {
                if (PrepareSharedMemoryReply(block, session.MaxTransferSize, WinHttpRedirectMemoryIpc::AccessKind::Write, reply)
                    && ValidateRange(static_cast<std::uintptr_t>(block.address), block.requestedSize, WinHttpRedirectMemoryIpc::AccessKind::Write, reply)
                    && ExecuteProtectedWrite(static_cast<std::uintptr_t>(block.address), block.requestData, block.requestedSize, reply))
                {
                    reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);
                    reply.transferredSize = block.requestedSize;
                    PopulateRegionInfo(static_cast<std::uintptr_t>(block.address), reply);
                }
                else
                {
                    FinalizeFailure(reply);
                }

                CopyReplyToSharedBlock(block, reply);
                MemoryBarrier();
                SetEvent(session.ReplyEvent);
                return true;
            }

            reply.requestId = block.requestId;
            reply.address = block.address;
            reply.requestedSize = block.requestedSize;
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::BadMessage);
            reply.win32Error = ERROR_INVALID_DATA;
            CopyReplyToSharedBlock(block, reply);
            MemoryBarrier();
            SetEvent(session.ReplyEvent);
            return true;
        }
    }

    void ProcessSharedMemoryConnectRequest(
        HANDLE pipeHandle,
        const WinHttpRedirectMemoryIpc::SharedMemoryConnectRequestPayload& request)
    {
        SharedMemorySession session = {};
        WinHttpRedirectMemoryIpc::SharedMemoryConnectReplyPayload reply = {};
        const bool opened = OpenSharedMemorySession(request, session, reply);

        WinHttpRedirectMemoryIpc::SendSharedMemoryConnectReply(
            pipeHandle,
            GetCurrentProcessId(),
            reply);

        if (!opened)
        {
            AppendRuntimeLog(
                "memory-ipc shared session open failed status=" + std::to_string(reply.status)
                + " win32=" + std::to_string(reply.win32Error));
            return;
        }

        AppendRuntimeLog(
            "memory-ipc shared session opened clientPid=" + std::to_string(request.clientPid)
            + " maxTransfer=" + std::to_string(session.MaxTransferSize));

        std::size_t requestCount = 0;
        ULONGLONG lastActivityTick = GetTickCount64();
        for (;;)
        {
            const DWORD waitResult = WaitForSingleObject(session.RequestEvent, kSharedSessionPollTimeoutMs);
            if (waitResult == WAIT_TIMEOUT)
            {
                if (IsPipeClientDisconnected(pipeHandle))
                {
                    AppendRuntimeLog(
                        "memory-ipc shared session client disconnected requests=" + std::to_string(requestCount));
                    break;
                }

                if ((GetTickCount64() - lastActivityTick) >= kSharedSessionIdleTimeoutMs)
                {
                    AppendRuntimeLog(
                        "memory-ipc shared session idle timeout requests=" + std::to_string(requestCount));
                    break;
                }

                continue;
            }

            if (waitResult != WAIT_OBJECT_0)
            {
                AppendRuntimeLog(
                    "memory-ipc shared session wait failed requests=" + std::to_string(requestCount)
                    + " error=" + std::to_string(GetLastError()));
                break;
            }

            requestCount++;
            lastActivityTick = GetTickCount64();
            if (!ProcessSharedMemoryRequest(session))
            {
                break;
            }
        }

        CloseSharedMemorySession(session);
        AppendRuntimeLog(
            "memory-ipc shared session closed requests=" + std::to_string(requestCount));
    }
}
