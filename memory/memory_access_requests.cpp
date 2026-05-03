#include "pch.h"
#include "../proxy/redirect_runtime.hpp"
#include "memory_runtime_internal.hpp"

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

    void HandleLoadDllRequest(
        const WinHttpRedirectMemoryIpc::LoadDllRequestPayload& request,
        WinHttpRedirectMemoryIpc::LoadDllReplyPayload& reply)
    {
        reply = {};
        reply.requestId = request.requestId;
        wcsncpy_s(reply.dllPath, WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS, request.dllPath, _TRUNCATE);

        const std::size_t pathLength = wcsnlen_s(request.dllPath, WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS);
        if (pathLength == 0 || pathLength >= WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::InvalidParameter);
            reply.win32Error = ERROR_INVALID_PARAMETER;
            wcsncpy_s(reply.text, WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS, L"invalid DLL path", _TRUNCATE);
            return;
        }

        if (GetFileAttributesW(request.dllPath) == INVALID_FILE_ATTRIBUTES)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
            reply.win32Error = GetLastError();
            wcsncpy_s(reply.text, WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS, L"DLL path not found", _TRUNCATE);
            return;
        }

        AppendRuntimeLog("memory-ipc load-dll request = " + Narrow(request.dllPath));
        HMODULE module = LoadLibraryW(request.dllPath);
        if (module == nullptr)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
            reply.win32Error = GetLastError();
            wcsncpy_s(reply.text, WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS, L"LoadLibraryW failed", _TRUNCATE);
            AppendRuntimeLog("memory-ipc load-dll failed error=" + std::to_string(reply.win32Error));
            return;
        }

        reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);
        reply.moduleHandle = reinterpret_cast<std::uint64_t>(module);
        wcsncpy_s(reply.text, WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS, L"LoadLibraryW succeeded", _TRUNCATE);
        AppendRuntimeLog("memory-ipc load-dll loaded = " + Narrow(request.dllPath));
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

            if (header->kind == static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::MessageKind::ModuleEnumRequest))
            {
                WinHttpRedirectMemoryIpc::ModuleEnumReplyPayload modReply = {};
                modReply.requestId = 0;

                if (buffer.size() < sizeof(WinHttpRedirectMemoryIpc::MessageHeader)
                    + sizeof(WinHttpRedirectMemoryIpc::ModuleEnumRequestPayload))
                {
                    modReply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::BadMessage);
                    modReply.win32Error = ERROR_INVALID_DATA;
                }
                else
                {
                    const auto* modReq = reinterpret_cast<const WinHttpRedirectMemoryIpc::ModuleEnumRequestPayload*>(
                        buffer.data() + sizeof(WinHttpRedirectMemoryIpc::MessageHeader));
                    modReply.requestId = modReq->requestId;
                    HandleModuleEnumRequest(modReply);
                }

                if (!WinHttpRedirectMemoryIpc::SendModuleEnumReply(
                        pipeHandle,
                        GetCurrentProcessId(),
                        modReply))
                {
                    AppendRuntimeLog(
                        "memory-ipc send module-enum reply failed requests=" + std::to_string(requestCount)
                        + " error=" + std::to_string(GetLastError()));
                    return;
                }

                continue;
            }

            if (header->kind == static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::MessageKind::LoadDllRequest))
            {
                WinHttpRedirectMemoryIpc::LoadDllReplyPayload loadReply = {};
                loadReply.requestId = 0;

                if (buffer.size() < sizeof(WinHttpRedirectMemoryIpc::MessageHeader)
                    + sizeof(WinHttpRedirectMemoryIpc::LoadDllRequestPayload))
                {
                    loadReply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::BadMessage);
                    loadReply.win32Error = ERROR_INVALID_DATA;
                    wcsncpy_s(loadReply.text, WINHTTP_REDIRECT_PROXY_MEMORY_MAX_PATH_CHARS, L"bad load-dll payload", _TRUNCATE);
                }
                else
                {
                    const auto* loadReq = reinterpret_cast<const WinHttpRedirectMemoryIpc::LoadDllRequestPayload*>(
                        buffer.data() + sizeof(WinHttpRedirectMemoryIpc::MessageHeader));
                    loadReply.requestId = loadReq->requestId;
                    HandleLoadDllRequest(*loadReq, loadReply);
                }

                if (!WinHttpRedirectMemoryIpc::SendLoadDllReply(
                        pipeHandle,
                        GetCurrentProcessId(),
                        loadReply))
                {
                    AppendRuntimeLog(
                        "memory-ipc send load-dll reply failed requests=" + std::to_string(requestCount)
                        + " error=" + std::to_string(GetLastError()));
                    return;
                }

                continue;
            }

            AppendRuntimeLog(
                "memory-ipc unknown message kind requests=" + std::to_string(requestCount)
                + " kind=" + std::to_string(header->kind));
            return;
        }
    }
}
