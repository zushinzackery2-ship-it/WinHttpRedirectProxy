#pragma once

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "winhttp_memory_ipc.hpp"

namespace WinHttpRedirectProxy::MemoryRuntime
{
    struct MemoryRegionCacheEntry
    {
        std::uintptr_t baseAddress;
        std::uintptr_t endAddress;
        DWORD protect;
        DWORD state;
        DWORD type;
    };

    struct MemoryAccessContext
    {
        bool active = false;
        WinHttpRedirectMemoryIpc::AccessKind accessKind = WinHttpRedirectMemoryIpc::AccessKind::Invalid;
        std::uint64_t requestId = 0;
        std::uintptr_t address = 0;
        std::uint32_t size = 0;
    };

    inline constexpr std::size_t kMaxRegionCacheEntries = 256;

    extern std::mutex gMemoryRegionCacheMutex;
    extern std::vector<MemoryRegionCacheEntry> gMemoryRegionCache;
    extern thread_local MemoryAccessContext gMemoryAccessContext;
    extern thread_local WinHttpRedirectMemoryIpc::MemoryReplyPayload* gMemoryAccessReply;

    std::string FormatHex(std::uint64_t value);
    bool IsReadableProtection(DWORD protect);
    bool IsWritableProtection(DWORD protect);
    void PopulateRegionInfo(std::uintptr_t address, WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    void InvalidateRegionCache(std::uintptr_t address);
    bool QueryRegionCached(
        std::uintptr_t address,
        MemoryRegionCacheEntry& entry,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    bool ValidateRange(
        std::uintptr_t address,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::AccessKind accessKind,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    void AppendMemoryAccessLog(const char* phase, const WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    LONG CALLBACK MemoryAccessVectoredHandler(EXCEPTION_POINTERS* exceptionPointers);
    bool ExecuteProtectedRead(
        std::uintptr_t address,
        void* destination,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    bool ExecuteProtectedWrite(
        std::uintptr_t address,
        const void* source,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    bool PrepareMemoryReply(
        std::uint64_t requestId,
        std::uint64_t address,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::AccessKind accessKind,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    void FinalizeFailure(WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    void HandleMemoryReadRequest(
        const WinHttpRedirectMemoryIpc::MemoryReadRequestPayload& request,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    void HandleMemoryWriteRequest(
        const WinHttpRedirectMemoryIpc::MemoryWriteRequestPayload& request,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply);
    void SendBadReply(HANDLE pipeHandle, WinHttpRedirectMemoryIpc::MessageKind replyKind);
    void ProcessMemoryPipeClient(HANDLE pipeHandle);
    DWORD WINAPI MemoryIpcThreadProc(void*);
}
