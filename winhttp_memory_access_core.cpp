#include "pch.h"
#include "winhttp_redirect_runtime.hpp"
#include "winhttp_memory_runtime_internal.hpp"

#include <limits>

namespace WinHttpRedirectProxy::MemoryRuntime
{
    std::mutex gMemoryRegionCacheMutex;
    std::vector<MemoryRegionCacheEntry> gMemoryRegionCache;
    thread_local MemoryAccessContext gMemoryAccessContext = {};
    thread_local WinHttpRedirectMemoryIpc::MemoryReplyPayload* gMemoryAccessReply = nullptr;

    namespace
    {
        bool TryGetRegionFromCache(std::uintptr_t address, MemoryRegionCacheEntry& entry)
        {
            std::lock_guard<std::mutex> lock(gMemoryRegionCacheMutex);
            for (const auto& candidate : gMemoryRegionCache)
            {
                if (address >= candidate.baseAddress && address < candidate.endAddress)
                {
                    entry = candidate;
                    return true;
                }
            }

            return false;
        }

        bool QueryRegion(std::uintptr_t address, MemoryRegionCacheEntry& entry)
        {
            MEMORY_BASIC_INFORMATION memoryInfo = {};
            if (VirtualQuery(reinterpret_cast<const void*>(address), &memoryInfo, sizeof(memoryInfo)) == 0)
            {
                return false;
            }

            entry.baseAddress = reinterpret_cast<std::uintptr_t>(memoryInfo.BaseAddress);
            entry.endAddress = entry.baseAddress + static_cast<std::uintptr_t>(memoryInfo.RegionSize);
            entry.protect = memoryInfo.Protect;
            entry.state = memoryInfo.State;
            entry.type = memoryInfo.Type;

            std::lock_guard<std::mutex> lock(gMemoryRegionCacheMutex);
            auto replaced = false;
            for (auto& candidate : gMemoryRegionCache)
            {
                if (candidate.baseAddress == entry.baseAddress)
                {
                    candidate = entry;
                    replaced = true;
                    break;
                }
            }

            if (!replaced)
            {
                if (gMemoryRegionCache.size() >= kMaxRegionCacheEntries)
                {
                    gMemoryRegionCache.erase(gMemoryRegionCache.begin());
                }

                gMemoryRegionCache.push_back(entry);
            }

            return true;
        }

        std::uintptr_t GetInstructionPointer(const EXCEPTION_POINTERS* exceptionPointers)
        {
            if (exceptionPointers == nullptr || exceptionPointers->ContextRecord == nullptr)
            {
                return 0;
            }

#if defined(_M_X64)
            return static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip);
#elif defined(_M_IX86)
            return static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Eip);
#else
            return 0;
#endif
        }

        std::uintptr_t GetFaultAddress(const EXCEPTION_POINTERS* exceptionPointers)
        {
            if (exceptionPointers == nullptr || exceptionPointers->ExceptionRecord == nullptr)
            {
                return 0;
            }

            const auto* record = exceptionPointers->ExceptionRecord;
            if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION
                && record->ExceptionCode != EXCEPTION_IN_PAGE_ERROR)
            {
                return 0;
            }

            if (record->NumberParameters < 2)
            {
                return 0;
            }

            return static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
        }

        void ResetMemoryAccessContext()
        {
            gMemoryAccessContext = {};
            gMemoryAccessReply = nullptr;
        }
    }

    std::string FormatHex(std::uint64_t value)
    {
        char buffer[32] = {};
        sprintf_s(buffer, "0x%llX", static_cast<unsigned long long>(value));
        return buffer;
    }

    bool IsReadableProtection(DWORD protect)
    {
        const auto value = protect & 0xFF;
        return value == PAGE_READONLY
            || value == PAGE_READWRITE
            || value == PAGE_WRITECOPY
            || value == PAGE_EXECUTE_READ
            || value == PAGE_EXECUTE_READWRITE
            || value == PAGE_EXECUTE_WRITECOPY;
    }

    bool IsWritableProtection(DWORD protect)
    {
        const auto value = protect & 0xFF;
        return value == PAGE_READWRITE
            || value == PAGE_WRITECOPY
            || value == PAGE_EXECUTE_READWRITE
            || value == PAGE_EXECUTE_WRITECOPY;
    }

    void PopulateRegionInfo(std::uintptr_t address, WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        MEMORY_BASIC_INFORMATION memoryInfo = {};
        if (VirtualQuery(reinterpret_cast<const void*>(address), &memoryInfo, sizeof(memoryInfo)) == 0)
        {
            return;
        }

        reply.regionBaseAddress = reinterpret_cast<std::uintptr_t>(memoryInfo.BaseAddress);
        reply.regionSize = static_cast<std::uint64_t>(memoryInfo.RegionSize);
        reply.pageProtect = memoryInfo.Protect;
        reply.pageState = memoryInfo.State;
        reply.pageType = memoryInfo.Type;
    }

    void InvalidateRegionCache(std::uintptr_t address)
    {
        std::lock_guard<std::mutex> lock(gMemoryRegionCacheMutex);
        std::erase_if(
            gMemoryRegionCache,
            [address](const MemoryRegionCacheEntry& entry)
            {
                return address >= entry.baseAddress && address < entry.endAddress;
            });
    }

    bool QueryRegionCached(
        std::uintptr_t address,
        MemoryRegionCacheEntry& entry,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        if (TryGetRegionFromCache(address, entry))
        {
            reply.cacheHits += 1;
            return true;
        }

        reply.cacheMisses += 1;
        return QueryRegion(address, entry);
    }

    bool ValidateRange(
        std::uintptr_t address,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::AccessKind accessKind,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        auto current = address;
        std::size_t remaining = size;
        while (remaining != 0)
        {
            MemoryRegionCacheEntry entry = {};
            if (!QueryRegionCached(current, entry, reply))
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
                reply.win32Error = ERROR_INVALID_ADDRESS;
                reply.faultAddress = current;
                return false;
            }

            reply.regionBaseAddress = entry.baseAddress;
            reply.regionSize = static_cast<std::uint64_t>(entry.endAddress - entry.baseAddress);
            reply.pageProtect = entry.protect;
            reply.pageState = entry.state;
            reply.pageType = entry.type;

            const auto allowed = accessKind == WinHttpRedirectMemoryIpc::AccessKind::Read
                ? IsReadableProtection(entry.protect)
                : IsWritableProtection(entry.protect);
            if (entry.state != MEM_COMMIT || (entry.protect & PAGE_GUARD) != 0 || !allowed)
            {
                reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::ProtectionDenied);
                reply.win32Error = ERROR_NOACCESS;
                reply.faultAddress = current;
                return false;
            }

            const auto available = static_cast<std::size_t>(entry.endAddress - current);
            const auto consumed = std::min(remaining, available);
            current += consumed;
            remaining -= consumed;
        }

        return true;
    }

    void AppendMemoryAccessLog(const char* phase, const WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        std::string line = "memory-";
        line += phase;
        line += " request=" + std::to_string(reply.requestId);
        line += " op=" + std::to_string(reply.accessKind);
        line += " address=" + FormatHex(reply.address);
        line += " fault=" + FormatHex(reply.faultAddress);
        line += " rip=" + FormatHex(reply.instructionPointer);
        line += " status=" + std::to_string(reply.status);
        line += " exception=" + FormatHex(reply.exceptionCode);
        AppendRuntimeLog(line);
    }

    LONG CALLBACK MemoryAccessVectoredHandler(EXCEPTION_POINTERS* exceptionPointers)
    {
        if (gMemoryAccessReply == nullptr || !gMemoryAccessContext.active || exceptionPointers == nullptr)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const auto code = exceptionPointers->ExceptionRecord != nullptr
            ? exceptionPointers->ExceptionRecord->ExceptionCode
            : 0;
        if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_IN_PAGE_ERROR)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        auto& reply = *gMemoryAccessReply;
        reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::ExceptionCaught);
        reply.exceptionCode = code;
        reply.win32Error = ERROR_NOACCESS;
        reply.faultAddress = GetFaultAddress(exceptionPointers);
        reply.instructionPointer = GetInstructionPointer(exceptionPointers);
        PopulateRegionInfo(reply.faultAddress != 0 ? static_cast<std::uintptr_t>(reply.faultAddress) : gMemoryAccessContext.address, reply);
        AppendMemoryAccessLog("exception", reply);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool ExecuteProtectedRead(
        std::uintptr_t address,
        void* destination,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        bool success = false;
        gMemoryAccessContext.active = true;
        gMemoryAccessContext.accessKind = WinHttpRedirectMemoryIpc::AccessKind::Read;
        gMemoryAccessContext.requestId = reply.requestId;
        gMemoryAccessContext.address = address;
        gMemoryAccessContext.size = size;
        gMemoryAccessReply = &reply;

        __try
        {
            std::memcpy(destination, reinterpret_cast<const void*>(address), size);
            success = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::ExceptionCaught);
            reply.exceptionCode = static_cast<std::uint32_t>(GetExceptionCode());
            reply.win32Error = ERROR_NOACCESS;
        }

        ResetMemoryAccessContext();
        return success;
    }

    bool ExecuteProtectedWrite(
        std::uintptr_t address,
        const void* source,
        std::uint32_t size,
        WinHttpRedirectMemoryIpc::MemoryReplyPayload& reply)
    {
        bool success = false;
        gMemoryAccessContext.active = true;
        gMemoryAccessContext.accessKind = WinHttpRedirectMemoryIpc::AccessKind::Write;
        gMemoryAccessContext.requestId = reply.requestId;
        gMemoryAccessContext.address = address;
        gMemoryAccessContext.size = size;
        gMemoryAccessReply = &reply;

        __try
        {
            std::memcpy(reinterpret_cast<void*>(address), source, size);
            success = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::ExceptionCaught);
            reply.exceptionCode = static_cast<std::uint32_t>(GetExceptionCode());
            reply.win32Error = ERROR_NOACCESS;
        }

        ResetMemoryAccessContext();
        return success;
    }
}
