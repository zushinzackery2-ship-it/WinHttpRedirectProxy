#include "pch.h"
#include "../proxy/redirect_runtime.hpp"
#include "memory_runtime_internal.hpp"

namespace WinHttpRedirectProxy::MemoryRuntime
{
    namespace
    {
        struct UNICODE_STRING
        {
            USHORT Length;
            USHORT MaximumLength;
            PWCH Buffer;
        };

        struct LIST_ENTRY
        {
            LIST_ENTRY* Flink;
            LIST_ENTRY* Blink;
        };

        struct LDR_DATA_TABLE_ENTRY
        {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        };

        struct PEB_LDR_DATA
        {
            ULONG Length;
            BOOLEAN Initialized;
            HANDLE SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        };

        struct PEB
        {
            BOOLEAN InheritedAddressSpace;
            BOOLEAN ReadImageFileExecOptions;
            BOOLEAN BeingDebugged;
            BOOLEAN BitField;
            PVOID Mutant;
            PVOID ImageBaseAddress;
            PEB_LDR_DATA* Ldr;
        };

        inline PEB* GetCurrentPeb()
        {
#if defined(_M_X64)
            return reinterpret_cast<PEB*>(__readgsqword(0x60));
#elif defined(_M_IX86)
            return reinterpret_cast<PEB*>(__readfsdword(0x30));
#else
            return nullptr;
#endif
        }

        void CopyWideName(wchar_t* dest, std::uint32_t destChars, const PWCH src, USHORT srcLen)
        {
            if (dest == nullptr || destChars == 0)
            {
                return;
            }

            dest[0] = L'\0';

            if (src == nullptr || srcLen == 0)
            {
                return;
            }

            const std::uint32_t copyChars = (std::min)(
                static_cast<std::uint32_t>(srcLen / sizeof(wchar_t)),
                destChars - 1);

            for (std::uint32_t i = 0; i < copyChars; ++i)
            {
                dest[i] = src[i];
            }

            dest[copyChars] = L'\0';
        }
    }

    void HandleModuleEnumRequest(WinHttpRedirectMemoryIpc::ModuleEnumReplyPayload& reply)
    {
        reply = {};
        reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::Success);

        PEB* peb = GetCurrentPeb();
        if (peb == nullptr || peb->Ldr == nullptr)
        {
            reply.status = static_cast<std::uint32_t>(WinHttpRedirectMemoryIpc::OperationStatus::QueryFailed);
            reply.win32Error = ERROR_NOT_SUPPORTED;
            return;
        }

        const LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        const LIST_ENTRY* current = head->Flink;

        std::uint32_t count = 0;
        while (current != head && count < WinHttpRedirectMemoryIpc::kMaxModuleEntries)
        {
            const auto* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            auto& dst = reply.entries[count];
            dst.baseAddress = reinterpret_cast<std::uint64_t>(entry->DllBase);
            dst.sizeOfImage = static_cast<std::uint64_t>(entry->SizeOfImage);
            CopyWideName(
                dst.name,
                WinHttpRedirectMemoryIpc::kModuleEntryNameChars,
                entry->BaseDllName.Buffer,
                entry->BaseDllName.Length);

            ++count;
            current = current->Flink;
        }

        reply.count = count;
        AppendRuntimeLog("memory-ipc module-enum count=" + std::to_string(count));
    }
}
