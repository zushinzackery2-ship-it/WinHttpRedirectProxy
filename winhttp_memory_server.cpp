#include "pch.h"
#include "winhttp_redirect_runtime.hpp"
#include "winhttp_memory_runtime.hpp"
#include "winhttp_memory_runtime_internal.hpp"

namespace WinHttpRedirectProxy
{
    namespace
    {
        std::atomic<bool> gMemoryRuntimeStopRequested = false;
        HANDLE gMemoryRuntimeThread = nullptr;
        PVOID gMemoryAccessVehHandle = nullptr;
    }

    namespace MemoryRuntime
    {
        DWORD WINAPI MemoryIpcThreadProc(void*)
        {
            AppendRuntimeLog("Memory IPC thread entered");
            AppendRuntimeLog("Memory IPC pipe = " + Narrow(WinHttpRedirectMemoryIpc::BuildPipeName(GetCurrentProcessId())));

            gMemoryAccessVehHandle = AddVectoredExceptionHandler(1, &MemoryAccessVectoredHandler);
            if (gMemoryAccessVehHandle == nullptr)
            {
                AppendRuntimeLog("AddVectoredExceptionHandler failed for memory IPC");
            }

            while (!gMemoryRuntimeStopRequested.load())
            {
                HANDLE pipeHandle = WinHttpRedirectMemoryIpc::CreatePipeServerInstance(GetCurrentProcessId());
                if (pipeHandle == INVALID_HANDLE_VALUE)
                {
                    AppendRuntimeLog("memory-ipc failed to create pipe instance");
                    Sleep(1000);
                    continue;
                }

                if (!WinHttpRedirectMemoryIpc::WaitForPipeClient(pipeHandle))
                {
                    AppendRuntimeLog("memory-ipc wait client failed error = " + std::to_string(GetLastError()));
                    WinHttpRedirectMemoryIpc::ClosePipe(pipeHandle);
                    if (!gMemoryRuntimeStopRequested.load())
                    {
                        Sleep(100);
                    }
                    continue;
                }

                AppendRuntimeLog("memory-ipc client connected");
                ProcessMemoryPipeClient(pipeHandle);
                AppendRuntimeLog("memory-ipc client disconnected");
                WinHttpRedirectMemoryIpc::ClosePipe(pipeHandle);
            }

            if (gMemoryAccessVehHandle != nullptr)
            {
                RemoveVectoredExceptionHandler(gMemoryAccessVehHandle);
                gMemoryAccessVehHandle = nullptr;
            }

            AppendRuntimeLog("Memory IPC thread exiting");
            return 0;
        }
    }

    void StartMemoryIpcRuntime()
    {
        if (ShouldSkipControllerRuntime() || gMemoryRuntimeThread != nullptr)
        {
            return;
        }

        gMemoryRuntimeStopRequested = false;
        gMemoryRuntimeThread = CreateThread(nullptr, 0, &MemoryRuntime::MemoryIpcThreadProc, nullptr, 0, nullptr);
        if (gMemoryRuntimeThread == nullptr)
        {
            AppendRuntimeLog("CreateThread failed for memory IPC, error = " + std::to_string(GetLastError()));
        }
    }

    void StopMemoryIpcRuntime()
    {
        gMemoryRuntimeStopRequested = true;
        if (gMemoryRuntimeThread != nullptr)
        {
            CloseHandle(gMemoryRuntimeThread);
            gMemoryRuntimeThread = nullptr;
        }
    }
}
