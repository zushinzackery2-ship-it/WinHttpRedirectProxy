#include "pch.h"
#include "winhttp_redirect_runtime.hpp"
#include "winhttp_memory_runtime.hpp"
#include "winhttp_memory_runtime_internal.hpp"

namespace WinHttpRedirectProxy
{
    namespace
    {
        std::atomic<bool> gMemoryRuntimeStopRequested = false;
        HANDLE gMemoryRuntimeStopEvent = nullptr;
        HANDLE gMemoryRuntimeThread = nullptr;
        PVOID gMemoryAccessVehHandle = nullptr;

        bool WaitForMemoryRuntimeStop(DWORD timeoutMs)
        {
            if (gMemoryRuntimeStopEvent == nullptr)
            {
                return gMemoryRuntimeStopRequested.load();
            }

            const DWORD waitResult = WaitForSingleObject(gMemoryRuntimeStopEvent, timeoutMs);
            return waitResult == WAIT_OBJECT_0 || gMemoryRuntimeStopRequested.load();
        }
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
                    if (WaitForMemoryRuntimeStop(1000))
                    {
                        break;
                    }
                    continue;
                }

                if (!WinHttpRedirectMemoryIpc::WaitForPipeClient(pipeHandle))
                {
                    AppendRuntimeLog("memory-ipc wait client failed error = " + std::to_string(GetLastError()));
                    WinHttpRedirectMemoryIpc::ClosePipe(pipeHandle);
                    if (!gMemoryRuntimeStopRequested.load() && WaitForMemoryRuntimeStop(100))
                    {
                        break;
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

        if (gMemoryRuntimeStopEvent == nullptr)
        {
            gMemoryRuntimeStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (gMemoryRuntimeStopEvent == nullptr)
            {
                AppendRuntimeLog("CreateEventW failed for memory IPC stop event, error = " + std::to_string(GetLastError()));
                return;
            }
        }
        else
        {
            ResetEvent(gMemoryRuntimeStopEvent);
        }

        gMemoryRuntimeStopRequested = false;
        gMemoryRuntimeThread = CreateThread(nullptr, 0, &MemoryRuntime::MemoryIpcThreadProc, nullptr, 0, nullptr);
        if (gMemoryRuntimeThread == nullptr)
        {
            AppendRuntimeLog("CreateThread failed for memory IPC, error = " + std::to_string(GetLastError()));
            SetEvent(gMemoryRuntimeStopEvent);
        }
    }

    void StopMemoryIpcRuntime()
    {
        gMemoryRuntimeStopRequested = true;
        if (gMemoryRuntimeStopEvent != nullptr)
        {
            SetEvent(gMemoryRuntimeStopEvent);
        }
        if (gMemoryRuntimeThread != nullptr)
        {
            CloseHandle(gMemoryRuntimeThread);
            gMemoryRuntimeThread = nullptr;
        }
    }
}
