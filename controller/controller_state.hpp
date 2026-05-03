#pragma once

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "../common/ipc_control.hpp"

namespace WinHttpRedirectController
{
    struct AgentSession
    {
        ~AgentSession()
        {
            if (pipeHandle != nullptr && pipeHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(pipeHandle);
                pipeHandle = INVALID_HANDLE_VALUE;
            }
            if (activityEvent != nullptr)
            {
                CloseHandle(activityEvent);
                activityEvent = nullptr;
            }
        }

        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        HANDLE activityEvent = nullptr;
        DWORD pid = 0;
        std::wstring processPath;
        std::atomic<bool> connected = true;
        std::atomic<bool> helloReceived = false;
        mutable std::mutex metadataMutex;
        std::mutex pendingLoadMutex;
        std::deque<std::wstring> pendingLoadDllPaths;
        std::mutex sendMutex;
    };

    struct ControllerState
    {
        ~ControllerState()
        {
            if (stopEvent != nullptr)
            {
                CloseHandle(stopEvent);
                stopEvent = nullptr;
            }
            for (auto handle : sessionThreads)
            {
                if (handle != nullptr)
                {
                    CloseHandle(handle);
                }
            }
            sessionThreads.clear();
        }

        std::atomic<bool> stopRequested = false;
        HANDLE stopEvent = nullptr;
        std::mutex sessionsMutex;
        std::vector<std::shared_ptr<AgentSession>> sessions;
        std::mutex sessionThreadsMutex;
        std::vector<HANDLE> sessionThreads;
        std::mutex logMutex;
        std::vector<std::wstring> logLines;
        std::atomic<std::uint64_t> sessionsRevision = 1;
        std::atomic<std::uint64_t> logRevision = 1;
        std::filesystem::path lastDllDirectory;
    };

    struct SessionThreadContext
    {
        std::shared_ptr<ControllerState> state;
        std::shared_ptr<AgentSession> session;
    };

    struct AcceptThreadContext
    {
        std::shared_ptr<ControllerState> state;
    };

    std::wstring WidenText(const char* text);
    void AppendLogLine(ControllerState& state, const std::wstring& line);
    std::wstring SnapshotLogText(ControllerState& state);
    void GetSessionIdentity(const std::shared_ptr<AgentSession>& session, DWORD& pid, std::wstring& processPath);
    std::wstring FormatSessionDisplay(const std::shared_ptr<AgentSession>& session);
    void PruneSessions(ControllerState& state);
    std::vector<std::shared_ptr<AgentSession>> SnapshotSessions(ControllerState& state);
    bool TrySelectDllPath(HWND ownerWindow, ControllerState& state, std::wstring& selectedPath);
    bool QueueLoadDllRequest(const std::shared_ptr<AgentSession>& session, const std::wstring& dllPath);
    bool SendLoadDllRequest(const std::shared_ptr<AgentSession>& session, const std::wstring& dllPath);
}
