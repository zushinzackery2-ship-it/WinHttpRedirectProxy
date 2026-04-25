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

#include "winhttp_ipc.hpp"

namespace WinHttpRedirectController
{
    struct AgentSession
    {
        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
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
        std::atomic<bool> stopRequested = false;
        std::mutex sessionsMutex;
        std::vector<std::shared_ptr<AgentSession>> sessions;
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
    void HandleSessionMessage(
        ControllerState& state,
        const std::shared_ptr<AgentSession>& session,
        const std::vector<std::uint8_t>& buffer);
    DWORD WINAPI SessionThreadProc(void* parameter);
    DWORD WINAPI AcceptThreadProc(void* parameter);
}
