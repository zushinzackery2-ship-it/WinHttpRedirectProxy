#pragma once

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>

#ifndef WINHTTP_REDIRECT_PROXY_LOG_FILE_NAME
#define WINHTTP_REDIRECT_PROXY_LOG_FILE_NAME L"upd_runtime_log.txt"
#endif

#ifndef WINHTTP_REDIRECT_PROXY_LOG_PREFIX
#define WINHTTP_REDIRECT_PROXY_LOG_PREFIX "[UPD] "
#endif

#include "../common/ipc_control.hpp"
#include "../memory/memory_runtime.hpp"

namespace WinHttpRedirectProxy
{
    inline std::filesystem::path gRuntimeLogPath;
    inline std::atomic<bool> gStopRequested = false;
    inline HANDLE gControllerStopEvent = nullptr;
    inline std::mutex gRuntimeLogMutex;
    inline HANDLE gControllerThread = nullptr;

    std::string Narrow(const std::wstring& text);
    std::wstring GetProcessPath();
    bool EqualsInsensitive(std::wstring_view left, std::wstring_view right);
    bool ShouldSkipControllerRuntime();
    std::filesystem::path GetModulePath(HMODULE module);
    void AppendRuntimeLog(const std::string& line);
    void CloseClientPipe(HANDLE& pipeHandle);
    bool WaitForControllerStop(DWORD timeoutMs);
    bool SendControllerLog(HANDLE pipeHandle, const char* text);
    bool HandleLoadDllRequest(HANDLE pipeHandle, const std::vector<std::uint8_t>& buffer);
    DWORD WINAPI ControllerThread(void*);
    BOOL HandleDllMain(HINSTANCE instance, DWORD reason, LPVOID reserved);
}
