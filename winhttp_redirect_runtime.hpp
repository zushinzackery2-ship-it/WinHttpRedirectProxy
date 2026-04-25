#pragma once

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "winhttp_ipc.hpp"
#include "winhttp_memory_runtime.hpp"

#ifndef WINHTTP_REDIRECT_PROXY_LOG_FILE_NAME
#define WINHTTP_REDIRECT_PROXY_LOG_FILE_NAME L"upd_runtime_log.txt"
#endif

#ifndef WINHTTP_REDIRECT_PROXY_LOG_PREFIX
#define WINHTTP_REDIRECT_PROXY_LOG_PREFIX "[UPD] "
#endif

namespace WinHttpRedirectProxy
{
    inline std::filesystem::path gRuntimeLogPath;
    inline std::atomic<bool> gStopRequested = false;
    inline std::mutex gRuntimeLogMutex;

    inline std::string Narrow(const std::wstring& text)
    {
        if (text.empty())
        {
            return {};
        }

        const auto count = WideCharToMultiByte(
            CP_UTF8,
            0,
            text.c_str(),
            -1,
            nullptr,
            0,
            nullptr,
            nullptr);
        if (count <= 1)
        {
            return {};
        }

        std::string result(static_cast<std::size_t>(count - 1), '\0');
        WideCharToMultiByte(
            CP_UTF8,
            0,
            text.c_str(),
            -1,
            result.data(),
            count - 1,
            nullptr,
            nullptr);
        return result;
    }

    inline std::wstring GetProcessPath()
    {
        std::wstring buffer(MAX_PATH, L'\0');
        const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0)
        {
            return {};
        }

        buffer.resize(length);
        return buffer;
    }

    inline bool EqualsInsensitive(std::wstring_view left, std::wstring_view right)
    {
        if (left.size() != right.size())
        {
            return false;
        }

        for (std::size_t index = 0; index < left.size(); ++index)
        {
            if (::towlower(left[index]) != ::towlower(right[index]))
            {
                return false;
            }
        }

        return true;
    }

    inline bool ShouldSkipControllerRuntime()
    {
        const auto processPath = GetProcessPath();
        if (processPath.empty())
        {
            return false;
        }

        return EqualsInsensitive(std::filesystem::path(processPath).filename().wstring(), L"winhttp_controller.exe");
    }

    inline std::filesystem::path GetModulePath(HMODULE module)
    {
        std::wstring buffer(MAX_PATH, L'\0');
        const auto length = GetModuleFileNameW(module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0)
        {
            return {};
        }

        buffer.resize(length);
        return std::filesystem::path(buffer);
    }

    inline void AppendRuntimeLog(const std::string& line)
    {
        std::lock_guard<std::mutex> lock(gRuntimeLogMutex);
        if (gRuntimeLogPath.empty())
        {
            return;
        }

        std::ofstream out(gRuntimeLogPath, std::ios::app | std::ios::binary);
        if (!out)
        {
            return;
        }

        out << WINHTTP_REDIRECT_PROXY_LOG_PREFIX << line << "\n";
    }

    inline void CloseClientPipe(HANDLE& pipeHandle)
    {
        if (pipeHandle == nullptr || pipeHandle == INVALID_HANDLE_VALUE)
        {
            pipeHandle = INVALID_HANDLE_VALUE;
            return;
        }

        CloseHandle(pipeHandle);
        pipeHandle = INVALID_HANDLE_VALUE;
    }

    inline bool SendControllerLog(HANDLE pipeHandle, const char* text)
    {
        return WinHttpRedirectProxyIpc::SendAgentLog(pipeHandle, GetCurrentProcessId(), text);
    }

    inline bool HandleLoadDllRequest(HANDLE pipeHandle, const std::vector<std::uint8_t>& buffer)
    {
        if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader) + sizeof(WinHttpRedirectProxyIpc::LoadDllRequestPayload))
        {
            return true;
        }

        const auto* payload = reinterpret_cast<const WinHttpRedirectProxyIpc::LoadDllRequestPayload*>(
            buffer.data() + sizeof(WinHttpRedirectProxyIpc::MessageHeader));
        const std::wstring dllPath(payload->dllPath);
        AppendRuntimeLog("Controller requested DLL = " + Narrow(dllPath));
        if (dllPath.empty())
        {
            WinHttpRedirectProxyIpc::SendLoadDllReply(
                pipeHandle,
                GetCurrentProcessId(),
                1,
                ERROR_INVALID_PARAMETER,
                dllPath,
                L"dll path is empty");
            return true;
        }

        const auto dllHandle = LoadLibraryW(dllPath.c_str());
        if (dllHandle == nullptr)
        {
            const auto error = GetLastError();
            AppendRuntimeLog("LoadLibraryW(selected DLL) failed, error = " + std::to_string(error));
            WinHttpRedirectProxyIpc::SendLoadDllReply(
                pipeHandle,
                GetCurrentProcessId(),
                1,
                error,
                dllPath,
                L"LoadLibraryW failed");
            return true;
        }

        AppendRuntimeLog("Loaded DLL from " + Narrow(dllPath));
        WinHttpRedirectProxyIpc::SendLoadDllReply(
            pipeHandle,
            GetCurrentProcessId(),
            0,
            0,
            dllPath,
            L"ok");
        return true;
    }

    inline DWORD WINAPI ControllerThread(void*)
    {
        AppendRuntimeLog("Controller thread entered");
        AppendRuntimeLog("PID = " + std::to_string(GetCurrentProcessId()));
        AppendRuntimeLog("Process = " + Narrow(GetProcessPath()));

        DWORD lastWaitLogTick = 0;
        while (!gStopRequested.load())
        {
            HANDLE pipeHandle = WinHttpRedirectProxyIpc::ConnectToPipe(500);
            if (pipeHandle == INVALID_HANDLE_VALUE)
            {
                const auto now = GetTickCount();
                if (lastWaitLogTick == 0 || now - lastWaitLogTick >= 5000)
                {
                    AppendRuntimeLog("Waiting for controller pipe");
                    lastWaitLogTick = now;
                }

                Sleep(1000);
                continue;
            }

            lastWaitLogTick = 0;
            AppendRuntimeLog("Controller connected");
            WinHttpRedirectProxyIpc::SendAgentHello(pipeHandle, GetCurrentProcessId(), GetProcessPath());
            SendControllerLog(pipeHandle, "agent connected");

            std::vector<std::uint8_t> buffer;
            while (!gStopRequested.load() && WinHttpRedirectProxyIpc::ReadMessage(pipeHandle, buffer))
            {
                if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader))
                {
                    continue;
                }

                const auto* header = reinterpret_cast<const WinHttpRedirectProxyIpc::MessageHeader*>(buffer.data());
                const auto kind = static_cast<WinHttpRedirectProxyIpc::MessageKind>(header->kind);
                if (kind == WinHttpRedirectProxyIpc::MessageKind::LoadDllRequest)
                {
                    HandleLoadDllRequest(pipeHandle, buffer);
                }
            }

            AppendRuntimeLog("Controller disconnected");
            CloseClientPipe(pipeHandle);
            Sleep(1000);
        }

        AppendRuntimeLog("Controller thread exiting");
        return 0;
    }

    inline BOOL HandleDllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
    {
        (void)reserved;

        if (reason == DLL_PROCESS_ATTACH)
        {
            DisableThreadLibraryCalls(instance);
            gStopRequested = false;

            const auto modulePath = GetModulePath(instance);
            gRuntimeLogPath = modulePath.parent_path() / WINHTTP_REDIRECT_PROXY_LOG_FILE_NAME;
            AppendRuntimeLog("DllMain attach");

            if (ShouldSkipControllerRuntime())
            {
                AppendRuntimeLog("Skipping controller IPC runtime inside winhttp_controller.exe");
                return TRUE;
            }

            StartMemoryIpcRuntime();

            const auto thread = CreateThread(nullptr, 0, &ControllerThread, nullptr, 0, nullptr);
            if (thread == nullptr)
            {
                AppendRuntimeLog("CreateThread failed, error = " + std::to_string(GetLastError()));
                return TRUE;
            }

            CloseHandle(thread);
        }
        else if (reason == DLL_PROCESS_DETACH)
        {
            gStopRequested = true;
            StopMemoryIpcRuntime();
        }

        return TRUE;
    }
}
