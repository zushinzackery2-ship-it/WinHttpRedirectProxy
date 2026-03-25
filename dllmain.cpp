#include "pch.h"
#include "winhttp_forward_exports.h"

namespace
{
    constexpr DWORD kBootstrapTimeoutMs = 180000;
    constexpr DWORD kWaitLogIntervalMs = 5000;
    constexpr std::size_t kModuleSnapshotLimit = 24;

    std::filesystem::path gRuntimeLogPath;
    std::mutex gRuntimeLogMutex;

    std::string Narrow(const std::wstring& text)
    {
        if (text.empty())
        {
            return {};
        }

        auto count = WideCharToMultiByte(
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

    std::wstring GetProcessPath()
    {
        std::wstring buffer(MAX_PATH, L'\0');
        auto length = GetModuleFileNameW(
            nullptr,
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (length == 0)
        {
            return {};
        }

        buffer.resize(length);
        return buffer;
    }

    std::filesystem::path GetModulePath(HMODULE module)
    {
        std::wstring buffer(MAX_PATH, L'\0');
        auto length = GetModuleFileNameW(
            module,
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (length == 0)
        {
            return {};
        }

        buffer.resize(length);
        return std::filesystem::path(buffer);
    }

    void AppendRuntimeLog(const std::string& line)
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

        out << "[UPD] " << line << "\n";
    }

    std::vector<std::wstring> EnumerateLoadedModules(std::size_t limit)
    {
        std::vector<std::wstring> modules;

        HMODULE loadedModules[1024] = {};
        DWORD bytesNeeded = 0;
        if (!EnumProcessModules(GetCurrentProcess(), loadedModules, sizeof(loadedModules), &bytesNeeded))
        {
            return modules;
        }

        auto count = std::min<std::size_t>(
            bytesNeeded / sizeof(HMODULE),
            std::size(loadedModules));
        for (std::size_t index = 0; index < count && modules.size() < limit; ++index)
        {
            wchar_t modulePath[MAX_PATH] = {};
            if (GetModuleFileNameW(loadedModules[index], modulePath, MAX_PATH) == 0)
            {
                continue;
            }

            modules.push_back(std::filesystem::path(modulePath).filename().wstring());
        }

        return modules;
    }

    void AppendModuleSnapshot(const char* prefix)
    {
        auto modules = EnumerateLoadedModules(kModuleSnapshotLimit);
        std::string line(prefix);
        line += " modules(" + std::to_string(modules.size()) + "): ";

        for (std::size_t index = 0; index < modules.size(); ++index)
        {
            if (index != 0)
            {
                line += ", ";
            }

            line += Narrow(modules[index]);
        }

        AppendRuntimeLog(line);
    }

    HMODULE FindLoadedModule(const wchar_t* moduleName)
    {
        auto handle = GetModuleHandleW(moduleName);
        if (handle != nullptr)
        {
            return handle;
        }

        HMODULE loadedModules[1024] = {};
        DWORD bytesNeeded = 0;
        if (!EnumProcessModules(GetCurrentProcess(), loadedModules, sizeof(loadedModules), &bytesNeeded))
        {
            return nullptr;
        }

        auto count = std::min<std::size_t>(
            bytesNeeded / sizeof(HMODULE),
            std::size(loadedModules));
        for (std::size_t index = 0; index < count; ++index)
        {
            wchar_t modulePath[MAX_PATH] = {};
            if (GetModuleFileNameW(loadedModules[index], modulePath, MAX_PATH) == 0)
            {
                continue;
            }

            if (_wcsicmp(
                    std::filesystem::path(modulePath).filename().c_str(),
                    moduleName)
                == 0)
            {
                return loadedModules[index];
            }
        }

        return nullptr;
    }

    bool WaitForBootstrapModules()
    {
        auto startTick = GetTickCount64();
        auto lastLogTick = startTick;

        while (GetTickCount64() - startTick < kBootstrapTimeoutMs)
        {
            auto gameAssembly = FindLoadedModule(L"GameAssembly.dll");
            auto unityPlayer = FindLoadedModule(L"UnityPlayer.dll");
            if (gameAssembly != nullptr || unityPlayer != nullptr)
            {
                if (gameAssembly != nullptr)
                {
                    AppendRuntimeLog("GameAssembly.dll ready");
                }
                if (unityPlayer != nullptr)
                {
                    AppendRuntimeLog("UnityPlayer.dll ready");
                }

                AppendModuleSnapshot("Bootstrap ready");
                return true;
            }

            auto nowTick = GetTickCount64();
            if (nowTick - lastLogTick >= kWaitLogIntervalMs)
            {
                AppendRuntimeLog("Still waiting for GameAssembly.dll / UnityPlayer.dll");
                AppendModuleSnapshot("Waiting");
                lastLogTick = nowTick;
            }

            Sleep(200);
        }

        AppendRuntimeLog("Timed out waiting for bootstrap modules");
        AppendModuleSnapshot("Timeout");
        return false;
    }

    DWORD WINAPI RuntimeCaptureThread(void*)
    {
        AppendRuntimeLog("Runtime thread entered");
        AppendRuntimeLog("PID = " + std::to_string(GetCurrentProcessId()));
        AppendRuntimeLog("Process = " + Narrow(GetProcessPath()));
        AppendModuleSnapshot("Startup");

        if (!WaitForBootstrapModules())
        {
            return 1;
        }

        auto probePath = gRuntimeLogPath.parent_path() / L"RuntimeCaptureProbe.dll";
        if (!std::filesystem::exists(probePath))
        {
            AppendRuntimeLog(
                "RuntimeCaptureProbe.dll not found: "
                + Narrow(probePath.wstring()));
            return 2;
        }

        auto probeHandle = LoadLibraryW(probePath.c_str());
        if (probeHandle == nullptr)
        {
            AppendRuntimeLog(
                "LoadLibraryW(RuntimeCaptureProbe.dll) failed, error = "
                + std::to_string(GetLastError()));
            return 3;
        }

        AppendRuntimeLog("Loaded RuntimeCaptureProbe from " + Narrow(probePath.wstring()));
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(instance);

        auto modulePath = GetModulePath(instance);
        gRuntimeLogPath = modulePath.parent_path() / L"upd_runtime_log.txt";
        AppendRuntimeLog("DllMain attach");

        auto thread = CreateThread(nullptr, 0, &RuntimeCaptureThread, nullptr, 0, nullptr);
        if (thread == nullptr)
        {
            AppendRuntimeLog(
                "CreateThread failed, error = "
                + std::to_string(GetLastError()));
            return TRUE;
        }

        CloseHandle(thread);
    }

    return TRUE;
}
