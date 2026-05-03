#include "pch.h"
#include "controller_state.hpp"

namespace WinHttpRedirectController
{
    std::wstring WidenText(const char* text)
    {
        if (text == nullptr || text[0] == '\0')
        {
            return {};
        }

        UINT codePage = CP_UTF8;
        auto count = MultiByteToWideChar(codePage, 0, text, -1, nullptr, 0);
        if (count <= 0)
        {
            codePage = CP_ACP;
            count = MultiByteToWideChar(codePage, 0, text, -1, nullptr, 0);
        }
        if (count <= 1)
        {
            return {};
        }

        std::wstring result(static_cast<std::size_t>(count), L'\0');
        MultiByteToWideChar(codePage, 0, text, -1, result.data(), count);
        result.resize(static_cast<std::size_t>(count - 1));
        return result;
    }

    void AppendLogLine(ControllerState& state, const std::wstring& line)
    {
        std::lock_guard<std::mutex> lock(state.logMutex);
        state.logLines.push_back(line);
        constexpr std::size_t kMaxLogLines = 256;
        if (state.logLines.size() > kMaxLogLines)
        {
            state.logLines.erase(
                state.logLines.begin(),
                state.logLines.begin() + (state.logLines.size() - kMaxLogLines));
        }

        state.logRevision.fetch_add(1);
    }

    std::wstring SnapshotLogText(ControllerState& state)
    {
        std::lock_guard<std::mutex> lock(state.logMutex);
        std::wstring text;
        for (std::size_t index = 0; index < state.logLines.size(); ++index)
        {
            if (index != 0)
            {
                text += L"\r\n";
            }

            text += state.logLines[index];
        }

        return text;
    }

    void GetSessionIdentity(
        const std::shared_ptr<AgentSession>& session,
        DWORD& pid,
        std::wstring& processPath)
    {
        pid = 0;
        processPath.clear();
        if (session == nullptr)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(session->metadataMutex);
        pid = session->pid;
        processPath = session->processPath;
    }

    std::wstring FormatSessionDisplay(const std::shared_ptr<AgentSession>& session)
    {
        DWORD pid = 0;
        std::wstring processPath;
        GetSessionIdentity(session, pid, processPath);
        return L"[" + std::to_wstring(pid) + L"] " + processPath;
    }

    void PruneSessions(ControllerState& state)
    {
        std::lock_guard<std::mutex> lock(state.sessionsMutex);
        const auto oldSize = state.sessions.size();
        std::erase_if(
            state.sessions,
            [](const std::shared_ptr<AgentSession>& session)
            {
                return session == nullptr || !session->connected.load();
            });
        if (state.sessions.size() != oldSize)
        {
            state.sessionsRevision.fetch_add(1);
        }
    }

    std::vector<std::shared_ptr<AgentSession>> SnapshotSessions(ControllerState& state)
    {
        std::lock_guard<std::mutex> lock(state.sessionsMutex);
        std::vector<std::shared_ptr<AgentSession>> sessions;
        for (const auto& session : state.sessions)
        {
            if (session != nullptr && session->connected.load() && session->helloReceived.load())
            {
                sessions.push_back(session);
            }
        }

        return sessions;
    }

    bool TrySelectDllPath(HWND ownerWindow, ControllerState& state, std::wstring& selectedPath)
    {
        std::wstring initialDirectory = state.lastDllDirectory.wstring();
        std::wstring filePathBuffer(32768, L'\0');
        OPENFILENAMEW dialog = {};
        static const wchar_t filter[] =
            L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0\0";

        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = ownerWindow;
        dialog.lpstrFilter = filter;
        dialog.lpstrFile = filePathBuffer.data();
        dialog.nMaxFile = static_cast<DWORD>(filePathBuffer.size());
        dialog.lpstrInitialDir = initialDirectory.empty() ? nullptr : initialDirectory.c_str();
        dialog.lpstrTitle = L"Select DLL to Load";
        dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;

        if (!GetOpenFileNameW(&dialog))
        {
            return false;
        }

        selectedPath.assign(filePathBuffer.c_str());
        state.lastDllDirectory = std::filesystem::path(selectedPath).parent_path();
        return true;
    }

    bool QueueLoadDllRequest(const std::shared_ptr<AgentSession>& session, const std::wstring& dllPath)
    {
        if (session == nullptr || !session->connected.load() || dllPath.empty())
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(session->pendingLoadMutex);
            session->pendingLoadDllPaths.push_back(dllPath);
        }

        if (session->activityEvent != nullptr)
        {
            SetEvent(session->activityEvent);
        }
        return true;
    }

    bool SendLoadDllRequest(const std::shared_ptr<AgentSession>& session, const std::wstring& dllPath)
    {
        if (session == nullptr || !session->connected.load())
        {
            return false;
        }

        std::lock_guard<std::mutex> lock(session->sendMutex);
        return WinHttpRedirectProxyIpc::SendLoadDllRequest(
            session->pipeHandle,
            GetCurrentProcessId(),
            dllPath);
    }
}
