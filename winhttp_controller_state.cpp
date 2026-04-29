#include "pch.h"
#include "winhttp_controller_state.hpp"

namespace WinHttpRedirectController
{
    namespace
    {
        bool TryDequeuePendingLoadDllPath(const std::shared_ptr<AgentSession>& session, std::wstring& dllPath)
        {
            std::lock_guard<std::mutex> lock(session->pendingLoadMutex);
            if (session->pendingLoadDllPaths.empty())
            {
                return false;
            }

            dllPath = std::move(session->pendingLoadDllPaths.front());
            session->pendingLoadDllPaths.pop_front();
            return true;
        }

        bool TryReadSessionMessage(HANDLE pipeHandle, std::vector<std::uint8_t>& buffer)
        {
            DWORD bytesAvailable = 0;
            if (!PeekNamedPipe(pipeHandle, nullptr, 0, nullptr, &bytesAvailable, nullptr))
            {
                return false;
            }

            if (bytesAvailable < sizeof(WinHttpRedirectProxyIpc::MessageHeader))
            {
                return true;
            }

            return WinHttpRedirectProxyIpc::ReadMessage(pipeHandle, buffer);
        }

        bool WaitForControllerStop(const std::shared_ptr<ControllerState>& state, DWORD timeoutMs)
        {
            if (state == nullptr)
            {
                return true;
            }

            if (state->stopEvent == nullptr)
            {
                return state->stopRequested.load();
            }

            const DWORD waitResult = WaitForSingleObject(state->stopEvent, timeoutMs);
            return waitResult == WAIT_OBJECT_0 || state->stopRequested.load();
        }

        bool WaitForSessionActivityOrStop(
            const std::shared_ptr<ControllerState>& state,
            const std::shared_ptr<AgentSession>& session,
            DWORD timeoutMs)
        {
            if (state == nullptr || session == nullptr)
            {
                return true;
            }

            if (state->stopEvent != nullptr && session->activityEvent != nullptr)
            {
                HANDLE handles[] = { state->stopEvent, session->activityEvent };
                const DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, timeoutMs);
                return waitResult == WAIT_OBJECT_0 || state->stopRequested.load() || !session->connected.load();
            }

            if (state->stopEvent != nullptr)
            {
                return WaitForControllerStop(state, timeoutMs) || !session->connected.load();
            }

            if (session->activityEvent != nullptr)
            {
                WaitForSingleObject(session->activityEvent, timeoutMs);
            }

            return state->stopRequested.load() || !session->connected.load();
        }
    }

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

    void HandleSessionMessage(
        ControllerState& state,
        const std::shared_ptr<AgentSession>& session,
        const std::vector<std::uint8_t>& buffer)
    {
        if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader))
        {
            return;
        }

        const auto* header = reinterpret_cast<const WinHttpRedirectProxyIpc::MessageHeader*>(buffer.data());
        const auto kind = static_cast<WinHttpRedirectProxyIpc::MessageKind>(header->kind);
        if (kind == WinHttpRedirectProxyIpc::MessageKind::AgentHello)
        {
            if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader)
                + sizeof(WinHttpRedirectProxyIpc::AgentHelloPayload))
            {
                return;
            }

            const auto* payload = reinterpret_cast<const WinHttpRedirectProxyIpc::AgentHelloPayload*>(
                buffer.data() + sizeof(WinHttpRedirectProxyIpc::MessageHeader));
            {
                std::lock_guard<std::mutex> lock(session->metadataMutex);
                session->pid = header->pid;
                session->processPath.assign(payload->processPath);
            }
            session->helloReceived = true;
            state.sessionsRevision.fetch_add(1);
            AppendLogLine(state, L"[connect] " + FormatSessionDisplay(session));
            return;
        }

        if (kind == WinHttpRedirectProxyIpc::MessageKind::AgentLog)
        {
            if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader)
                + sizeof(WinHttpRedirectProxyIpc::AgentLogPayload))
            {
                return;
            }

            const auto* payload = reinterpret_cast<const WinHttpRedirectProxyIpc::AgentLogPayload*>(
                buffer.data() + sizeof(WinHttpRedirectProxyIpc::MessageHeader));
            AppendLogLine(
                state,
                L"[log] pid=" + std::to_wstring(header->pid) + L" " + WidenText(payload->text));
            return;
        }

        if (kind == WinHttpRedirectProxyIpc::MessageKind::LoadDllReply)
        {
            if (buffer.size() < sizeof(WinHttpRedirectProxyIpc::MessageHeader)
                + sizeof(WinHttpRedirectProxyIpc::LoadDllReplyPayload))
            {
                return;
            }

            const auto* payload = reinterpret_cast<const WinHttpRedirectProxyIpc::LoadDllReplyPayload*>(
                buffer.data() + sizeof(WinHttpRedirectProxyIpc::MessageHeader));
            if (payload->status == 0)
            {
                AppendLogLine(
                    state,
                    L"[load-ok] pid=" + std::to_wstring(header->pid) + L" path=" + payload->dllPath);
            }
            else
            {
                AppendLogLine(
                    state,
                    L"[load-fail] pid=" + std::to_wstring(header->pid)
                    + L" error=" + std::to_wstring(payload->win32Error)
                    + L" path=" + payload->dllPath
                    + L" text=" + payload->text);
            }
        }
    }

    DWORD WINAPI SessionThreadProc(void* parameter)
    {
        std::unique_ptr<SessionThreadContext> context(static_cast<SessionThreadContext*>(parameter));
        auto state = context->state;
        std::vector<std::uint8_t> buffer;
        while (!state->stopRequested.load() && context->session->connected.load())
        {
            std::wstring dllPath;
            if (TryDequeuePendingLoadDllPath(context->session, dllPath))
            {
                DWORD pid = 0;
                std::wstring processPath;
                GetSessionIdentity(context->session, pid, processPath);
                if (!SendLoadDllRequest(context->session, dllPath))
                {
                    AppendLogLine(*state, L"[load-send-fail] pid=" + std::to_wstring(pid) + L" path=" + dllPath);
                    context->session->connected = false;
                    break;
                }

                AppendLogLine(*state, L"[load-request] pid=" + std::to_wstring(pid) + L" path=" + dllPath);
            }

            if (!TryReadSessionMessage(context->session->pipeHandle, buffer))
            {
                break;
            }

            if (!buffer.empty())
            {
                HandleSessionMessage(*state, context->session, buffer);
                buffer.clear();
                continue;
            }

            if (WaitForSessionActivityOrStop(state, context->session, 15))
            {
                break;
            }
        }

        context->session->connected = false;
        WinHttpRedirectProxyIpc::ClosePipe(context->session->pipeHandle);
        if (context->session->helloReceived.load())
        {
            AppendLogLine(*state, L"[disconnect] " + FormatSessionDisplay(context->session));
        }

        state->sessionsRevision.fetch_add(1);
        PruneSessions(*state);
        return 0;
    }

    DWORD WINAPI AcceptThreadProc(void* parameter)
    {
        std::unique_ptr<AcceptThreadContext> context(static_cast<AcceptThreadContext*>(parameter));
        auto state = context->state;
        AppendLogLine(*state, L"controller listening on named pipe");
        while (!state->stopRequested.load())
        {
            HANDLE pipeHandle = WinHttpRedirectProxyIpc::CreatePipeServerInstance();
            if (pipeHandle == INVALID_HANDLE_VALUE)
            {
                AppendLogLine(*state, L"failed to create named pipe instance");
                if (WaitForControllerStop(state, 1000))
                {
                    break;
                }
                continue;
            }

            if (!WinHttpRedirectProxyIpc::WaitForPipeClient(pipeHandle))
            {
                WinHttpRedirectProxyIpc::ClosePipe(pipeHandle);
                if (!state->stopRequested.load() && WaitForControllerStop(state, 100))
                {
                    break;
                }
                continue;
            }

            auto session = std::make_shared<AgentSession>();
            session->pipeHandle = pipeHandle;
            session->activityEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (session->activityEvent == nullptr)
            {
                session->connected = false;
                WinHttpRedirectProxyIpc::ClosePipe(session->pipeHandle);
                AppendLogLine(*state, L"failed to create session activity event");
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(state->sessionsMutex);
                state->sessions.push_back(session);
            }
            state->sessionsRevision.fetch_add(1);

            auto* sessionContext = new SessionThreadContext();
            sessionContext->state = state;
            sessionContext->session = session;
            const auto thread = CreateThread(nullptr, 0, &SessionThreadProc, sessionContext, 0, nullptr);
            if (thread == nullptr)
            {
                session->connected = false;
                WinHttpRedirectProxyIpc::ClosePipe(session->pipeHandle);
                delete sessionContext;
                AppendLogLine(*state, L"failed to create session thread");
                PruneSessions(*state);
                continue;
            }

            CloseHandle(thread);
        }

        return 0;
    }
}
