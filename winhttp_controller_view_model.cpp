#include "pch.h"
#include "winhttp_controller_view_model.hpp"

#include "winhttp_controller_pipe_discovery.hpp"

namespace WinHttpRedirectController
{
    namespace
    {
        ControllerDisplayRow* FindRowByPid(std::vector<ControllerDisplayRow>& rows, DWORD pid)
        {
            const auto iterator = std::find_if(
                rows.begin(),
                rows.end(),
                [pid](const ControllerDisplayRow& row)
                {
                    return row.pid == pid;
                });
            return iterator != rows.end() ? &(*iterator) : nullptr;
        }

        void RefreshChannelText(ControllerDisplayRow& row)
        {
            if (row.controlSession != nullptr && row.hasMemoryIpc)
            {
                row.channelText = L"Control + Memory IPC";
                return;
            }

            if (row.controlSession != nullptr)
            {
                row.channelText = L"Control";
                return;
            }

            row.channelText = L"Memory IPC only";
        }
    }

    std::vector<ControllerDisplayRow> BuildControllerDisplayRows(ControllerState& state)
    {
        std::vector<ControllerDisplayRow> rows;

        for (const auto& session : SnapshotSessions(state))
        {
            DWORD pid = 0;
            std::wstring processPath;
            GetSessionIdentity(session, pid, processPath);
            if (pid == 0)
            {
                continue;
            }

            ControllerDisplayRow row = {};
            row.pid = pid;
            row.processPath = processPath.empty() ? L"(process path unavailable)" : processPath;
            row.controlSession = session;
            RefreshChannelText(row);
            rows.push_back(std::move(row));
        }

        for (const auto& endpoint : DiscoverMemoryIpcEndpoints())
        {
            ControllerDisplayRow* row = FindRowByPid(rows, endpoint.pid);
            if (row == nullptr)
            {
                ControllerDisplayRow memoryOnlyRow = {};
                memoryOnlyRow.pid = endpoint.pid;
                memoryOnlyRow.processPath = L"(control session not connected)";
                memoryOnlyRow.hasMemoryIpc = true;
                RefreshChannelText(memoryOnlyRow);
                rows.push_back(std::move(memoryOnlyRow));
                continue;
            }

            row->hasMemoryIpc = true;
            RefreshChannelText(*row);
        }

        std::sort(
            rows.begin(),
            rows.end(),
            [](const ControllerDisplayRow& left, const ControllerDisplayRow& right)
            {
                return left.pid < right.pid;
            });
        return rows;
    }

    std::wstring BuildControllerDisplaySignature(
        std::uint64_t sessionsRevision,
        const std::vector<ControllerDisplayRow>& rows)
    {
        std::wstring signature = std::to_wstring(sessionsRevision);
        for (const auto& row : rows)
        {
            signature += L"|";
            signature += std::to_wstring(row.pid);
            signature += row.controlSession != nullptr ? L":C" : L":-";
            signature += row.hasMemoryIpc ? L":M:" : L":-:";
            signature += row.processPath;
            signature += L":";
            signature += row.channelText;
        }

        return signature;
    }

    std::size_t CountControlRows(const std::vector<ControllerDisplayRow>& rows)
    {
        return static_cast<std::size_t>(std::count_if(
            rows.begin(),
            rows.end(),
            [](const ControllerDisplayRow& row)
            {
                return row.controlSession != nullptr;
            }));
    }

    std::size_t CountMemoryIpcRows(const std::vector<ControllerDisplayRow>& rows)
    {
        return static_cast<std::size_t>(std::count_if(
            rows.begin(),
            rows.end(),
            [](const ControllerDisplayRow& row)
            {
                return row.hasMemoryIpc;
            }));
    }
}
