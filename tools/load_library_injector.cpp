#include <windows.h>

#include <cwchar>
#include <iostream>
#include <string>

namespace
{
    bool ParsePid(const wchar_t* text, DWORD& pid)
    {
        if (text == nullptr || *text == L'\0')
        {
            return false;
        }

        wchar_t* end = nullptr;
        const unsigned long value = std::wcstoul(text, &end, 0);
        if (end == text || (end != nullptr && *end != L'\0') || value == 0)
        {
            return false;
        }

        pid = static_cast<DWORD>(value);
        return true;
    }

    std::wstring GetFullPathOrOriginal(const wchar_t* path)
    {
        std::wstring buffer(32768, L'\0');
        const DWORD length = GetFullPathNameW(path, static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (length == 0 || length >= buffer.size())
        {
            return path;
        }

        buffer.resize(length);
        return buffer;
    }

    void EnableDebugPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            return;
        }

        LUID luid = {};
        if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid))
        {
            CloseHandle(token);
            return;
        }

        TOKEN_PRIVILEGES privileges = {};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
        CloseHandle(token);
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 3)
    {
        std::wcerr << L"Usage: load_library_injector.exe <pid> <dll-path>\n";
        return 1;
    }

    DWORD pid = 0;
    if (!ParsePid(argv[1], pid))
    {
        std::wcerr << L"Invalid pid\n";
        return 2;
    }

    const std::wstring dllPath = GetFullPathOrOriginal(argv[2]);
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcerr << L"DLL not found: " << dllPath << L"\n";
        return 3;
    }

    EnableDebugPrivilege();

    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr)
    {
        std::wcerr << L"OpenProcess failed: " << GetLastError() << L"\n";
        return 4;
    }

    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remotePath == nullptr)
    {
        std::wcerr << L"VirtualAllocEx failed: " << GetLastError() << L"\n";
        CloseHandle(process);
        return 5;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remotePath, dllPath.c_str(), bytes, &written) || written != bytes)
    {
        std::wcerr << L"WriteProcessMemory failed: " << GetLastError() << L" written=" << written << L" expected=" << bytes << L"\n";
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return 6;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto* loadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
    if (loadLibraryW == nullptr)
    {
        std::wcerr << L"GetProcAddress(LoadLibraryW) failed: " << GetLastError() << L"\n";
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return 7;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibraryW, remotePath, 0, nullptr);
    if (thread == nullptr)
    {
        std::wcerr << L"CreateRemoteThread failed: " << GetLastError() << L"\n";
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return 8;
    }

    const DWORD wait = WaitForSingleObject(thread, 60000);
    DWORD remoteModule = 0;
    GetExitCodeThread(thread, &remoteModule);

    CloseHandle(thread);
    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    CloseHandle(process);

    if (wait != WAIT_OBJECT_0)
    {
        std::wcerr << L"WaitForSingleObject failed or timed out: " << wait << L"\n";
        return 9;
    }

    if (remoteModule == 0)
    {
        std::wcerr << L"LoadLibraryW returned null\n";
        return 10;
    }

    std::wcout << L"LoadLibraryW OK pid=" << pid << L" module=0x" << std::hex << remoteModule << L" path=" << dllPath << L"\n";
    return 0;
}
