#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"

#define MAX_SERVICES 1024
#define TH32CS_SNAPPROCESS 0x00000002
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define TH32CS_SNAPTHREAD 0x00000004
#define SystemProcessInformation 5

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Static arrays moved outside the function
const char* protectionTypes[] = { "None", "Light", "Full" };
const char* protectionSigners[] = { "None", "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem", "App" };

// TYPEDEF
typedef LONG KPRIORITY;

typedef struct {
    DWORD pids[MAX_SERVICES];
    char* names[MAX_SERVICES];
    size_t count;
} servicesArray;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct tagPROCESSENTRY32W {
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD   th32ModuleID;
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;
    LONG    pcPriClassBase;
    DWORD   dwFlags;
    WCHAR   szExeFile[MAX_PATH];
} PROCESSENTRY32W, * PPROCESSENTRY32W;

typedef struct tagTHREADENTRY32W {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG tpBasePri;
    LONG tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32W, * PTHREADENTRY32W, * LPTHREADENTRY32W;

typedef enum {
    ProcessProtectionInformation = 61
} PROCESSINFOCLASS;

typedef struct _PS_PROTECTION {
    UCHAR Level;
    union {
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION;

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* PNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

// Function pointers for KERNEL32
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ProcessIdToSessionId(DWORD, DWORD*);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32FirstW(HANDLE, PROCESSENTRY32W*);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32NextW(HANDLE, PROCESSENTRY32W*);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT BOOL KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32W);
DECLSPEC_IMPORT BOOL KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32W);
WINBASEAPI BOOL WINAPI KERNEL32$QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME lpSystemTime);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI HANDLE   WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);

// Function pointers for MSVCRT
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$atoi(const char* str);

// Function pointers for ADVAPI32
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);


// GLOBAL VARIABLES
DWORD ACCESS_TYPE = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

// FUNCTIONS
void manual_strcpy(char* dest, const char* src, size_t max) {
    size_t i = 0;
    while (i < max - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

char* manual_strrchr(const char* str, char c) {
    if (str == NULL) return NULL;
    const char* last = NULL;
    while (*str != '\0') {
        if (*str == c) last = str;
        str++;
    }
    return (char*)last;
}

void manual_wcsncpy(wchar_t* dest, const wchar_t* src, size_t max) {
    size_t i = 0;
    while (i < max - 1 && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
}

void ushort_to_hex4(WORD value, char* output) {
    const char* hex = "0123456789abcdef";
    output[0] = hex[(value >> 12) & 0xF];
    output[1] = hex[(value >> 8) & 0xF];
    output[2] = hex[(value >> 4) & 0xF];
    output[3] = hex[(value) & 0xF];
    output[4] = '\0';
}

size_t manual_strlen(const char* str) {
    size_t len = 0;
    while (*str++) len++;
    return len;
}

BOOL checkAdmin(HMODULE hAdvapi32) {
    if (BeaconIsAdmin()) {
        HANDLE hToken;
        if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            LUID luid;
            if (ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
                TOKEN_PRIVILEGES tp = { 1 };
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
            }
            KERNEL32$CloseHandle(hToken);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "User has ADMINISTRATOR token: SeDebugPrivilege enabled.\n");
        return TRUE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "User does not have ADMINISTRATOR token.\n");
    return FALSE;
}

void addServiceToArray(servicesArray* array, DWORD pid, const char* name) {
    if (array->count >= MAX_SERVICES) return;
    array->pids[array->count] = pid;
    char* dup = (char*)MSVCRT$malloc(manual_strlen(name) + 1);
    if (dup) {
        manual_strcpy(dup, name, manual_strlen(name) + 1);
        array->names[array->count] = dup;
    }
    array->count++;
}

void enumerateServices(HMODULE hAdvapi32, servicesArray* svcArr) {
    SC_HANDLE scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { return; }

    DWORD needed = 0, returned = 0, resume = 0;
    LPBYTE buf = NULL;

    if (!ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &needed, &returned, &resume, NULL) && KERNEL32$GetLastError() != ERROR_MORE_DATA) {
        KERNEL32$CloseHandle(scm);
        return;
    }

    buf = (LPBYTE)MSVCRT$calloc(1, needed);
    if (!buf) {
        KERNEL32$CloseHandle(scm);
        return;
    }

    if (!ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf, needed, &needed, &returned, &resume, NULL)) {
        MSVCRT$free(buf);
        KERNEL32$CloseHandle(scm);
        return;
    }

    LPENUM_SERVICE_STATUS_PROCESSA svc = (LPENUM_SERVICE_STATUS_PROCESSA)buf;
    for (DWORD i = 0; i < returned; i++) {
        if (svc[i].lpServiceName) {
            addServiceToArray(svcArr, svc[i].ServiceStatusProcess.dwProcessId, svc[i].lpServiceName);
        }
    }

    MSVCRT$free(buf);
    KERNEL32$CloseHandle(scm);
}

void showServices(servicesArray* sa) {
    if (!sa || sa->count == 0) return;

    formatp output;
    BeaconFormatAlloc(&output, 4096);
    BeaconFormatPrintf(&output, "%-6s %-40s\n%s\n", "PID", "ServiceName", "-----------------------------------------------------------");

    for (DWORD i = 0; i < sa->count; i++) {
        if (sa->pids[i] != 0) {
            BeaconFormatPrintf(&output, "%-6lu %-40s\n", sa->pids[i], sa->names[i] ? sa->names[i] : "<null>");
        }
    }

    char* finalOut = BeaconFormatToString(&output, NULL);
    if (finalOut) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", finalOut);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to format service list\n");
    }
    BeaconFormatFree(&output);
}

void showProcesses(HMODULE hAdvapi32, servicesArray* sa) {
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD cProcesses = 0;
    if (KERNEL32$Process32FirstW(hSnapshot, &pe)) {
        do {
            cProcesses++;
        } while (KERNEL32$Process32NextW(hSnapshot, &pe));
    }

    formatp output;
    DWORD bufferSize = 4096;
    BeaconFormatAlloc(&output, bufferSize);
    BeaconFormatPrintf(&output, "Enumerated %lu processes\n", cProcesses);
    BeaconFormatPrintf(&output, "%-6s %-50s %-40s %-10s %-20s\n", "PID", "ProcessName", "User", "Session", "Service");

    if (!KERNEL32$Process32FirstW(hSnapshot, &pe)) {
        BeaconFormatFree(&output);
        KERNEL32$CloseHandle(hSnapshot);
        return;
    }

    do {
        char processName[MAX_PATH] = "<unknown>";
        char username[256] = "";
        char svc[MAX_PATH] = "";
        DWORD sessionId = 0;

        HANDLE hProcess = KERNEL32$OpenProcess(ACCESS_TYPE, FALSE, pe.th32ProcessID);
        if (!hProcess) continue;

        int len = KERNEL32$WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, processName, MAX_PATH, NULL, NULL);
        if (len > 0) {
            char* p = manual_strrchr(processName, '\\');
            if (p) manual_strcpy(processName, p + 1, MAX_PATH);
        }

        HANDLE hToken;
        if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            BYTE buffer[1024];
            DWORD size = sizeof(buffer);
            if (ADVAPI32$GetTokenInformation(hToken, TokenUser, buffer, size, &size)) {
                TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;
                char name[256], domain[256];
                DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
                SID_NAME_USE sidType;
                if (ADVAPI32$LookupAccountSidA(NULL, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
                    formatp userFmt;
                    BeaconFormatAlloc(&userFmt, 256);
                    BeaconFormatPrintf(&userFmt, "%s\\%s", domain, name);
                    char* formatted = BeaconFormatToString(&userFmt, NULL);
                    manual_strcpy(username, formatted, sizeof(username));
                    BeaconFormatFree(&userFmt);
                }
            }
            KERNEL32$CloseHandle(hToken);
        }

        KERNEL32$ProcessIdToSessionId(pe.th32ProcessID, &sessionId);

        for (DWORD j = 0; j < sa->count; j++) {
            if (pe.th32ProcessID == sa->pids[j]) {
                manual_strcpy(svc, sa->names[j], sizeof(svc));
                break;
            }
        }

        // Ensure buffer resizing
        size_t lineLen = 256;
        char* current = BeaconFormatToString(&output, NULL);
        size_t currentLen = current ? manual_strlen(current) : 0;
        if (currentLen + lineLen + 1 > bufferSize) {
            bufferSize *= 2;
            formatp newOutput;
            BeaconFormatAlloc(&newOutput, bufferSize);
            if (current) {
                BeaconFormatPrintf(&newOutput, "%s", current);
            }
            BeaconFormatFree(&output);
            output = newOutput;
        }

        //Print line
        BeaconFormatPrintf(&output, "%-6lu %-50s %-40s %-10lu %-20s\n",
            pe.th32ProcessID, processName, username, sessionId, svc);

        KERNEL32$CloseHandle(hProcess);
    } while (KERNEL32$Process32NextW(hSnapshot, &pe));

    char* finalOut = BeaconFormatToString(&output, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", finalOut);
    BeaconFormatFree(&output);
    KERNEL32$CloseHandle(hSnapshot);
}

void findProcess(char* charPname) {
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) { return; }

    wchar_t processName[260];
    if (!KERNEL32$MultiByteToWideChar(CP_ACP, 0, charPname, -1, processName, 260)) {
        KERNEL32$CloseHandle(hSnapshot);
        return;
    }

    PROCESSENTRY32W pe = { sizeof(pe) };
    BOOL found = FALSE;

    formatp output;
    BeaconFormatAlloc(&output, 4096);

    if (KERNEL32$Process32FirstW(hSnapshot, &pe)) {
        do {
            if (MSVCRT$_wcsicmp(pe.szExeFile, processName) == 0) {
                if (!found) {
                    BeaconFormatPrintf(&output, "Process '%s' found PIDs:\n", charPname);
                    found = TRUE;
                }

                BOOL isAdmin = FALSE;
                HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    HANDLE hToken = NULL;
                    if (ADVAPI32$OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                        TOKEN_ELEVATION elevation;
                        DWORD size;
                        if (ADVAPI32$GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                            isAdmin = elevation.TokenIsElevated;
                        }
                        KERNEL32$CloseHandle(hToken);
                    }
                    KERNEL32$CloseHandle(hProc);
                }

                BeaconFormatPrintf(&output, "%lu%s\n", pe.th32ProcessID, isAdmin ? " [admin]" : "");
            }
        } while (KERNEL32$Process32NextW(hSnapshot, &pe));
    }

    if (found) {
        char* finalOut = BeaconFormatToString(&output, NULL);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", finalOut);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Process '%s' not found.\n", charPname);
    }

    BeaconFormatFree(&output);
    KERNEL32$CloseHandle(hSnapshot);
}

int threadInfo(DWORD pid) {
    THREADENTRY32W te = { sizeof(te) };
    BOOL threadsFound = FALSE;
    BOOL fail = FALSE;

    PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    PNtQueryInformationThread NtQueryInformationThread = (PNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!NtQuerySystemInformation || !NtQueryInformationThread) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve required functions.\n");
        return 1;
    }

    DWORD bufferSize = 0x4096;
    PVOID buffer = NULL;
    NTSTATUS status;

    // Allocate buffer for system process information
    do {
        if (buffer) MSVCRT$free(buffer);
        buffer = MSVCRT$malloc(bufferSize);
        if (!buffer) { return 1; }

        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        MSVCRT$free(buffer);
        BeaconPrintf(CALLBACK_ERROR, "NtQuerySystemInformation failed: 0x%08X\n", status);
        return 1;
    }

    // Create a snapshot of all threads
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        MSVCRT$free(buffer);
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed: %u\n", KERNEL32$GetLastError());
        return 1;
    }

    formatp output;
    BeaconFormatAlloc(&output, 4096);


    // Enumerate threads
    if (KERNEL32$Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                threadsFound = TRUE;

                ULONG_PTR startAddress = 0;
                HANDLE hThread = KERNEL32$OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread == NULL) {
                    fail = TRUE;
                    //BeaconPrintf(CALLBACK_ERROR, "Failed to open thread %u: %u\n", te.th32ThreadID, KERNEL32$GetLastError());
                }
                else {
                    //NtQueryInformationThread get info
                    NTSTATUS threadStatus = NtQueryInformationThread(hThread, 9, &startAddress, sizeof(startAddress), NULL);
                    if (!NT_SUCCESS(threadStatus)) {
                        BeaconPrintf(CALLBACK_ERROR, "NtQueryInformationThread failed for thread %u: 0x%08X\n", te.th32ThreadID, threadStatus);
                        startAddress = 0;
                    }
                    KERNEL32$CloseHandle(hThread);
                }

                //Parse status info
                PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
                while (TRUE) {
                    if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
                        for (DWORD i = 0; i < spi->NumberOfThreads; i++) {
                            if ((DWORD)(ULONG_PTR)spi->Threads[i].ClientId.UniqueThread == te.th32ThreadID) {
                                const char* stateStr = "Unknown";
                                if (spi->Threads[i].ThreadState == 0) { stateStr = "Initialized"; }
                                else if (spi->Threads[i].ThreadState == 1) { stateStr = "Ready"; }
                                else if (spi->Threads[i].ThreadState == 2) { stateStr = "Running"; }
                                else if (spi->Threads[i].ThreadState == 3) { stateStr = "Standby"; }
                                else if (spi->Threads[i].ThreadState == 4) { stateStr = "Terminated"; }
                                else if (spi->Threads[i].ThreadState == 5) { stateStr = "Waiting"; }
                                else if (spi->Threads[i].ThreadState == 6) { stateStr = "Transition"; }
                                else if (spi->Threads[i].ThreadState == 7) { stateStr = "Deferred"; }

                                BeaconFormatPrintf(&output, "Thread ID: %-6u | Base Pri: %-2ld | State: %-10s | StartAddr: 0x%p\n",
                                    te.th32ThreadID,
                                    te.tpBasePri,
                                    stateStr,
                                    (PVOID)startAddress 
                                );
                                break;
                            }
                        }
                        break;
                    }
                    if (spi->NextEntryOffset == 0) break;
                    spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
                }
            }
        } while (KERNEL32$Thread32Next(hSnapshot, &te));
    }

    if (threadsFound) {
        char* finalOut = BeaconFormatToString(&output, NULL);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", finalOut);
    }
    else {
        BeaconFormatPrintf(&output, "No threads found for process %u.\n", pid);
        char* finalOut = BeaconFormatToString(&output, NULL);
        BeaconPrintf(CALLBACK_ERROR, "%s", finalOut);
    }

    if (fail) BeaconPrintf(CALLBACK_ERROR, "The program could not read process threads\n");

    BeaconFormatFree(&output);
    KERNEL32$CloseHandle(hSnapshot);
    MSVCRT$free(buffer);

    return 0;
}

char* getDescription(HANDLE hProcess) {
    char* description = (char*)MSVCRT$malloc(MAX_PATH);
    manual_strcpy(description, "<no description>", MAX_PATH);

    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!KERNEL32$QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        return description;
    }

    HMODULE hVer = KERNEL32$GetModuleHandleA("version.dll");
    if (!hVer) {
        hVer = KERNEL32$LoadLibraryA("version.dll");
        if (!hVer) {
            return description;
        }
    }

    //HAd to use this way -> sprintf and _sprintf give problems
    DWORD(WINAPI * pGetFileVersionInfoSizeA)(LPCSTR, LPDWORD) = (DWORD(WINAPI*)(LPCSTR, LPDWORD))KERNEL32$GetProcAddress(hVer, "GetFileVersionInfoSizeA");
    BOOL(WINAPI * pGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID) = (BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID))KERNEL32$GetProcAddress(hVer, "GetFileVersionInfoA");
    BOOL(WINAPI * pVerQueryValueA)(LPCVOID, LPCSTR, LPVOID*, PUINT) = (BOOL(WINAPI*)(LPCVOID, LPCSTR, LPVOID*, PUINT))KERNEL32$GetProcAddress(hVer, "VerQueryValueA");
    if (!pGetFileVersionInfoSizeA || !pGetFileVersionInfoA || !pVerQueryValueA) { return description; }

    DWORD dummy = 0, verSize = pGetFileVersionInfoSizeA(path, &dummy);
    if (verSize == 0) { return description; }

    LPVOID verData = MSVCRT$malloc(verSize);
    if (!verData) { return description; }

    if (!pGetFileVersionInfoA(path, 0, verSize, verData)) {
        MSVCRT$free(verData);
        return description;
    }

    struct LANGANDCODEPAGE { WORD wLanguage, wCodePage; } *lpTrans = NULL;
    UINT cbTrans = 0;
    if (!pVerQueryValueA(verData, "\\VarFileInfo\\Translation", (LPVOID*)&lpTrans, &cbTrans) ||
        cbTrans < sizeof(*lpTrans)) {
        MSVCRT$free(verData);
        return description;
    }

    char langHex[5], codePageHex[5];
    ushort_to_hex4(lpTrans->wLanguage, langHex);
    ushort_to_hex4(lpTrans->wCodePage, codePageHex);

    char subBlock[64];
    size_t len = 0;
    MSVCRT$memcpy(subBlock + len, "\\StringFileInfo\\", 16);  len += 16;
    MSVCRT$memcpy(subBlock + len, langHex, 4);  len += 4;
    MSVCRT$memcpy(subBlock + len, codePageHex, 4);   len += 4;
    MSVCRT$memcpy(subBlock + len, "\\FileDescription", 16);   len += 16;
    subBlock[len] = '\0';

    LPSTR value = NULL;
    UINT valueLen = 0;
    if (pVerQueryValueA(verData, subBlock, (LPVOID*)&value, &valueLen) && valueLen > 0) {
        manual_strcpy(description, value, MAX_PATH);
    }

    MSVCRT$free(verData);
    return description;
}

char* getProtection(HANDLE hProcess, DWORD pid) {
    formatp buffer;
    BeaconFormatAlloc(&buffer, 64);
    char* finalResult = NULL;

    typedef NTSTATUS(NTAPI* PZwQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    PZwQueryInformationProcess ZwQueryInformationProcess = hNtdll ? (PZwQueryInformationProcess)KERNEL32$GetProcAddress(hNtdll, "ZwQueryInformationProcess") : NULL;

    if (!hNtdll || !ZwQueryInformationProcess) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve ZwQueryInformationProcess for PID %lu", pid);
        BeaconFormatFree(&buffer);
        return NULL;
    }

    // Reopen process with minimal permissions to ensure handle validity
    HANDLE hQueryProcess = hProcess;
    if (!hProcess) {
        hQueryProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hQueryProcess) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to open process handle for PID %lu: Error %lu", pid, KERNEL32$GetLastError());
            BeaconFormatPrintf(&buffer, "<unavailable>");
            finalResult = (char*)MSVCRT$malloc(manual_strlen("<unavailable>") + 1);
            if (finalResult) {
                manual_strcpy(finalResult, "<unavailable>", manual_strlen("<unavailable>") + 1);
            }
            BeaconFormatFree(&buffer);
            return finalResult;
        }
    }

    PS_PROTECTION prot = { 0 };
    NTSTATUS status = ZwQueryInformationProcess(hQueryProcess, ProcessProtectionInformation, &prot, sizeof(prot), NULL);
    const char* result = NULL;

    if (!NT_SUCCESS(status)) {  result = "<unavailable>"; }
    else {
        // Manually extract Type and Signer
        UCHAR type = prot.Level & 0x07;
        UCHAR signer = (prot.Level >> 4) & 0x0F;
        const char* typeStr = type < 3 ? protectionTypes[type] : "Unknown";
        const char* signerStr = signer < 9 ? protectionSigners[signer] : "Unknown";
        BeaconFormatPrintf(&buffer, "%s (Signer: %s)", typeStr, signerStr);
        result = BeaconFormatToString(&buffer, NULL);
    }

    if (result) {
        size_t len = manual_strlen(result) + 1;
        finalResult = (char*)MSVCRT$malloc(len);
        if (finalResult) {
            manual_strcpy(finalResult, result, len);
        }
    }

    if (hQueryProcess != hProcess) {
        KERNEL32$CloseHandle(hQueryProcess);
    }
    BeaconFormatFree(&buffer);
    return finalResult;
}

int getProcessInfo(DWORD pid, servicesArray* sa) {
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    // Create process snapshot
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create process snapshot\n");
        return 1;
    }

    // Find the process in the snapshot
    BOOL found = FALSE;
    if (!KERNEL32$Process32FirstW(hSnapshot, &pe)) {
        BeaconPrintf(CALLBACK_ERROR, "Can't enumerate processes\n");
        KERNEL32$CloseHandle(hSnapshot);
        return 1;
    }

    do {
        if (pe.th32ProcessID == pid) {
            found = TRUE;
            break;
        }
    } while (KERNEL32$Process32NextW(hSnapshot, &pe));

    if (!found) {
        BeaconPrintf(CALLBACK_ERROR, "No process found with PID %lu\n", pid);
        KERNEL32$CloseHandle(hSnapshot);
        return 1;
    }

    // Attempt to open process with ACCESS_TYPE, LIMITED if not
    HANDLE hProcess = KERNEL32$OpenProcess(ACCESS_TYPE, FALSE, pid);
    if (!hProcess) {
        hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            DWORD err = KERNEL32$GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                BeaconPrintf(CALLBACK_ERROR, "Access denied opening process %lu. It may be a protected system process.\n", pid);
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "Unable to open process %lu (Error: %lu)\n", pid, err);
            }
        }
    }

    //ParentName
    char* exePath = (char*)MSVCRT$malloc(MAX_PATH);
    manual_strcpy(exePath, "<unknown>", MAX_PATH);
    wchar_t* parentName = (wchar_t*)MSVCRT$malloc(MAX_PATH * sizeof(wchar_t));
    if (!parentName) {
        MSVCRT$free(exePath);
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure\n");
        if (hProcess) KERNEL32$CloseHandle(hProcess);
        KERNEL32$CloseHandle(hSnapshot);
        return 1;
    }
    manual_wcsncpy(parentName, L"<unknown>", MAX_PATH);

    //Description
    char* description = (char*)MSVCRT$malloc(MAX_PATH);
    if (!description) {
        MSVCRT$free(exePath);
        MSVCRT$free(parentName);
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure\n");
        if (hProcess) KERNEL32$CloseHandle(hProcess);
        KERNEL32$CloseHandle(hSnapshot);
        return 1;
    }
    manual_strcpy(description, "<unavailable>", MAX_PATH);

    //Username
    char* username = (char*)MSVCRT$malloc(256);
    if (!username) {
        MSVCRT$free(exePath);
        MSVCRT$free(parentName);
        MSVCRT$free(description);
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure\n");
        if (hProcess) KERNEL32$CloseHandle(hProcess);
        KERNEL32$CloseHandle(hSnapshot);
        return 1;
    }
    manual_strcpy(username, "<unavailable>", 256);


    //Service
    DWORD sessionID = 0;
    char* svc = (char*)MSVCRT$malloc(MAX_PATH);
    if (!svc) {
        MSVCRT$free(exePath);
        MSVCRT$free(parentName);
        MSVCRT$free(description);
        MSVCRT$free(username);
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure\n");
        if (hProcess) KERNEL32$CloseHandle(hProcess);
        KERNEL32$CloseHandle(hSnapshot);
        return 1;
    }
    svc[0] = '\0';

    //Full path
    if (hProcess) {
        DWORD len = MAX_PATH;
        if (!KERNEL32$QueryFullProcessImageNameA(hProcess, 0, exePath, &len)) {
            manual_strcpy(exePath, "<access denied>", MAX_PATH);
        }
        const char* descStr = getDescription(hProcess);
        manual_strcpy(description, descStr, MAX_PATH);
    }
    else {
        manual_strcpy(exePath, "<access denied>", MAX_PATH);
        manual_strcpy(description, "<unavailable>", MAX_PATH);
    }

    //Get token info
    if (hProcess) {
        HANDLE hToken = NULL;
        if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            BYTE* buffer = (BYTE*)MSVCRT$malloc(1024);
            if (buffer) {
                DWORD size = 1024;
                if (ADVAPI32$GetTokenInformation(hToken, TokenUser, buffer, size, &size)) {
                    TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;
                    SID_NAME_USE sidType;
                    char* name = (char*)MSVCRT$malloc(256);
                    char* domain = (char*)MSVCRT$malloc(256);
                    if (name && domain) {
                        DWORD nameLen = 256, domainLen = 256;
                        if (ADVAPI32$LookupAccountSidA(NULL, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
                            formatp fmtBufferUser;
                            BeaconFormatAlloc(&fmtBufferUser, 256);
                            BeaconFormatPrintf(&fmtBufferUser, "%s\\%s", domain, name);
                            char* formatted = BeaconFormatToString(&fmtBufferUser, NULL);
                            manual_strcpy(username, formatted, 256);
                            BeaconFormatFree(&fmtBufferUser);
                        }
                    }
                    if (name) MSVCRT$free(name);
                    if (domain) MSVCRT$free(domain);
                }
                MSVCRT$free(buffer);
            }
            KERNEL32$CloseHandle(hToken);
        }
    }

    // Get session ID
    KERNEL32$ProcessIdToSessionId(pe.th32ProcessID, &sessionID);

    //SessionID
    for (size_t i = 0; i < sa->count; i++) {
        if (pe.th32ProcessID == sa->pids[i]) {
            manual_strcpy(svc, sa->names[i], MAX_PATH);
            break;
        }
    }

    //Parent Process Name (Description)
    if (pe.th32ParentProcessID != 0) {
        PROCESSENTRY32W* parentPE = (PROCESSENTRY32W*)MSVCRT$malloc(sizeof(PROCESSENTRY32W));
        if (parentPE) {
            parentPE->dwSize = sizeof(PROCESSENTRY32W);
            HANDLE hSnapParent = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapParent != INVALID_HANDLE_VALUE) {
                if (KERNEL32$Process32FirstW(hSnapParent, parentPE)) {
                    do {
                        if (parentPE->th32ProcessID == pe.th32ParentProcessID) {
                            manual_wcsncpy(parentName, parentPE->szExeFile, MAX_PATH);
                            break;
                        }
                    } while (KERNEL32$Process32NextW(hSnapParent, parentPE));
                }
                KERNEL32$CloseHandle(hSnapParent);
            }
            MSVCRT$free(parentPE);
        }
    }

    //Check if admin
    char procName[MAX_PATH] = "<unknown>";
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, procName, MAX_PATH, NULL, NULL);
    BOOL isAdmin = FALSE;
    if (hProcess) {
        HANDLE hToken = NULL;
        if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size;
            if (ADVAPI32$GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isAdmin = elevation.TokenIsElevated;
            }
            KERNEL32$CloseHandle(hToken);
        }
    }

    formatp procNameBuffer;
    BeaconFormatAlloc(&procNameBuffer, 256);
    BeaconFormatPrintf(&procNameBuffer, "%s%s", procName, isAdmin ? " [admin]" : "");
    char* procNameWithAdmin = BeaconFormatToString(&procNameBuffer, NULL);

    // Get protection info
    const char* protectionInfo = getProtection(hProcess, pid);

    // Format output
    formatp output;
    BeaconFormatAlloc(&output, 4096);
    BeaconFormatPrintf(&output,
        "Process Info\n"
        "---------------\n"
        "Process name: %s\n"
        "PID: %lu\n\n"
        "General Info\n"
        "---------------\n"
        "Parent Name: %ls\n"
        "Parent PID: %lu\n"
        "Username: %s\n"
        "SessionID: %lu\n"
        "Binary Description: %s\n"
        "Executable Path: %s\n"
        "Protection Type: %s\n",
        procNameWithAdmin,
        pe.th32ProcessID,
        parentName,
        pe.th32ParentProcessID,
        username,
        sessionID,
        description,
        exePath,
        protectionInfo);

    if (svc[0]) {
        BeaconFormatPrintf(&output, "Service Name: %s\n", svc);
    }

    BeaconFormatPrintf(&output,
        "Thread Count: %lu\n"
        "Priority Base: %ld\n\n"
        "Threads Info\n"
        "---------------\n",
        pe.cntThreads,
        pe.pcPriClassBase);

    char* finalOutput = BeaconFormatToString(&output, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", finalOutput);

    // Get thread info
    threadInfo(pe.th32ProcessID);

    // Cleanup
    BeaconFormatFree(&output);
    BeaconFormatFree(&procNameBuffer);
    if (svc) MSVCRT$free(svc);
    if (username) MSVCRT$free(username);
    if (description) MSVCRT$free(description);
    if (parentName) MSVCRT$free(parentName);
    if (exePath) MSVCRT$free(exePath);
    if (hProcess) KERNEL32$CloseHandle(hProcess);
    if (hSnapshot) KERNEL32$CloseHandle(hSnapshot);

    return 0;
}

void showHelp() {
    BeaconPrintf(CALLBACK_OUTPUT, "\n \
        Process Thread Enumerator (by K43M1S)\n \
        ------------------------------------------------\n \
        Usage:\n \
        -ps                     Show all running processes\n \
        -ss                     Show all running services\n \
        -f <ProcessName>        Find process by name and show PID\n \
        -i <PID>                Show process info by PID\n \
        -w <PID> <Iterations>   Watch process threads\n");
}

void go(char* args, int len) {
    HMODULE hEtw = KERNEL32$LoadLibraryA("Advapi32.dll");
    if (!hEtw) {
        BeaconPrintf(CALLBACK_ERROR, "Error loading Advapi32.dll");
        return;
    }

    char* buffer = (char*)MSVCRT$calloc(len + 1, 1);
    if (!buffer) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to parse arguments.\n");
        KERNEL32$FreeLibrary(hEtw);
        return;
    }

    //INPUT MANAGEMENT
    MSVCRT$memcpy(buffer, args, len);
    buffer[len] = '\0';

    char* cmd = buffer;
    char* arg1 = NULL;
    char* arg2 = NULL;
    char* pos = buffer;
    while (*pos && *pos != ' ') pos++;
    if (*pos == ' ') {
        *pos = '\0';
        arg1 = pos + 1;
        pos = arg1;
        while (*pos && *pos != ' ') pos++;
        if (*pos == ' ') {
            *pos = '\0';
            arg2 = pos + 1;
        }
    }

    //Check if admin
    checkAdmin(hEtw);

    //Create service list
    servicesArray* sa = (servicesArray*)MSVCRT$calloc(1, sizeof(servicesArray));
    enumerateServices(hEtw, sa);

    if (cmd[0] == '-' && cmd[1] == 'i' && cmd[2] == '\0' && arg1) {
        getProcessInfo((DWORD)MSVCRT$atoi(arg1), sa);
    }
    else if (cmd[0] == '-' && cmd[1] == 'w' && cmd[2] == '\0' && arg1 && arg2) {
        for (int i = 0; i < (int)MSVCRT$atoi(arg2); i++) {
            threadInfo((DWORD)MSVCRT$atoi(arg1));
            KERNEL32$Sleep(1000);
        }
    }
    else if (cmd[0] == '-' && cmd[1] == 'p' && cmd[2] == 's' && cmd[3] == '\0') {
        showProcesses(hEtw, sa);
    }
    else if (cmd[0] == '-' && cmd[1] == 's' && cmd[2] == 's' && cmd[3] == '\0') {
        showServices(sa);
    }
    else if (cmd[0] == '-' && cmd[1] == 'f' && cmd[2] == '\0' && arg1) {
        findProcess(arg1);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Invalid options.\n");
        showHelp();
    }

    for (size_t i = 0; i < sa->count; i++) {
        if (sa->names[i]) MSVCRT$free(sa->names[i]);
    }
    MSVCRT$free(sa);
    MSVCRT$free(buffer);
    KERNEL32$FreeLibrary(hEtw);
}
}