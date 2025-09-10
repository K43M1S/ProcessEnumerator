#include <windows.h>
#include <winver.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

DWORD ACCESS_TYPE = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

#define MAX_SERVICES 1024
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct {
	DWORD pids[MAX_SERVICES];
	char* names[MAX_SERVICES];
	size_t count;
} servicesArray;

typedef LONG KPRIORITY;
typedef int PROCESSINFOCLASS;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _PS_PROTECTION {
	UCHAR Type : 3;
	UCHAR Audit : 1;
	UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER   KernelTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   CreateTime;
	ULONG           WaitTime;
	PVOID           StartAddress;
	CLIENT_ID       ClientId;
	LONG            Priority;
	LONG            BasePriority;
	ULONG           ContextSwitches;
	ULONG           ThreadState;
	ULONG           WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
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

typedef NTSTATUS(NTAPI* PNtQueryInformationThread)(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* PFN_ZwQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


//################################################################################//

BOOL isRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&ntAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &adminGroup)) {

		CheckTokenMembership(NULL, adminGroup, &isAdmin);
		FreeSid(adminGroup);
	}
	return isAdmin;
}

BOOL enableDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	printf("User is Administrator: seDebugPrivilege enabled\n");
	CloseHandle(hToken);

	return result && GetLastError() == ERROR_SUCCESS;
}

void addServiceToArray(servicesArray* array, DWORD pid, const char* name) {
	if (array->count >= MAX_SERVICES) return;
	array->pids[array->count] = pid;
	array->names[array->count] = _strdup(name);
	array->count++;
}

void enumerateServices(servicesArray* serviceArray) {
	SC_HANDLE hSCManager;
	LPBYTE lpBuffer = NULL;
	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;
	DWORD dwBufferSize = 0;

	// Open Service Control Manager
	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (!hSCManager) { return;}

	// Determine required buffer size
	EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded,&dwServicesReturned, &dwResumeHandle, NULL);
	if (GetLastError() != ERROR_MORE_DATA) {
		CloseServiceHandle(hSCManager);
		return;
	}

	// Allocate the buffer
	dwBufferSize = dwBytesNeeded;
	lpBuffer = (LPBYTE)calloc(dwBufferSize, sizeof(char));
	if (!lpBuffer) {
		CloseServiceHandle(hSCManager);
		return;
	}

	// Enumerate services
	if (!EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,SERVICE_STATE_ALL, lpBuffer, dwBufferSize,&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
		free(lpBuffer);
		CloseServiceHandle(hSCManager);
		return;
	}

	LPENUM_SERVICE_STATUS_PROCESSA pServices = (LPENUM_SERVICE_STATUS_PROCESSA)lpBuffer;

	for (DWORD i = 0; i < dwServicesReturned; i++) {
		//printf("%-6lu %-40s\n", pServices[i].ServiceStatusProcess.dwProcessId, pServices[i].lpServiceName);

		addServiceToArray(serviceArray, pServices[i].ServiceStatusProcess.dwProcessId, pServices[i].lpServiceName);
	}

	free(lpBuffer);
	CloseServiceHandle(hSCManager);
}

char* getProtectionInfo(HANDLE hProcess) {
	static char buffer[128];

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		snprintf(buffer, sizeof(buffer), "Unavailable (no ntdll)");
		return buffer;
	}

	PFN_ZwQueryInformationProcess ZwQueryInformationProcess = (PFN_ZwQueryInformationProcess)GetProcAddress(ntdll, "ZwQueryInformationProcess");
	if (!ZwQueryInformationProcess) {
		snprintf(buffer, sizeof(buffer), "Unavailable (GetProcAddress failed)");
		return buffer;
	}

	PS_PROTECTION protectionStruct = { 0 };
	NTSTATUS status = ZwQueryInformationProcess(hProcess,(PROCESSINFOCLASS)61,&protectionStruct,sizeof(protectionStruct),NULL);
	if (status != 0) {
		snprintf(buffer, sizeof(buffer), "Unavailable (0x%08X)", status);
		return buffer;
	}

	const char* typeStr;
	const char* signerStr;

	switch (protectionStruct.Type) {
	case 0: typeStr = "None"; break;
	case 1: typeStr = "ProtectedLight"; break;
	case 2: typeStr = "Protected"; break;
	default: typeStr = "Unknown"; break;
	}

	switch (protectionStruct.Signer) {
	case 0: signerStr = "None"; break;
	case 1: signerStr = "Authenticode"; break;
	case 2: signerStr = "CodeGen"; break;
	case 3: signerStr = "Antimalware"; break;
	case 4: signerStr = "LSA"; break;
	case 5: signerStr = "Windows"; break;
	case 6: signerStr = "WinTcb"; break;
	case 7: signerStr = "WinSystem"; break;
	case 8: signerStr = "App"; break;
	default: signerStr = "Unknown"; break;
	}

	snprintf(buffer, sizeof(buffer), "%s (Signer: %s)", typeStr, signerStr);
	return buffer;
}

void showServices(servicesArray* sa) {
	printf("%-6s %-40s\n", "PID", "ServiceName");
	printf("-----------------------------------------------------------\n");

	for (DWORD i = 0; i <  i < sa->count; i++) {
		if (sa->pids[i] != 0) {
			printf("%-6lu %-40s\n", sa->pids[i], sa->names[i]);
		}
	}

}

void showProcesses(servicesArray* sa) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(pe);

	if (!Process32FirstW(hSnapshot, &pe)) { // Failed
		CloseHandle(hSnapshot);
		return;
	}

	printf("%-6s %-50s %-40s %-10s %-20s\n", "PID", "ProcessName", "User", "Session", "Service");

	do {
		if (pe.th32ProcessID == 0) continue;

		char username[256] = "";
		char svc[MAX_PATH] = "";
		DWORD sid = 0;

		char exeName[MAX_PATH];
		WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);

		HANDLE hProcess = OpenProcess(ACCESS_TYPE, FALSE, pe.th32ProcessID);
		if (!hProcess) { hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID); } // Retry
		if (!hProcess) {
			DWORD err = GetLastError();
			if (err == ERROR_ACCESS_DENIED) {
				fprintf(stderr, "Access denied opening process %lu. It may be a protected system process.\n", pe.th32ProcessID);
			}
			else {
				fprintf(stderr, "Unable to open process %lu (Error: %lu)\n", pe.th32ProcessID, err);
			}
			CloseHandle(hSnapshot);
			return;
		}

		HANDLE hToken;
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
			BYTE buffer[1024];
			DWORD size = sizeof(buffer);
			if (GetTokenInformation(hToken, TokenUser, buffer, size, &size)) {
				TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;
				SID_NAME_USE sidType;
				char name[256], domain[256];
				DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
				if (LookupAccountSidA(NULL, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
					snprintf(username, sizeof(username), "%s\\%s", domain, name);
				}
			}

			ProcessIdToSessionId(pe.th32ProcessID, &sid);

			for (DWORD i = 0; i < sa->count; i++) {
				if (pe.th32ProcessID == sa->pids[i]) {
					strncpy_s(svc, sizeof(svc), sa->names[i], _TRUNCATE);
					break;
				}
			}

			CloseHandle(hToken);
		}
		CloseHandle(hProcess);

		printf("%-6lu %-50s %-40s %-10lu %-20s\n", pe.th32ProcessID, exeName, username, sid, svc);

	} while (Process32NextW(hSnapshot, &pe));

	CloseHandle(hSnapshot);
}

void findProcess(char* processName) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return;
	}

	PROCESSENTRY32W pe = { sizeof(pe) };
	BOOL found = FALSE;

	// Convert char* to wchar_t* (I do not want to use wprintf)
	size_t len = strlen(processName);
	wchar_t* wProcessName = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
	if (!wProcessName) {
		CloseHandle(hSnapshot);
		return;
	}
	MultiByteToWideChar(CP_ACP, 0, processName, -1, wProcessName, (int)(len + 1));

	if (Process32FirstW(hSnapshot, &pe)) {
		for (;;) {
			if (_wcsicmp(pe.szExeFile, wProcessName) == 0) {
				if (!found) {
					// Convert wchar_t* to char* 
					char ansiName[MAX_PATH];
					WideCharToMultiByte(CP_ACP, 0, wProcessName, -1, ansiName, MAX_PATH, NULL, NULL);
					printf("Process '%s' found PIDs:\n", ansiName);
					found = TRUE;
				}

				// Admin check
				BOOL isAdmin = FALSE;
				HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
				if (hProc) {
					HANDLE hToken = NULL;
					if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
						TOKEN_ELEVATION elevation;
						DWORD size;
						if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
							isAdmin = elevation.TokenIsElevated;
						}
						CloseHandle(hToken);
					}
					CloseHandle(hProc);
				}

				printf("%lu%s\n", pe.th32ProcessID, isAdmin ? " [admin]" : "");
			}
			if (!Process32NextW(hSnapshot, &pe)) break;
		}
	}

	if (!found) {
		char ansiName[MAX_PATH];
		WideCharToMultiByte(CP_ACP, 0, wProcessName, -1, ansiName, MAX_PATH, NULL, NULL);
		printf("Process '%s' not found.\n", ansiName);
	}

	free(wProcessName);
	CloseHandle(hSnapshot);
}

int threadInfo(DWORD pid) {
	THREADENTRY32 te = { sizeof(te) };
	BOOL threadsFound = FALSE;
	BOOL allZeroStart = TRUE;

	PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	PNtQueryInformationThread NtQueryInformationThread = (PNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
	if (!NtQuerySystemInformation || !NtQueryInformationThread) {
		fprintf(stderr, "Failed to resolve required functions.\n");
		return 1;
	}

	DWORD bufferSize = 0x10000;
	PVOID buffer = NULL;
	NTSTATUS status;

	do {
		if (buffer) free(buffer);
		buffer = malloc(bufferSize);
		status = NtQuerySystemInformation(5, buffer, bufferSize, &bufferSize);
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status)) {
		fprintf(stderr, "NtQuerySystemInformation failed.\n");
		free(buffer);
		return 1;
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		free(buffer);
		return 1;
	}

	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				threadsFound = TRUE;

				ULONG_PTR startAddress = 0;
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
				if (hThread) {
					NtQueryInformationThread(hThread, 9, &startAddress, sizeof(startAddress), NULL);
					CloseHandle(hThread);
				}

				if (startAddress != 0) {
					allZeroStart = FALSE;
				}

				const char* stateStr = "Unknown";
				PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
				while (TRUE) {
					if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
						for (DWORD i = 0; i < spi->NumberOfThreads; i++) {
							if ((DWORD)(ULONG_PTR)spi->Threads[i].ClientId.UniqueThread == te.th32ThreadID) {
								switch (spi->Threads[i].ThreadState) {
								case 0: stateStr = "Initialized"; break;
								case 1: stateStr = "Ready";       break;
								case 2: stateStr = "Running";     break;
								case 3: stateStr = "Standby";     break;
								case 4: stateStr = "Terminated";  break;
								case 5: stateStr = "Waiting";     break;
								case 6: stateStr = "Transition";  break;
								case 7: stateStr = "Deferred";    break;
								default: stateStr = "Unknown";    break;
								}
								break;
							}
						}
						break;
					}
					if (spi->NextEntryOffset == 0) break;
					spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
				}

				printf("Thread ID: %-6u | Base Pri: %-2ld | State: %-10s | StartAddr: 0x%p\n",
					te.th32ThreadID,
					te.tpBasePri,
					stateStr,
					(PVOID)startAddress
				);
			}
		} while (Thread32Next(hSnapshot, &te));
	}

	CloseHandle(hSnapshot);
	free(buffer);

	if (!threadsFound) {
		printf("No threads found for process %u.\n", pid);
	}
	else if (allZeroStart) {
		printf("\nThe program can't access to thread memory addresses!\n");
	}
	return 0;
}

void watchProcessThreads(DWORD pid, int iters, servicesArray* sa) {

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	// Create snapshot
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return;
	}

	// Validate PID
	BOOL found = FALSE;
	while (Process32Next(hSnapshot, &pe)) {
		if (pe.th32ProcessID == pid) {
			found = TRUE;
			break;
		}
	}

	if (!found) {
		printf("No process found with PID %lu\n", pid);
		CloseHandle(hSnapshot);
		return;
	}

	char ansiName[MAX_PATH];
	WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, ansiName, MAX_PATH, NULL, NULL);
	printf("Process name: %s\n", ansiName);
	printf("PID: %lu\n\n", pe.th32ProcessID);

	HANDLE hProcess = OpenProcess(ACCESS_TYPE, FALSE, pid);
	if (!hProcess) {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); // Retry
	}
	if (!hProcess) {
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) {
			printf("Access denied opening process %lu. It may be a protected system process.\n", pid);
		}
		else {
			printf("Unable to open process %lu (Error: %lu)\n", pid, err);
		}
		CloseHandle(hSnapshot);
		return;
	}

	SYSTEMTIME st;
	for (int i = 0; i < iters; i++) {
		GetSystemTime(&st);
		printf("Iteration number: %d (%02d:%02d:%02d)\n", i, st.wHour, st.wMinute, st.wSecond);
		threadInfo(pid);
		printf("\n");
		Sleep(1000);
	}

	CloseHandle(hProcess);
	CloseHandle(hSnapshot);
}


void getProcessInfo(DWORD pid, servicesArray* sa) {
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	//Create snapshot
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return;
	}

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (pe.th32ProcessID == pid) {
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	else {
		printf("No process found with PID %lu\n", pid);
		CloseHandle(hSnapshot);
		return;
	}

	//Open Process
	HANDLE hToken;
	char exePath[MAX_PATH] = "<unknown>";
	char parentNameA[MAX_PATH] = "<unknown>";
	char description[MAX_PATH] = "<unknown>";
	char username[256] = "NT AUTHORITY\\SYSTEM";
	DWORD sessionID = 0;
	char svc[MAX_PATH] = "";

	HANDLE hProcess = OpenProcess(ACCESS_TYPE, FALSE, pid);
	if (!hProcess) {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	}
	if (!hProcess) {
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) {
			printf("Access denied opening process %lu. It may be a protected system process.\n", pid);
		}
		else {
			printf("Unable to open process %lu (Error: %lu)\n", pid, err);
		}
		CloseHandle(hSnapshot);
		return;
	}

	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		BYTE buffer[1024];
		DWORD size = sizeof(buffer);
		if (GetTokenInformation(hToken, TokenUser, buffer, size, &size)) {
			TOKEN_USER* tokenUser = (TOKEN_USER*)buffer;
			SID_NAME_USE sidType;
			char name[256], domain[256];
			DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
			if (LookupAccountSidA(NULL, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
				snprintf(username, sizeof(username), "%s\\%s", domain, name);
			}
		}
		CloseHandle(hToken);
	}

	// Get Session ID
	ProcessIdToSessionId(pe.th32ProcessID, &sessionID);

	// Get service name if applicable
	for (size_t i = 0; i < sa->count; i++) {
		if (pe.th32ProcessID == sa->pids[i]) {
			strcpy_s(svc, sizeof(svc), sa->names[i]);
			break;
		}
	}

	// Get full path
	if (hProcess) {
		DWORD len = MAX_PATH;
		if (!QueryFullProcessImageNameA(hProcess, 0, exePath, &len)) {
			strcpy_s(exePath, sizeof(exePath), "<access denied>");
		}
	}

	// Get parent process name
	if (pe.th32ParentProcessID != 0) {
		PROCESSENTRY32W parentPE;
		parentPE.dwSize = sizeof(parentPE);
		HANDLE hSnapParent = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapParent != INVALID_HANDLE_VALUE) {
			if (Process32FirstW(hSnapParent, &parentPE)) {
				do {
					if (parentPE.th32ProcessID == pe.th32ParentProcessID) {
						WideCharToMultiByte(CP_ACP, 0, parentPE.szExeFile, -1, parentNameA, MAX_PATH, NULL, NULL);
						break;
					}
				} while (Process32NextW(hSnapParent, &parentPE));
			}
			CloseHandle(hSnapParent);
		}
	}

	//Get Description
	DWORD verHandle = 0;
	DWORD verSize = GetFileVersionInfoSizeA(exePath, &verHandle);
	if (verSize != 0) {
		BYTE* verData = (BYTE*)malloc(verSize);
		if (verData) {
			if (GetFileVersionInfoA(exePath, verHandle, verSize, verData)) {
				struct LANGANDCODEPAGE {
					WORD wLanguage;
					WORD wCodePage;
				} *lpTranslate;

				UINT cbTranslate = 0;
				if (VerQueryValueA(verData, "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) &&
					cbTranslate >= sizeof(struct LANGANDCODEPAGE)) {
					char subBlock[50];
					snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%04x%04x\\FileDescription",
						lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

					LPVOID lpBuffer = NULL;
					UINT size = 0;
					if (VerQueryValueA(verData, subBlock, &lpBuffer, &size) && lpBuffer && size > 0) {
						strncpy_s(description, sizeof(description), (char*)lpBuffer, size);
					}
				}
			}
			free(verData);
		}
	}

	//Check if process is running as admin
	BOOL isAdmin = FALSE;
	if (hProcess) {
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
			TOKEN_ELEVATION elevation;
			DWORD size;
			if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
				isAdmin = elevation.TokenIsElevated;
			}
			CloseHandle(hToken);
		}
	}

	char processNameA[MAX_PATH] = "<unknown>";
	WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, processNameA, MAX_PATH, NULL, NULL);

	// Print Info
	printf("Process Info\n");
	printf("---------------\n");
	printf("Process name: %s%s\n", processNameA, isAdmin ? " [admin]" : "");
	printf("PID: %lu\n\n", pe.th32ProcessID);

	printf("General Info\n");
	printf("---------------\n");
	printf("Parent Name: %s\n", parentNameA);
	printf("Parent PID: %lu\n", pe.th32ParentProcessID);
	printf("Username: %s\n", username);
	printf("SessionID: %lu\n", sessionID);
	printf("Binary Description: %s\n", description);
	printf("Executable Path: %s\n\n", exePath);
	printf("Protection Type: %s\n", getProtectionInfo(hProcess));
	if (svc[0]) {
		printf("Service Name: %s\n", svc);
	}
	printf("Thread Count: %lu\n", pe.cntThreads);
	printf("Priority Base: %ld\n", pe.pcPriClassBase);

	printf("\nThreads Info\n");
	printf("---------------\n");
	threadInfo(pid);

	CloseHandle(hProcess);
	CloseHandle(hSnapshot);
}


void showHelp() {
	printf("\nProcess Thread Enumerator (by K43M1S)\n");
	printf("------------------------------------------------\n");
	printf("Usage:\n");
	printf("  -ps                     Show all running processes\n");
	printf("  -ss                     Show all running services\n");
	printf("  -f <ProcessName>        Find process by name and show PID\n");
	printf("  -i <PID>                Show process info by PID\n");
	printf("  -w <PID> <Iterations>   Watch process therads\n");
}

int main(int argc, char* argv[]) {
	if (argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
		showHelp();
		return 0;
	}

	wchar_t processName[256];

	//Load processes
	servicesArray sa = { 0 };
	enumerateServices(&sa);

	//Ensure admin
	BOOL isAdmin = isRunningAsAdmin();
	if (isAdmin) {
		enableDebugPrivilege();
		//ACCESS_TYPE = PROCESS_ALL_ACCESS; NOT NEEDED
	}
	printf("\n");

	//Input manager
	if (strcmp(argv[1], "-i") == 0 && argc == 3) {
		DWORD pid = (DWORD)atoi(argv[2]);
		getProcessInfo(pid, &sa);
	}
	else if (strcmp(argv[1], "-w") == 0 && argc == 4) {
		DWORD pid = (DWORD)atoi(argv[2]);
		int iters = atoi(argv[3]);
		watchProcessThreads(pid, iters, &sa);
	}
	else if (strcmp(argv[1], "-ps") == 0 && argc == 2) {
		showProcesses(&sa);
	}
	else if (strcmp(argv[1], "-ss") == 0 && argc == 2) {
		showServices(&sa);
	}
	else if (strcmp(argv[1], "-f") == 0 && argc == 3) {
		findProcess(argv[2]);
	}
	else {
		printf("Invalid option.\n");
		showHelp();
	}

	//ServiceArrays Cleanup
	for (size_t i = 0; i < sa.count; i++) {
		free(sa.names[i]);
	}

	return 0;
}