# ProcessEnumerator

A Windows process and service enumeration tool inspired by Sysinternals Process Informer — available both as a standalone Portable Executable and as a Beacon Object File (BOF) for use within Cobalt Strike or compatible C2 frameworks.

## Features

- Lists all running **processes** and **services**
- Resolves associated **user accounts** and **session IDs**
- Retrieves detailed **thread-level information**
- Detects **process protection status** (Protected Process Light, signer info)
- Displays **executable path**, **description** (from version resource), and **parent process**
- Maps **services to their hosting processes**

> **Note:** Not suitable for restricted environments such as AppContainer or WinPE.

## Repository Structure

```
ProcessEnumerator/
├── Beacon Object File/   # BOF source and compiled .o
├── Portable Executable/  # PE source and compiled .exe
└── ProcessEnumerator.md  # Internal research notes
```

## Delivery Formats

### 1. Portable Executable (`.exe`)

Standard Windows console application. Requires no external dependencies.

**Usage flow:**

1. Parses user arguments
2. Initializes the service cache
3. Requests `SeDebugPrivilege` if running as administrator
4. Dispatches to the appropriate function

**Available functions:**

| Function | Description |
|---|---|
| `showProcesses()` | Lists all running processes: PID, name, user, session, service name |
| `findProcess(name)` | Searches for a process by name; reports PID and elevation status |
| `getProcessInfo(pid)` | Full process details: parent, user, path, description, protection, threads |
| `watchProcessThreads(pid, n)` | Polls `threadInfo()` every second for *n* iterations |

**`getProcessInfo()` output includes:**
- Process name and PID
- Parent PID and parent name
- User and session information
- Executable description from version resources
- Full executable path
- Protected Process information via `ZwQueryInformationProcess`
- Thread count, base priority, and per-thread details

### 2. Beacon Object File (`.o`)

Adapted for in-memory execution from a Cobalt Strike beacon. Key differences from the PE version:

- Functions use **output buffers** instead of `printf` — cleaner BOF experience
- Some functions simplified for the post-exploitation context
- All Win32 calls made through **Direct Function Resolution (DFR)** macros

**DFR imports:**

| Library | Imported functions (sample) |
|---|---|
| `KERNEL32` | `OpenProcess`, `CreateToolhelp32Snapshot`, `Process32FirstW/NextW`, `Thread32First/Next`, `QueryFullProcessImageNameA`, `OpenThread` |
| `ADVAPI32` | `OpenSCManagerA`, `EnumServicesStatusExA`, `OpenProcessToken`, `LookupAccountSidA`, `GetTokenInformation` |
| `MSVCRT` | `calloc`, `malloc`, `free`, `memcpy`, `_wcsicmp` |

**NT API definitions resolved dynamically at runtime:**

```c
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
```

## Technical Notes

### Undocumented NT APIs

The tool dynamically resolves three undocumented APIs at runtime:

- `NtQuerySystemInformation` — used for `SystemProcessInformation` to enumerate processes and threads
- `ZwQueryInformationProcess` — used to retrieve protection level and signer info
- `NtQueryInformationThread` — used for per-thread state details

### Process Handle Strategy

To maximize coverage, the tool attempts two access levels when opening a process handle:

```c
HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
if (!hProcess)
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); // fallback
```

### Known Limitations

- **Windows Protected Processes (PPL/PP):** Thread enumeration is denied for `NT AUTHORITY\SYSTEM` protected processes. The tool reports access errors gracefully rather than crashing.
- **Non-admin context:** `SeDebugPrivilege` is not available; some process handles may be restricted.
- **AppContainer / WinPE:** Not supported.
