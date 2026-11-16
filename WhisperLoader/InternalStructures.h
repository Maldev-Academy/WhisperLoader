// Copyright 2026 MalDev Academy
// WhisperLoader - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperLoader

// This file is from
// https://github.com/Maldev-Academy/TpDirectCallbackHijack

#pragma once
#ifndef INTERNAL_STRUCTURES_H
#define INTERNAL_STRUCTURES_H

#include <Windows.h>   
#include <stddef.h>    
#include <assert.h>    

/* Forward declarations (pointer-only - this is defined in Structures.h however) */
struct _ACTIVATION_CONTEXT;

/* ================================================================== */
/*  Helper types (not provided by <Windows.h>)                        */
/* ================================================================== */

typedef struct _TPP_CALLER   { PVOID ReturnAddress; } TPP_CALLER;   /* 0x08 */
typedef struct _TPP_REFCOUNT { LONG  Refcount;       } TPP_REFCOUNT; /* 0x04 */

typedef union _TPP_POOL_QUEUE_STATE {
    LONGLONG Exchange;
    struct {
        ULONG RunningThreadGoal   : 16;   /* +0x000 Pos 0  */
        ULONG PendingReleaseCount : 16;   /* +0x000 Pos 16 */
        ULONG QueueLength;                /* +0x004        */
    };
} TPP_POOL_QUEUE_STATE;                                           /* 0x08 */
static_assert(sizeof(TPP_POOL_QUEUE_STATE) == 0x08, "TPP_POOL_QUEUE_STATE size");

typedef union _TPP_FLAGS_COUNT {
    LONGLONG Data;
    struct {
        ULONGLONG Count : 60;   /* +0x000 Pos 0  */
        ULONGLONG Flags : 4;    /* +0x000 Pos 60 */
    };
} TPP_FLAGS_COUNT;                                                /* 0x08 */
static_assert(sizeof(TPP_FLAGS_COUNT) == 0x08, "TPP_FLAGS_COUNT size");

typedef struct _TPP_ITE_WAITER {
/* 0x000 */ struct _TPP_ITE_WAITER *Next;
/* 0x008 */ PVOID                   ThreadId;
} TPP_ITE_WAITER;                                                 /* 0x10 */
static_assert(sizeof(TPP_ITE_WAITER) == 0x10, "TPP_ITE_WAITER size");

typedef struct _TPP_ITE { TPP_ITE_WAITER *First; } TPP_ITE;      /* 0x08 */

typedef struct _TPP_BARRIER {
/* 0x000 */ TPP_FLAGS_COUNT Ptr;
/* 0x008 */ RTL_SRWLOCK     WaitLock;
/* 0x010 */ TPP_ITE         WaitList;
} TPP_BARRIER;                                                    /* 0x18 */
static_assert(sizeof(TPP_BARRIER) == 0x18, "TPP_BARRIER size");

typedef struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS {
/* 0x000 */ PVOID Free;
/* 0x008 */ PVOID CallbackEpilog;
/* 0x010 */ PVOID StopCallbackGeneration;
/* 0x018 */ PVOID CancelPendingCallbacks;
} TPP_CLEANUP_GROUP_MEMBER_VFUNCS;                               /* 0x20 */
static_assert(sizeof(TPP_CLEANUP_GROUP_MEMBER_VFUNCS) == 0x20, "VFUNCS size");

/* Completes the opaque TP_CLEANUP_GROUP tag forward-declared by windows.h.
 * Refcount(4) + Released(4) pack into the first 8 bytes. */
typedef struct _TP_CLEANUP_GROUP {
/* 0x000 */ TPP_REFCOUNT Refcount;
/* 0x004 */ LONG         Released;
/* 0x008 */ RTL_SRWLOCK  MemberLock;
/* 0x010 */ LIST_ENTRY   MemberList;
/* 0x020 */ TPP_BARRIER  Barrier;
/* 0x038 */ RTL_SRWLOCK  CleanupLock;
/* 0x040 */ LIST_ENTRY   CleanupList;
} TP_CLEANUP_GROUP;                                               /* 0x50 */
static_assert(sizeof(TP_CLEANUP_GROUP) == 0x50, "TP_CLEANUP_GROUP size");
static_assert(offsetof(TP_CLEANUP_GROUP, Released)    == 0x004, "TP_CLEANUP_GROUP.Released");
static_assert(offsetof(TP_CLEANUP_GROUP, Barrier)     == 0x020, "TP_CLEANUP_GROUP.Barrier");
static_assert(offsetof(TP_CLEANUP_GROUP, CleanupList) == 0x040, "TP_CLEANUP_GROUP.CleanupList");

typedef struct _TP_TASK_CALLBACKS {
/* 0x000 */ PVOID ExecuteCallback;
/* 0x008 */ PVOID Unposted;
} TP_TASK_CALLBACKS;                                              /* 0x10 */

typedef struct _TP_TASK {
/* 0x000 */ TP_TASK_CALLBACKS *Callbacks;
/* 0x008 */ ULONG              NumaNode;
/* 0x00c */ UCHAR              IdealProcessor;
/*         (3 bytes padding to 0x010) */
/* 0x010 */ LIST_ENTRY         ListEntry;
} TP_TASK;                                                        /* 0x20 */
static_assert(sizeof(TP_TASK) == 0x20, "TP_TASK size");
static_assert(offsetof(TP_TASK, ListEntry) == 0x010, "TP_TASK.ListEntry");

typedef struct _TP_DIRECT {
/* 0x000 */ TP_TASK    Task;
/* 0x020 */ ULONGLONG  Lock;
/* 0x028 */ LIST_ENTRY IoCompletionInformationList;
/* 0x038 */ PVOID      Callback;
/* 0x040 */ ULONG      NumaNode;
/* 0x044 */ UCHAR      IdealProcessor;
/*         (3 bytes padding to 0x048) */
} TP_DIRECT;                                                      /* 0x48 */
static_assert(sizeof(TP_DIRECT) == 0x48, "TP_DIRECT size");
static_assert(offsetof(TP_DIRECT, IoCompletionInformationList) == 0x028, "TP_DIRECT.IoCompletionInformationList");
static_assert(offsetof(TP_DIRECT, IdealProcessor) == 0x044, "TP_DIRECT.IdealProcessor");

typedef struct _TPP_PH_LINKS {
/* 0x000 */ LIST_ENTRY Siblings;
/* 0x010 */ LIST_ENTRY Children;
/* 0x020 */ LONGLONG   Key;
} TPP_PH_LINKS;                                                   /* 0x28 */
static_assert(sizeof(TPP_PH_LINKS) == 0x28, "TPP_PH_LINKS size");

typedef struct _TPP_PH { TPP_PH_LINKS *Root; } TPP_PH;          /* 0x08 */

typedef struct _TPP_QUEUE {
/* 0x000 */ LIST_ENTRY  Queue;
/* 0x010 */ RTL_SRWLOCK Lock;
} TPP_QUEUE;                                                      /* 0x18 (dt -v confirmed) */
static_assert(sizeof(TPP_QUEUE) == 0x18, "TPP_QUEUE size");

typedef struct _TPP_NUMA_NODE {
/* 0x000 */ LONG WorkerCount;
} TPP_NUMA_NODE;                                                  /* 0x04 (dt -v confirmed) */
static_assert(sizeof(TPP_NUMA_NODE) == 0x04, "TPP_NUMA_NODE size");


typedef struct _RTL_WORK_ON_BEHALF_TICKET {
/* 0x000 */    ULONG ThreadId;
/* 0x004 */    ULONG ThreadCreationTimeLow;
} RTL_WORK_ON_BEHALF_TICKET;   /* 0x008 (dt -v confirmed) */                                 
static_assert(sizeof(RTL_WORK_ON_BEHALF_TICKET) == 0x08, "RTL_WORK_ON_BEHALF_TICKET size");


/* ================================================================== */
/*  Timer queue                                                       */
/* ================================================================== */

typedef struct _TPP_TIMER_SUBQUEUE {
/* 0x000 */ LONGLONG  Expiration;
/* 0x008 */ TPP_PH    WindowStart;
/* 0x010 */ TPP_PH    WindowEnd;
/* 0x018 */ PVOID     Timer;
/* 0x020 */ PVOID     TimerPkt;
/* 0x028 */ TP_DIRECT Direct;             /* 0x48 -> ends 0x070 */
/* 0x070 */ ULONG     ExpirationWindow;
/*         (4 bytes padding to 0x078) */
} TPP_TIMER_SUBQUEUE;                                             /* 0x78 */
static_assert(sizeof(TPP_TIMER_SUBQUEUE) == 0x78, "TPP_TIMER_SUBQUEUE size");
static_assert(offsetof(TPP_TIMER_SUBQUEUE, Direct) == 0x028, "SubQueue.Direct");

typedef struct _TPP_TIMER_QUEUE {
/* 0x000 */ RTL_SRWLOCK        Lock;
/* 0x008 */ TPP_TIMER_SUBQUEUE AbsoluteQueue;
/* 0x080 */ TPP_TIMER_SUBQUEUE RelativeQueue;
/* 0x0f8 */ LONG               AllocatedTimerCount;
/*         (4 bytes padding to 0x100) */
} TPP_TIMER_QUEUE;                                                /* 0x100 */
static_assert(sizeof(TPP_TIMER_QUEUE) == 0x100, "TPP_TIMER_QUEUE size");
static_assert(offsetof(TPP_TIMER_QUEUE, RelativeQueue) == 0x080, "TimerQueue.RelativeQueue");
static_assert(offsetof(TPP_TIMER_QUEUE, AllocatedTimerCount) == 0x0f8, "TimerQueue.AllocatedTimerCount");

/* ================================================================== */
/*  _TP_POOL  (size 0x1d8) - completes the opaque windows.h tag        */
/* ================================================================== */
typedef struct _TP_POOL {
/* 0x000 */ TPP_REFCOUNT           Refcount;
/* 0x008 */ TPP_POOL_QUEUE_STATE   QueueState;
/* 0x010 */ TPP_QUEUE             *TaskQueue[3];
/* 0x028 */ TPP_NUMA_NODE         *NumaNode;
/* 0x030 */ GROUP_AFFINITY        *ProximityInfo;
/* 0x038 */ PVOID                  WorkerFactory;
/* 0x040 */ PVOID                  CompletionPort;
/* 0x048 */ RTL_SRWLOCK            Lock;
/* 0x050 */ LIST_ENTRY             PoolObjectList;
/* 0x060 */ LIST_ENTRY             WorkerList;
/* 0x070 */ TPP_TIMER_QUEUE        TimerQueue;
/* 0x170 */ RTL_SRWLOCK            ShutdownLock;
/* 0x178 */ UCHAR                  ShutdownInitiated;
/* 0x179 */ UCHAR                  Released;
/* 0x17a */ USHORT                 PoolFlags;
/*         (4 bytes padding to 0x180) */
/* 0x180 */ LIST_ENTRY             PoolLinks;
/* 0x190 */ TPP_CALLER             AllocCaller;
/* 0x198 */ TPP_CALLER             ReleaseCaller;
/* 0x1a0 */ LONG                   AvailableWorkerCount;
/* 0x1a4 */ LONG                   LongRunningWorkerCount;
/* 0x1a8 */ ULONG                  LastProcCount;
/* 0x1ac */ LONG                   NodeStatus;
/* 0x1b0 */ LONG                   BindingCount;
/* 0x1b4 */ ULONG                  CallbackChecksDisabled : 1;
/* 0x1b4 */ ULONG                  TrimTarget             : 11;
/* 0x1b4 */ ULONG                  TrimmedThrdCount       : 11;
/* 0x1b8 */ ULONG                  SelectedCpuSetCount;
/*         (4 bytes padding to 0x1c0) */
/* 0x1c0 */ RTL_CONDITION_VARIABLE TrimComplete;
/* 0x1c8 */ LIST_ENTRY             TrimmedWorkerList;
} TP_POOL;                                                        /* 0x1d8 */
static_assert(sizeof(TP_POOL) == 0x1d8, "TP_POOL size");
static_assert(offsetof(TP_POOL, TimerQueue) == 0x070, "TP_POOL.TimerQueue");
static_assert(offsetof(TP_POOL, PoolLinks)  == 0x180, "TP_POOL.PoolLinks");
static_assert(offsetof(TP_POOL, TrimmedWorkerList) == 0x1c8, "TP_POOL.TrimmedWorkerList");

/* ================================================================== */
/*  _TPP_CLEANUP_GROUP_MEMBER  (size 0x0c8)                           */
/* ================================================================== */
typedef struct _TPP_CLEANUP_GROUP_MEMBER {
/* 0x000 */ TPP_REFCOUNT          Refcount;
/* 0x008 */ TPP_CLEANUP_GROUP_MEMBER_VFUNCS *VFuncs;
/* 0x010 */ TP_CLEANUP_GROUP     *CleanupGroup;
/* 0x018 */ PVOID                 CleanupGroupCancelCallback;
/* 0x020 */ PVOID                 FinalizationCallback;
/* 0x028 */ LIST_ENTRY            CleanupGroupMemberLinks;
/* 0x038 */ TPP_BARRIER           CallbackBarrier;
/* 0x050 */ union {
                PVOID Callback;
                PVOID WorkCallback;
                PVOID SimpleCallback;
                PVOID TimerCallback;
                PVOID WaitCallback;
                PVOID IoCallback;
                PVOID AlpcCallback;
                PVOID AlpcCallbackEx;
                PVOID JobCallback;
            };
/* 0x058 */ PVOID                 Context;
/* 0x060 */ struct _ACTIVATION_CONTEXT *ActivationContext;
/* 0x068 */ PVOID                 SubProcessTag;
/* 0x070 */ GUID                  ActivityId;
/* 0x080 */ RTL_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
/* 0x088 */ PVOID                 RaceDll;
/* 0x090 */ TP_POOL              *Pool;
/* 0x098 */ LIST_ENTRY            PoolObjectLinks;
/* 0x0a8 */ union {
                LONG Flags;
                struct {
                    LONG LongFunction              : 1;
                    LONG Persistent                : 1;
                    LONG UnusedPublic              : 14;
                    LONG Released                  : 1;
                    LONG CleanupGroupReleased      : 1;
                    LONG InCleanupGroupCleanupList : 1;
                    LONG UnusedPrivate             : 13;
                };
            };
/*         (4 bytes padding to 0x0b0) */
/* 0x0b0 */ TPP_CALLER            AllocCaller;
/* 0x0b8 */ TPP_CALLER            ReleaseCaller;
/* 0x0c0 */ TP_CALLBACK_PRIORITY  CallbackPriority;
/*         (4 bytes padding to 0x0c8) */
} TPP_CLEANUP_GROUP_MEMBER;                                       /* 0x0c8 */
static_assert(sizeof(TPP_CLEANUP_GROUP_MEMBER) == 0x0c8, "TPP_CLEANUP_GROUP_MEMBER size");
static_assert(offsetof(TPP_CLEANUP_GROUP_MEMBER, CallbackBarrier) == 0x038, "CGM.CallbackBarrier");
static_assert(offsetof(TPP_CLEANUP_GROUP_MEMBER, ActivityId)      == 0x070, "CGM.ActivityId");
static_assert(offsetof(TPP_CLEANUP_GROUP_MEMBER, CallbackPriority)== 0x0c0, "CGM.CallbackPriority");

/* ================================================================== */
/*  _TP_IO  (size 0x120) - completes the opaque windows.h tag          */
/* ================================================================== */
typedef struct _TP_IO {
/* 0x000 */ TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
/* 0x0c8 */ TP_DIRECT             Direct;
/* 0x110 */ PVOID                 File;
/* 0x118 */ LONG                  PendingIrpCount;
/*         (4 bytes padding to 0x120) */
} TP_IO;                                                          /* 0x120 */
static_assert(offsetof(TP_IO, Direct)          == 0x0c8, "TP_IO.Direct");
static_assert(offsetof(TP_IO, File)            == 0x110, "TP_IO.File");
static_assert(offsetof(TP_IO, PendingIrpCount) == 0x118, "TP_IO.PendingIrpCount");

/* ================================================================== */
/*  _TP_ALPC  (size 0x128) - completes the opaque windows.h tag       */
/* ================================================================== */
typedef struct _TP_ALPC {
/* 0x000 */ TP_DIRECT                   Direct;             /* 0x48 */
/* 0x048 */ TPP_CLEANUP_GROUP_MEMBER    CleanupGroupMember; /* 0xC8 -> ends 0x110 */
/* 0x110 */ PVOID                       AlpcPort;
/* 0x118 */ LONG                        DeferredSendCount;
/* 0x11c */ LONG                        LastConcurrencyCount;
/* 0x120 */ union {
                ULONG Flags;
                struct {
                    ULONG ExTypeCallback           : 1;     /* Pos 0  */
                    ULONG CompletionListRegistered : 1;     /* Pos 1  */
                    ULONG Reserved                 : 30;    /* Pos 2  */
                };
            };
/*         (4 bytes padding to 0x128) */
} TP_ALPC;                                                   /* 0x128 */
static_assert(offsetof(TP_ALPC, Direct)             == 0x000, "TP_ALPC.Direct");
static_assert(offsetof(TP_ALPC, CleanupGroupMember) == 0x048, "TP_ALPC.CleanupGroupMember");
static_assert(offsetof(TP_ALPC, AlpcPort)           == 0x110, "TP_ALPC.AlpcPort");
static_assert(offsetof(TP_ALPC, Flags)              == 0x120, "TP_ALPC.Flags");

/* ================================================================== */
/*  _TP_JOB  (size 0x128) - completes the opaque windows.h tag        */
/* ================================================================== */
typedef struct _TP_JOB {
/* 0x000 */ TP_DIRECT                   Direct;             /* 0x48 */
/* 0x048 */ TPP_CLEANUP_GROUP_MEMBER    CleanupGroupMember; /* 0xC8 -> ends 0x110 */
/* 0x110 */ PVOID                       JobHandle;
/* 0x118 */ union {
                LONGLONG CompletionState;
                struct {
                    ULONGLONG Rundown         : 1;          /* Pos 0  */
                    ULONGLONG CompletionCount : 63;         /* Pos 1  */
                };
            };
/* 0x120 */ RTL_SRWLOCK                 RundownLock;
} TP_JOB;                                                    /* 0x128 */
static_assert(offsetof(TP_JOB, Direct)             == 0x000, "TP_JOB.Direct");
static_assert(offsetof(TP_JOB, CleanupGroupMember) == 0x048, "TP_JOB.CleanupGroupMember");
static_assert(offsetof(TP_JOB, JobHandle)          == 0x110, "TP_JOB.JobHandle");
static_assert(offsetof(TP_JOB, CompletionState)    == 0x118, "TP_JOB.CompletionState");
static_assert(offsetof(TP_JOB, RundownLock)        == 0x120, "TP_JOB.RundownLock");

/* ================================================================== */
/*  Pool-object kinds supported by the TP_DIRECT.Callback patch path. */
/* ================================================================== */

typedef enum _TP_OBJECT_KIND 
{
    TpObjectKindNone  = 0,
    TpObjectKindIo    = 1,     
    TpObjectKindAlpc  = 2,     
    TpObjectKindJob   = 3,     
    TpObjectKindMax
} TP_OBJECT_KIND;

/* =====================================================================
 *  nt!ObTypeIndexTable (indices are build-specific, verify per target)
 * ===================================================================== */
typedef enum _OB_TYPE_INDEX {
    ObTypeIndexUnknown                        = 0x00,  /* slot 0, unused/sentinel */
    ObTypeIndexReserved                       = 0x01,  /* ObpDefaultObject placeholder (no type ptr) */
    ObTypeIndexType                           = 0x02,
    ObTypeIndexDirectory                      = 0x03,
    ObTypeIndexSymbolicLink                   = 0x04,
    ObTypeIndexToken                          = 0x05,
    ObTypeIndexSession                        = 0x06,
    ObTypeIndexJob                            = 0x07,
    ObTypeIndexProcess                        = 0x08,
    ObTypeIndexThread                         = 0x09,
    ObTypeIndexPartition                      = 0x0a,
    ObTypeIndexUserApcReserve                 = 0x0b,
    ObTypeIndexIoCompletionReserve            = 0x0c,
    ObTypeIndexActivityReference              = 0x0d,
    ObTypeIndexProcessStateChange             = 0x0e,
    ObTypeIndexThreadStateChange              = 0x0f,
    ObTypeIndexCpuPartition                   = 0x10,
    ObTypeIndexSchedulerSharedData            = 0x11,
    ObTypeIndexPsSiloContextPaged             = 0x12,
    ObTypeIndexPsSiloContextNonPaged          = 0x13,
    ObTypeIndexDebugObject                    = 0x14,
    ObTypeIndexEvent                          = 0x15,
    ObTypeIndexMutant                         = 0x16,
    ObTypeIndexCallback                       = 0x17,
    ObTypeIndexSemaphore                      = 0x18,
    ObTypeIndexTimer                          = 0x19,
    ObTypeIndexIRTimer                        = 0x1a,
    ObTypeIndexProfile                        = 0x1b,
    ObTypeIndexKeyedEvent                     = 0x1c,
    ObTypeIndexWindowStation                  = 0x1d,
    ObTypeIndexDesktop                        = 0x1e,
    ObTypeIndexComposition                    = 0x1f,
    ObTypeIndexRawInputManager                = 0x20,
    ObTypeIndexCoreMessaging                  = 0x21,
    ObTypeIndexActivationObject               = 0x22,
    ObTypeIndexTpWorkerFactory                = 0x23,
    ObTypeIndexAdapter                        = 0x24,
    ObTypeIndexController                     = 0x25,
    ObTypeIndexDevice                         = 0x26,
    ObTypeIndexDriver                         = 0x27,
    ObTypeIndexIoCompletion                   = 0x28,
    ObTypeIndexWaitCompletionPacket           = 0x29,
    ObTypeIndexFile                           = 0x2a,
    ObTypeIndexIoRing                         = 0x2b,
    ObTypeIndexTmTm                           = 0x2c,
    ObTypeIndexTmTx                           = 0x2d,
    ObTypeIndexTmRm                           = 0x2e,
    ObTypeIndexTmEn                           = 0x2f,
    ObTypeIndexAlpcPort                       = 0x30,  
    ObTypeIndexSection                        = 0x31,
    ObTypeIndexKey                            = 0x32,
    ObTypeIndexRegistryTransaction            = 0x33,
    ObTypeIndexDmaAdapter                     = 0x34,
    ObTypeIndexEnergyTracker                  = 0x35,
    ObTypeIndexPowerRequest                   = 0x36,
    ObTypeIndexWmiGuid                        = 0x37,
    ObTypeIndexEtwRegistration                = 0x38,
    ObTypeIndexEtwSessionDemuxEntry           = 0x39,
    ObTypeIndexEtwConsumer                    = 0x3a,
    ObTypeIndexCoverageSampler                = 0x3b,
    ObTypeIndexPcwObject                      = 0x3c,
    ObTypeIndexFilterConnectionPort           = 0x3d,
    ObTypeIndexFilterCommunicationPort        = 0x3e,
    ObTypeIndexDxgkSharedResource             = 0x3f,
    ObTypeIndexDxgkSharedKeyedMutexObject     = 0x40,
    ObTypeIndexDxgkSharedSyncObject           = 0x41,
    ObTypeIndexDxgkSharedSwapChainObject      = 0x42,
    ObTypeIndexDxgkDisplayManagerObject       = 0x43,
    ObTypeIndexDxgkSharedProtectedSessionObject = 0x44,
    ObTypeIndexDxgkSharedBundleObject         = 0x45,
    ObTypeIndexDxgkCompositionObject          = 0x46,
    ObTypeIndexDxgkDisplayMuxSwitch           = 0x47,
    ObTypeIndexNdisCmState                    = 0x48,
    ObTypeIndexNdisThreadState                = 0x49,
    ObTypeIndexVRegConfigurationContext       = 0x4a,

    ObTypeIndexMax                            = 0x4b,  /* one past last populated */
} OB_TYPE_INDEX;


#endif // INTERNAL_STRUCTURES_H

