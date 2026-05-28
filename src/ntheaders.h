#pragma once

#define NTSTATUS_SUCCESS 0x00000000

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS NTAPI USER_THREAD_START_ROUTINE(PVOID ThreadParameter);
typedef USER_THREAD_START_ROUTINE *PUSER_THREAD_START_ROUTINE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef enum _PROCESSINFOCLASS // 4 bytes
{
    ProcessBasicInformation   = 0x0,
    ProcessDebugPort          = 0x7,
    ProcessWow64Information   = 0x1A,
    ProcessImageFileName      = 0x1B,
    ProcessBreakOnTermination = 0x1D,
} PROCESSINFOCLASS;

//0x7c8 bytes (sizeof)
struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob:1;                                           //0x50
            ULONG ProcessInitializing:1;                                    //0x50
            ULONG ProcessUsingVEH:1;                                        //0x50
            ULONG ProcessUsingVCH:1;                                        //0x50
            ULONG ProcessUsingFTH:1;                                        //0x50
            ULONG ProcessPreviouslyThrottled:1;                             //0x50
            ULONG ProcessCurrentlyThrottled:1;                              //0x50
            ULONG ProcessImagesHotPatched:1;                                //0x50
            ULONG ReservedBits0:24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    VOID* TlsBitmap;                                                        //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* SharedData;                                                       //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID (*PostProcessInitRoutine)();                                       //0x230
    VOID* TlsExpansionBitmap;                                               //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    VOID* SparePointers[4];                                                 //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* pUnused;                                                          //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x378
            ULONG CritSecTracingEnabled:1;                                  //0x378
            ULONG LibLoaderTracingEnabled:1;                                //0x378
            ULONG SpareTracingBits:29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct _LIST_ENTRY TppWorkerpList;                                      //0x390
    VOID* WaitOnAddressHashTable[128];                                      //0x3a0
    VOID* TelemetryCoverageHeader;                                          //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x7c0
            ULONG Reserved:31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
};

//0x480 bytes (sizeof)
struct _PEB32
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    VOID* Mutant;                                                           //0x4
    VOID* ImageBaseAddress;                                                 //0x8
    struct _PEB_LDR_DATA* Ldr;                                              //0xc
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
    VOID* SubSystemData;                                                    //0x14
    VOID* ProcessHeap;                                                      //0x18
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x20
    VOID* IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob:1;                                           //0x28
            ULONG ProcessInitializing:1;                                    //0x28
            ULONG ProcessUsingVEH:1;                                        //0x28
            ULONG ProcessUsingVCH:1;                                        //0x28
            ULONG ProcessUsingFTH:1;                                        //0x28
            ULONG ProcessPreviouslyThrottled:1;                             //0x28
            ULONG ProcessCurrentlyThrottled:1;                              //0x28
            ULONG ProcessImagesHotPatched:1;                                //0x28
            ULONG ReservedBits0:24;                                         //0x28
        };
    };
    union
    {
        VOID* KernelCallbackTable;                                          //0x2c
        VOID* UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved;                                                   //0x30
    union _SLIST_HEADER* volatile AtlThunkSListPtr32;                       //0x34
    VOID* ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    VOID* TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    VOID* ReadOnlySharedMemoryBase;                                         //0x4c
    VOID* SharedData;                                                       //0x50
    VOID** ReadOnlyStaticServerData;                                        //0x54
    VOID* AnsiCodePageData;                                                 //0x58
    VOID* OemCodePageData;                                                  //0x5c
    VOID* UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    VOID** ProcessHeaps;                                                    //0x90
    VOID* GdiSharedHandleTable;                                             //0x94
    VOID* ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    VOID (*PostProcessInitRoutine)();                                       //0x14c
    VOID* TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    VOID* pShimData;                                                        //0x1e8
    VOID* AppCompatInfo;                                                    //0x1ec
    struct _UNICODE_STRING CSDVersion;                                      //0x1f0
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x1f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x1fc
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x200
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x204
    ULONG MinimumStackCommit;                                               //0x208
    VOID* SparePointers[4];                                                 //0x20c
    ULONG SpareUlongs[5];                                                   //0x21c
    VOID* WerRegistrationData;                                              //0x230
    VOID* WerShipAssertPtr;                                                 //0x234
    VOID* pUnused;                                                          //0x238
    VOID* pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x240
            ULONG CritSecTracingEnabled:1;                                  //0x240
            ULONG LibLoaderTracingEnabled:1;                                //0x240
            ULONG SpareTracingBits:29;                                      //0x240
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
    ULONG TppWorkerpListLock;                                               //0x250
    struct _LIST_ENTRY TppWorkerpList;                                      //0x254
    VOID* WaitOnAddressHashTable[128];                                      //0x25c
    VOID* TelemetryCoverageHeader;                                          //0x45c
    ULONG CloudFileFlags;                                                   //0x460
    ULONG CloudFileDiagFlags;                                               //0x464
    CHAR PlaceholderCompatibilityMode;                                      //0x468
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x470
    union
    {
        ULONG LeapSecondFlags;                                              //0x474
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x474
            ULONG Reserved:31;                                              //0x474
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x478
};
#ifdef WIN32
typedef _PEB32 PEB, *PPEB;
#else
typedef _PEB64 PEB, *PPEB;
#endif

typedef struct _PROCESS_BASIC_INFORMATION // sizeof=0x30
{
    PVOID Reserved1;
    struct _PEB *PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

//0x58 bytes (sizeof)
struct _PEB_LDR_DATA64
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
};

//0x30 bytes (sizeof)
struct _PEB_LDR_DATA32
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
	VOID* EntryInProgress;                                                  //0x24
	UCHAR ShutdownInProgress;                                               //0x28
	VOID* ShutdownThreadId;                                                 //0x2c
};

#ifdef WIN32
typedef _PEB_LDR_DATA32 PEB_LDR_DATA, *PPEB_LDR_DATA;
#else
typedef _PEB_LDR_DATA64 PEB_LDR_DATA, *PPEB_LDR_DATA;
#endif

//0x120 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY64
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary:1;                                         //0x68
            ULONG MarkedForRemoval:1;                                       //0x68
            ULONG ImageDll:1;                                               //0x68
            ULONG LoadNotificationsSent:1;                                  //0x68
            ULONG TelemetryEntryProcessed:1;                                //0x68
            ULONG ProcessStaticImport:1;                                    //0x68
            ULONG InLegacyLists:1;                                          //0x68
            ULONG InIndexes:1;                                              //0x68
            ULONG ShimDll:1;                                                //0x68
            ULONG InExceptionTable:1;                                       //0x68
            ULONG ReservedFlags1:2;                                         //0x68
            ULONG LoadInProgress:1;                                         //0x68
            ULONG LoadConfigProcessed:1;                                    //0x68
            ULONG EntryProcessed:1;                                         //0x68
            ULONG ProtectDelayLoad:1;                                       //0x68
            ULONG ReservedFlags3:2;                                         //0x68
            ULONG DontCallForThreads:1;                                     //0x68
            ULONG ProcessAttachCalled:1;                                    //0x68
            ULONG ProcessAttachFailed:1;                                    //0x68
            ULONG CorDeferredValidate:1;                                    //0x68
            ULONG CorImage:1;                                               //0x68
            ULONG DontRelocate:1;                                           //0x68
            ULONG CorILOnly:1;                                              //0x68
            ULONG ChpeImage:1;                                              //0x68
            ULONG ReservedFlags5:2;                                         //0x68
            ULONG Redirected:1;                                             //0x68
            ULONG ReservedFlags6:2;                                         //0x68
            ULONG CompatDatabaseProcessed:1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    BYTE Reserved1[0x18];                                                   //0xc8
    BYTE Reserved2[0x18];                                                   //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    INT LoadReason;                                                         //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
};

//0xa8 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY32
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
    VOID* DllBase;                                                          //0x18
    VOID* EntryPoint;                                                       //0x1c
    ULONG SizeOfImage;                                                      //0x20
    struct _UNICODE_STRING FullDllName;                                     //0x24
    struct _UNICODE_STRING BaseDllName;                                     //0x2c
    union
    {
        UCHAR FlagGroup[4];                                                 //0x34
        ULONG Flags;                                                        //0x34
        struct
        {
            ULONG PackagedBinary:1;                                         //0x34
            ULONG MarkedForRemoval:1;                                       //0x34
            ULONG ImageDll:1;                                               //0x34
            ULONG LoadNotificationsSent:1;                                  //0x34
            ULONG TelemetryEntryProcessed:1;                                //0x34
            ULONG ProcessStaticImport:1;                                    //0x34
            ULONG InLegacyLists:1;                                          //0x34
            ULONG InIndexes:1;                                              //0x34
            ULONG ShimDll:1;                                                //0x34
            ULONG InExceptionTable:1;                                       //0x34
            ULONG ReservedFlags1:2;                                         //0x34
            ULONG LoadInProgress:1;                                         //0x34
            ULONG LoadConfigProcessed:1;                                    //0x34
            ULONG EntryProcessed:1;                                         //0x34
            ULONG ProtectDelayLoad:1;                                       //0x34
            ULONG ReservedFlags3:2;                                         //0x34
            ULONG DontCallForThreads:1;                                     //0x34
            ULONG ProcessAttachCalled:1;                                    //0x34
            ULONG ProcessAttachFailed:1;                                    //0x34
            ULONG CorDeferredValidate:1;                                    //0x34
            ULONG CorImage:1;                                               //0x34
            ULONG DontRelocate:1;                                           //0x34
            ULONG CorILOnly:1;                                              //0x34
            ULONG ChpeImage:1;                                              //0x34
            ULONG ReservedFlags5:2;                                         //0x34
            ULONG Redirected:1;                                             //0x34
            ULONG ReservedFlags6:2;                                         //0x34
            ULONG CompatDatabaseProcessed:1;                                //0x34
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x38
    USHORT TlsIndex;                                                        //0x3a
    struct _LIST_ENTRY HashLinks;                                           //0x3c
    ULONG TimeDateStamp;                                                    //0x44
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x48
    VOID* Lock;                                                             //0x4c
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x50
    struct _LIST_ENTRY NodeModuleLink;                                      //0x54
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0x5c
    VOID* ParentDllBase;                                                    //0x60
    VOID* SwitchBackContext;                                                //0x64
    BYTE Reserved1[0xC];													//0x68
    BYTE Reserved2[0xC];							                        //0x74
    ULONG OriginalBase;                                                     //0x80
    union _LARGE_INTEGER LoadTime;                                          //0x88
    ULONG BaseNameHashValue;                                                //0x90
    BYTE Reserved3[0x4];				                                    //0x94
    ULONG ImplicitPathOptions;                                              //0x98
    ULONG ReferenceCount;                                                   //0x9c
    ULONG DependentLoadFlags;                                               //0xa0
    UCHAR SigningLevel;                                                     //0xa4
};

#ifdef WIN32
typedef _LDR_DATA_TABLE_ENTRY32 LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#elif
typedef _LDR_DATA_TABLE_ENTRY64 LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#endif

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation           = 0x0,
    SystemProcessorInformation       = 0x1,
    SystemPerformanceInformation     = 0x2,
    SystemTimeOfDayInformation       = 0x3,
    SystemPathInformation            = 0x4,
    SystemProcessInformation         = 0x5,
    SystemCallCountInformation       = 0x6,
    SystemDeviceInformation          = 0x7,
    SystemProcessorPerformanceInformation = 0x8,
    SystemFlagsInformation           = 0x9,
    SystemCallTimeInformation        = 0xA,
    SystemModuleInformation          = 0xB,
    SystemLocksInformation           = 0xC,
    SystemStackTraceInformation      = 0xD,
    SystemPagedPoolInformation       = 0xE,
    SystemNonPagedPoolInformation    = 0xF,
    SystemHandleInformation          = 0x10,
    SystemObjectInformation          = 0x11,
    SystemPageFileInformation        = 0x12,
    SystemVdmInstemulInformation     = 0x13,
    SystemVdmBopInformation          = 0x14,
    SystemFileCacheInformation       = 0x15,
    SystemPoolTagInformation         = 0x16,
    SystemInterruptInformation       = 0x17,
    SystemDpcBehaviorInformation     = 0x18,
    SystemFullMemoryInformation      = 0x19,
    SystemLoadGdiDriverInformation   = 0x1A,
    SystemUnloadGdiDriverInformation = 0x1B,
    SystemTimeAdjustmentInformation  = 0x1C,
    SystemSummaryMemoryInformation   = 0x1D,
    SystemMirrorMemoryInformation    = 0x1E,
    SystemPerformanceTraceInformation = 0x1F,
    SystemObsolete0                  = 0x20,
    SystemExceptionInformation       = 0x21,
    SystemCrashDumpStateInformation  = 0x22,
    SystemKernelDebuggerInformation  = 0x23,
    SystemContextSwitchInformation   = 0x24,
    SystemRegistryQuotaInformation   = 0x25,
    SystemExtendServiceTableInformation = 0x26,
    SystemPrioritySeperation         = 0x27,
    SystemVerifierAddDriverInformation = 0x28,
    SystemVerifierRemoveDriverInformation = 0x29,
    SystemProcessorIdleInformation   = 0x2A,
    SystemLegacyDriverInformation    = 0x2B,
    SystemCurrentTimeZoneInformation = 0x2C,
    SystemLookasideInformation       = 0x2D,
    SystemTimeSlipNotification       = 0x2E,
    SystemSessionCreate              = 0x2F,
    SystemSessionDetach              = 0x30,
    SystemSessionInformation         = 0x31,
    SystemRangeStartInformation      = 0x32,
    SystemVerifierInformation        = 0x33,
    SystemVerifierThunkExtend        = 0x34,
    SystemSessionProcessInformation  = 0x35,
    SystemLoadGdiDriverInSystemSpace = 0x36,
    SystemNumaProcessorMap           = 0x37,
    SystemPrefetcherInformation      = 0x38,
    SystemExtendedProcessInformation = 0x39,
    SystemRecommendedSharedDataAlignment = 0x3A,
    SystemComPlusPackage             = 0x3B,
    SystemNumaAvailableMemory        = 0x3C,
    SystemProcessorPowerInformation  = 0x3D,
    SystemEmulationBasicInformation  = 0x3E,
    SystemEmulationProcessorInformation = 0x3F,
    SystemExtendedHandleInformation  = 0x40,
    SystemLostDelayedWriteInformation = 0x41,
    SystemBigPoolInformation         = 0x42,
    SystemSessionPoolTagInformation  = 0x43,
    SystemSessionMappedViewInformation = 0x44,
    SystemHotpatchInformation        = 0x45,
    SystemObjectSecurityMode         = 0x46,
    SystemWatchdogTimerHandler       = 0x47,
    SystemWatchdogTimerInformation   = 0x48,
    SystemLogicalProcessorInformation = 0x49,
    SystemWow64SharedInformationObsolete = 0x4A,
    SystemRegisterFirmwareTableInformationHandler = 0x4B,
    SystemFirmwareTableInformation   = 0x4C,
    SystemModuleInformationEx        = 0x4D,
    SystemVerifierTriageInformation  = 0x4E,
    SystemSuperfetchInformation      = 0x4F,
    SystemMemoryListInformation      = 0x50,
    SystemFileCacheInformationEx     = 0x51,
    SystemThreadPriorityClientIdInformation = 0x52,
    SystemProcessorIdleCycleTimeInformation = 0x53,
    SystemVerifierCancellationInformation = 0x54,
    SystemProcessorPowerInformationEx = 0x55,
    SystemRefTraceInformation        = 0x56,
    SystemSpecialPoolInformation     = 0x57,
    SystemProcessIdInformation       = 0x58,
    SystemErrorPortInformation       = 0x59,
    SystemBootEnvironmentInformation = 0x5A,
    SystemHypervisorInformation      = 0x5B,
    SystemVerifierInformationEx      = 0x5C,
    SystemTimeZoneInformation        = 0x5D,
    SystemImageFileExecutionOptionsInformation = 0x5E,
    SystemCoverageInformation        = 0x5F,
    SystemPrefetchPatchInformation   = 0x60,
    SystemVerifierFaultsInformation  = 0x61,
    SystemSystemPartitionInformation = 0x62,
    SystemSystemDiskInformation      = 0x63,
    SystemProcessorPerformanceDistribution = 0x64,
    SystemNumaProximityNodeInformation = 0x65,
    SystemDynamicTimeZoneInformation = 0x66,
    SystemCodeIntegrityInformation   = 0x67,
    SystemProcessorMicrocodeUpdateInformation = 0x68,
    SystemProcessorBrandString       = 0x69,
    SystemVirtualAddressInformation  = 0x6A,
    SystemLogicalProcessorAndGroupInformation = 0x6B,
    SystemProcessorCycleTimeInformation = 0x6C,
    SystemStoreInformation           = 0x6D,
    SystemRegistryAppendString       = 0x6E,
    SystemAitSamplingValue           = 0x6F,
    SystemVhdBootInformation         = 0x70,
    SystemCpuQuotaInformation        = 0x71,
    SystemNativeBasicInformation     = 0x72,
    SystemErrorPortTimeouts          = 0x73,
    SystemLowPriorityIoInformation   = 0x74,
    SystemBootEntropyInformation     = 0x75,
    SystemVerifierCountersInformation = 0x76,
    SystemPagedPoolInformationEx     = 0x77,
    SystemSystemPtesInformationEx    = 0x78,
    SystemNodeDistanceInformation    = 0x79,
    SystemAcpiAuditInformation       = 0x7A,
    SystemBasicPerformanceInformation = 0x7B,
    SystemQueryPerformanceCounterInformation = 0x7C,
    SystemSessionBigPoolInformation  = 0x7D,
    SystemBootGraphicsInformation    = 0x7E,
    SystemScrubPhysicalMemoryInformation = 0x7F,
    SystemBadPageInformation         = 0x80,
    SystemProcessorProfileControlArea = 0x81,
    SystemCombinePhysicalMemoryInformation = 0x82,
    SystemEntropyInterruptTimingInformation = 0x83,
    SystemConsoleInformation         = 0x84,
    SystemPlatformBinaryInformation  = 0x85,
    SystemPolicyInformation          = 0x86,
    SystemHypervisorProcessorCountInformation = 0x87,
    SystemDeviceDataInformation      = 0x88,
    SystemDeviceDataEnumerationInformation = 0x89,
    SystemMemoryTopologyInformation  = 0x8A,
    SystemMemoryChannelInformation   = 0x8B,
    SystemBootLogoInformation        = 0x8C,
    SystemProcessorPerformanceInformationEx = 0x8D,
    SystemCriticalProcessErrorLogInformation = 0x8E,
    SystemSecureBootPolicyInformation = 0x8F,
    SystemPageFileInformationEx      = 0x90,
    SystemSecureBootInformation      = 0x91,
    SystemEntropyInterruptTimingRawInformation = 0x92,
    SystemPortableWorkspaceEfiLauncherInformation = 0x93,
    SystemFullProcessInformation     = 0x94,
    SystemKernelDebuggerInformationEx = 0x95,
    SystemBootMetadataInformation    = 0x96,
    SystemSoftRebootInformation      = 0x97,
    SystemElamCertificateInformation = 0x98,
    SystemOfflineDumpConfigInformation = 0x99,
    SystemProcessorFeaturesInformation = 0x9A,
    SystemRegistryReconciliationInformation = 0x9B,
    SystemEdidInformation            = 0x9C,
    SystemManufacturingInformation   = 0x9D,
    SystemEnergyEstimationConfigInformation = 0x9E,
    SystemHypervisorDetailInformation = 0x9F,
    SystemProcessorCycleStatsInformation = 0xA0,
    SystemVmGenerationCountInformation = 0xA1,
    SystemTrustedPlatformModuleInformation = 0xA2,
    SystemKernelDebuggerFlags        = 0xA3,
    SystemCodeIntegrityPolicyInformation = 0xA4,
    SystemIsolatedUserModeInformation = 0xA5,
    SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
    SystemSingleModuleInformation    = 0xA7,
    SystemAllowedCpuSetsInformation  = 0xA8,
    SystemVsmProtectionInformation   = 0xA9,
    SystemInterruptCpuSetsInformation = 0xAA,
    SystemSecureBootPolicyFullInformation = 0xAB,
    SystemCodeIntegrityPolicyFullInformation = 0xAC,
    SystemAffinitizedInterruptProcessorInformation = 0xAD,
    SystemRootSiloInformation        = 0xAE,
    SystemCpuSetInformation          = 0xAF,
    SystemCpuSetTagInformation       = 0xB0,
    SystemWin32WerStartCallout       = 0xB1,
    SystemSecureKernelProfileInformation = 0xB2,
    SystemCodeIntegrityPlatformManifestInformation = 0xB3,
    SystemInterruptSteeringInformation = 0xB4,
    SystemSupportedProcessorArchitectures = 0xB5,
    SystemMemoryUsageInformation     = 0xB6,
    SystemCodeIntegrityCertificateInformation = 0xB7,
    SystemPhysicalMemoryInformation  = 0xB8,
    SystemControlFlowTransition      = 0xB9,
    SystemKernelDebuggingAllowed     = 0xBA,
    SystemActivityModerationExeState = 0xBB,
    SystemActivityModerationUserSettings = 0xBC,
    SystemCodeIntegrityPoliciesFullInformation = 0xBD,
    SystemCodeIntegrityUnlockInformation = 0xBE,
    SystemIntegrityQuotaInformation  = 0xBF,
    SystemFlushInformation           = 0xC0,
    SystemProcessorIdleMaskInformation = 0xC1,
    SystemSecureDumpEncryptionInformation = 0xC2,
    SystemWriteConstraintInformation = 0xC3,
    SystemKernelVaShadowInformation  = 0xC4,
    SystemHypervisorSharedPageInformation = 0xC5,
    SystemFirmwareBootPerformanceInformation = 0xC6,
    SystemCodeIntegrityVerificationInformation = 0xC7,
    SystemFirmwarePartitionInformation = 0xC8,
    SystemSpeculationControlInformation = 0xC9,
    SystemDmaGuardPolicyInformation  = 0xCA,
    SystemEnclaveLaunchControlInformation = 0xCB,
    SystemWorkloadAllowedCpuSetsInformation = 0xCC,
    SystemCodeIntegrityUnlockModeInformation = 0xCD,
    SystemLeapSecondInformation      = 0xCE,
    SystemFlags2Information          = 0xCF,
    SystemSecurityModelInformation   = 0xD0,
    SystemCodeIntegritySyntheticCacheInformation = 0xD1,
    SystemFeatureConfigurationInformation = 0xD2,
    SystemFeatureConfigurationSectionInformation = 0xD3,
    SystemFeatureUsageSubscriptionInformation = 0xD4,
    SystemSecureSpeculationControlInformation = 0xD5,
    SystemSpacesBootInformation      = 0xD6,
    SystemFwRamdiskInformation       = 0xD7,
    SystemWheaIpmiHardwareInformation = 0xD8,
    SystemDifSetRuleClassInformation = 0xD9,
    SystemDifClearRuleClassInformation = 0xDA,
    SystemDifApplyPluginVerificationOnDriver = 0xDB,
    SystemDifRemovePluginVerificationOnDriver = 0xDC,
    SystemShadowStackInformation     = 0xDD,
    SystemBuildVersionInformation    = 0xDE,
    SystemPoolLimitInformation       = 0xDF,
    SystemCodeIntegrityAddDynamicStore = 0xE0,
    SystemCodeIntegrityClearDynamicStores = 0xE1,
    SystemPoolZeroingInformation     = 0xE3,
    MaxSystemInfoClass               = 0xE4,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION // sizeof=0x100
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    // padding byte
    // padding byte
    // padding byte
    // padding byte
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    // padding byte
    // padding byte
    // padding byte
    // padding byte
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _TEB // sizeof=0x1838
{
	_NT_TIB NtTib;
	void *EnvironmentPointer;
	_CLIENT_ID ClientId;
	void *ActiveRpcHandle;
	void *ThreadLocalStoragePointer;
	_PEB *ProcessEnvironmentBlock;
	unsigned int LastErrorValue;
	unsigned int CountOfOwnedCriticalSections;
	void *CsrClientThread;
	void *Win32ThreadInfo;
	unsigned int User32Reserved[26];
	unsigned int UserReserved[5];
	// padding byte
	// padding byte
	// padding byte
	// padding byte
	void *WOW32Reserved;
	unsigned int CurrentLocale;
	unsigned int FpSoftwareStatusRegister;
	void *ReservedForDebuggerInstrumentation[16];
	void *SystemReserved1[30];
	char PlaceholderCompatibilityMode;
	unsigned __int8 PlaceholderHydrationAlwaysExplicit;
	char PlaceholderReserved[10];
	unsigned int ProxiedProcessId;
	BYTE _ActivationStack[0x28];
	unsigned __int8 WorkingOnBehalfTicket[8];
	int ExceptionCode;
	unsigned __int8 Padding0[4];
	BYTE *ActivationContextStackPointer[0x28];
	unsigned __int64 InstrumentationCallbackSp;
	unsigned __int64 InstrumentationCallbackPreviousPc;
	unsigned __int64 InstrumentationCallbackPreviousSp;
	unsigned int TxFsContext;
	unsigned __int8 InstrumentationCallbackDisabled;
	unsigned __int8 UnalignedLoadStoreExceptions;
	unsigned __int8 Padding1[2];
	BYTE GdiTebBatch[0x4E8];
	_CLIENT_ID RealClientId;
	void *GdiCachedProcessHandle;
	unsigned int GdiClientPID;
	unsigned int GdiClientTID;
	void *GdiThreadLocalInfo;
	unsigned __int64 Win32ClientInfo[62];
	void *glDispatchTable[233];
	unsigned __int64 glReserved1[29];
	void *glReserved2;
	void *glSectionInfo;
	void *glSection;
	void *glTable;
	void *glCurrentRC;
	void *glContext;
	unsigned int LastStatusValue;
	unsigned __int8 Padding2[4];
	_UNICODE_STRING StaticUnicodeString;
	wchar_t StaticUnicodeBuffer[261];
	unsigned __int8 Padding3[6];
	void *DeallocationStack;
	void *TlsSlots[64];
	_LIST_ENTRY TlsLinks;
	void *Vdm;
	void *ReservedForNtRpc;
	void *DbgSsReserved[2];
	unsigned int HardErrorMode;
	unsigned __int8 Padding4[4];
	void *Instrumentation[11];
	_GUID ActivityId;
	void *SubProcessTag;
	void *PerflibData;
	void *EtwTraceData;
	void *WinSockData;
	unsigned int GdiBatchCount;
	BYTE ___u68[0x4];
	unsigned int GuaranteedStackBytes;
	unsigned __int8 Padding5[4];
	void *ReservedForPerf;
	void *ReservedForOle;
	unsigned int WaitingOnLoaderLock;
	unsigned __int8 Padding6[4];
	void *SavedPriorityState;
	unsigned __int64 ReservedForCodeCoverage;
	void *ThreadPoolData;
	void **TlsExpansionSlots;
	void *DeallocationBStore;
	void *BStoreLimit;
	unsigned int MuiGeneration;
	unsigned int IsImpersonating;
	void *NlsCache;
	void *pShimData;
	unsigned int HeapData;
	unsigned __int8 Padding7[4];
	void *CurrentTransactionHandle;
	BYTE ActiveFrame[0x18]; //x
	void *FlsData;
	void *PreferredLanguages;
	void *UserPrefLanguages;
	void *MergedPrefLanguages;
	unsigned int MuiImpersonation;
	BYTE ___u94[0x2];
	BYTE ___u95[0x2];
	void *TxnScopeEnterCallback;
	void *TxnScopeExitCallback;
	void *TxnScopeContext;
	unsigned int LockCount;
	int WowTebOffset;
	void *ResourceRetValue;
	void *ReservedForWdf;
	unsigned __int64 ReservedForCrt;
	_GUID EffectiveContainerId;
} *PTEB;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation
} THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;