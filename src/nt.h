#pragma once

/*ULONG_PTR GetNtFuncAddressEx(HANDLE procHandle, ULONG_PTR baseAddress, WORD biasedOrdinal, const char* name, char** forwardModule, char** forwardName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
    if (ntReadVirtualMemory(procHandle, reinterpret_cast<PVOID>(baseAddress), dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr) != NTSTATUS_SUCCESS) {
        printf("[!] Failed to read dos header.\n");
        return 0;
    }

    if (dosHeader->e_lfanew == 0) {
        printf("[!] Invalid dos header.\n");
        return 0;
    }

    IMAGE_NT_HEADERS ntHeader;
    if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + dosHeader->e_lfanew, &ntHeader, sizeof(IMAGE_NT_HEADERS), nullptr) != NTSTATUS_SUCCESS) {
        printf("[!] Failed to read nt header.\n");
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY EDT;
    if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &EDT, sizeof(IMAGE_EXPORT_DIRECTORY), NULL) != NTSTATUS_SUCCESS) {
        printf("[!] Failed to read export table.\n");
        return 0;
    }

    DWORD funcRVA = 0;

    if (biasedOrdinal) {
        if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + EDT.AddressOfFunctions + 4 * (biasedOrdinal - EDT.Base), &funcRVA, sizeof(DWORD), nullptr) != NTSTATUS_SUCCESS) {
            printf("[!] Failed to read function address.\n");
            return 0;
        }
    } else {
        for (int i = 0; i < EDT.NumberOfNames; i++) {
            DWORD currentNameRVA;
            if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + EDT.AddressOfNames + 4*i, &currentNameRVA, sizeof(DWORD), nullptr) != NTSTATUS_SUCCESS) {
                printf("[!] Failed to read address of name.\n");
                return 0;
            }

            char currentName[256];
            if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + currentNameRVA, currentName, 256, nullptr) != NTSTATUS_SUCCESS) {
                continue;
            }

            if (strcmp(currentName, name) == 0) {
                WORD funcOrdinal = 0;
                if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + EDT.AddressOfNameOrdinals + 2*i, &funcOrdinal, sizeof(WORD), nullptr) != NTSTATUS_SUCCESS) {
                    printf("[!] Failed to get function ordinal.\n");
                    return 0;
                }

                if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + EDT.AddressOfFunctions + 4*funcOrdinal, &funcRVA, sizeof(DWORD), nullptr) != NTSTATUS_SUCCESS) {
                    printf("[!] Failed to read function address.\n");
                    return 0;
                }

                break;
            }
        }
    }

    //lets check if its forwarder func
    if (forwardModule && forwardName) {
        char forwarder[4352];
        if (ntReadVirtualMemory(procHandle, reinterpret_cast<PBYTE>(baseAddress) + funcRVA, forwarder, 4352, nullptr) != NTSTATUS_SUCCESS) {
            printf("[!] Failed to get forwarder info.\n");
            return 0;
        }

        char* seperator = strchr(forwarder, '.');
        if (seperator != nullptr) {
            char moduleName[256];
            strncpy(moduleName, forwarder, seperator - forwarder);

            char funcName[4096];
            strncpy(funcName, forwarder + (seperator - forwarder + 1), (sizeof(forwarder) / sizeof(forwarder[0])) - (seperator - forwarder + 1));

            *forwardModule = (char*)malloc(256);
            *forwardName = (char*)malloc(4096);

            sprintf(*forwardModule, "%s.dll", moduleName);
            strcpy(*forwardName, funcName);
        }
    }

    return funcRVA;
}*/

typedef NTSTATUS (*t_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                    PCOBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

typedef NTSTATUS NTAPI (*t_NtAllocateVirtualMemoryEx)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                      ULONG AllocationType, ULONG PageProtection,
                                                      PMEM_EXTENDED_PARAMETER ExtendedParameters,
                                                      ULONG ExtendedParameterCount);

typedef NTSTATUS NTAPI (*t_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                 SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS NTAPI (*t_NtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                             PCOBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                             PUSER_THREAD_START_ROUTINE StartRoutine, PVOID Argument,
                                             ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
                                             SIZE_T MaximumStackSize, PVOID AttributeList);

typedef NTSTATUS NTAPI (*t_NtReadVirtualMemory)(HANDLE ProcessHandle,
                                                PVOID BaseAddress,
                                                PVOID Buffer,
                                                SIZE_T NumberOfBytesToRead,
                                                PSIZE_T NumberOfBytesRead);

typedef NTSTATUS NTAPI (*t_NtQueryInformationProcess)(HANDLE ProcessHandle,
                                                    PROCESSINFOCLASS ProcessInformationClass,
                                                    PVOID ProcessInformation,
                                                    ULONG ProcessInformationLength,
                                                    PULONG ReturnLength);

typedef NTSTATUS NTAPI (*t_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
                                                    ULONG SystemInformationLength, PULONG ReturnLength);

typedef NTSTATUS NTAPI (*t_NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation,
                                                    ULONG ThreadInformationLength, PULONG ReturnLength);

typedef NTSTATUS NTAPI (*t_NtGetNextThread)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                            ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);

typedef NTSTATUS NTAPI (*t_NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT ThreadContext);

typedef NTSTATUS NTAPI (*t_NtSuspendThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

typedef NTSTATUS NTAPI (*t_NtSetContextThread)(HANDLE ThreadHandle, PCONTEXT ThreadContext);

typedef NTSTATUS NTAPI (*t_NtResumeThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

typedef NTSTATUS NTAPI (*t_NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

namespace winNtInjection {
    struct DLL_MAIN_ARGS {
        ULONG_PTR entryPoint;
        ULONG_PTR tlsAddress;
        PVOID baseAddress;
        ULONG_PTR imageBase;
    };

    struct PROC_MODULE_INFORMATION {
        void* baseAddress;
        char* moduleName;
        char* modulePath;
    };

    struct IMAGE_RELOCATION_ENTRY {
        unsigned short Offset   : 12;
        unsigned short Type     : 4;
    };

    extern FARPROC loadLibraryA;
    extern t_NtOpenProcess ntOpenProcess;
    extern t_NtAllocateVirtualMemoryEx ntAllocateVirtualMemoryEx;
    extern t_NtWriteVirtualMemory ntWriteVirtualMemory;
    extern t_NtCreateThreadEx ntCreateThreadEx;
    extern t_NtReadVirtualMemory ntReadVirtualMemory;
    extern t_NtQueryInformationProcess ntQueryInformationProcess;
    extern t_NtQuerySystemInformation ntQuerySystemInformation;
    extern t_NtQueryInformationThread ntQueryInformationThread;
    extern t_NtGetNextThread ntGetNextThread;
    extern t_NtGetContextThread ntGetContextThread;
    extern t_NtSuspendThread ntSuspendThread;
    extern t_NtSetContextThread ntSetContextThread;
    extern t_NtResumeThread ntResumeThread;
    extern t_NtWaitForSingleObject ntWaitForSingleObject;

    extern HMODULE ntdll;
    extern HMODULE kernel32;
    extern OBJECT_ATTRIBUTES ntObjectAttribs;

    bool Initialize();

    //some utilities
    HANDLE GetProcessIdByName(const char* procName);
    HANDLE OpenNtProcessById(HANDLE pid);
    ULONG_PTR GetNtModuleHandle(HANDLE procHandle, const char* moduleName);

    IMAGE_SECTION_HEADER GetSectionHeaderByVA(PIMAGE_NT_HEADERS ntHeader, DWORD va);
    ULONG_PTR GetFuncAddressFromFile(const char* modulePath, WORD biasedOrdinal, const char* name, char** forwardModule = nullptr, char** forwardName = nullptr);
    bool SearchForFullName(const char* name, char* fullName);

    bool OpenLibrary(const char* path, unsigned char** outData = nullptr);

    //execution methods
    bool ECreateThreadEx(HANDLE procHandle, PVOID shellCodeBase, PVOID shellArgBase);
    bool EThreadHijack(HANDLE procHandle, PVOID shellCodeBase, PVOID shellArgBase);

    //injection methods
    bool ILdrLoadDll(HANDLE procHandle, const char* path, bool execution(HANDLE, PVOID, PVOID));
    ULONG_PTR IManualLoad(HANDLE procHandle, const char* path, bool execution(HANDLE, PVOID, PVOID));
}
