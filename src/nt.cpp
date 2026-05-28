#include "includes.h"
#include "nt.h"

namespace winNtInjection {
    FARPROC loadLibraryA;
    t_NtOpenProcess ntOpenProcess;
    t_NtAllocateVirtualMemoryEx ntAllocateVirtualMemoryEx;
    t_NtWriteVirtualMemory ntWriteVirtualMemory;
    t_NtCreateThreadEx ntCreateThreadEx;
    t_NtReadVirtualMemory ntReadVirtualMemory;
    t_NtQueryInformationProcess ntQueryInformationProcess;
    t_NtQuerySystemInformation ntQuerySystemInformation;
    t_NtQueryInformationThread ntQueryInformationThread;
    t_NtGetNextThread ntGetNextThread;
    t_NtGetContextThread ntGetContextThread;
    t_NtSuspendThread ntSuspendThread;
    t_NtSetContextThread ntSetContextThread;
    t_NtResumeThread ntResumeThread;
    t_NtWaitForSingleObject ntWaitForSingleObject;

    OBJECT_ATTRIBUTES ntObjectAttribs;

    HMODULE ntdll = nullptr;
    HMODULE kernel32 = nullptr;

    bool Initialize() {
        ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll == nullptr) {
            PERROR("[-] Failed to get Native API address.\n");
            return false;
        }

        kernel32 = GetModuleHandleA("kernel32.dll");
        if (kernel32 == nullptr) {
            PERROR("[-] Failed to get Kernel32 address.\n");
            return false;
        }

        loadLibraryA = GetProcAddress(kernel32, "LoadLibraryA");
        ntOpenProcess = reinterpret_cast<t_NtOpenProcess>(GetProcAddress(ntdll, "NtOpenProcess"));
        ntAllocateVirtualMemoryEx = reinterpret_cast<t_NtAllocateVirtualMemoryEx>(GetProcAddress(ntdll, "NtAllocateVirtualMemoryEx"));
        ntWriteVirtualMemory = reinterpret_cast<t_NtWriteVirtualMemory>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
        ntCreateThreadEx = reinterpret_cast<t_NtCreateThreadEx>(GetProcAddress(ntdll, "NtCreateThreadEx"));
        ntReadVirtualMemory = reinterpret_cast<t_NtReadVirtualMemory>(GetProcAddress(ntdll, "NtReadVirtualMemory"));
        ntQueryInformationProcess = reinterpret_cast<t_NtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
        ntQuerySystemInformation = reinterpret_cast<t_NtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
        ntQueryInformationThread = reinterpret_cast<t_NtQueryInformationThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
        ntGetNextThread = reinterpret_cast<t_NtGetNextThread>(GetProcAddress(ntdll, "NtGetNextThread"));
        ntGetContextThread = reinterpret_cast<t_NtGetContextThread>(GetProcAddress(ntdll, "NtGetContextThread"));
        ntSuspendThread = reinterpret_cast<t_NtSuspendThread>(GetProcAddress(ntdll, "NtSuspendThread"));
        ntSetContextThread = reinterpret_cast<t_NtSetContextThread>(GetProcAddress(ntdll, "NtSetContextThread"));
        ntResumeThread = reinterpret_cast<t_NtResumeThread>(GetProcAddress(ntdll, "NtResumeThread"));
        ntWaitForSingleObject = reinterpret_cast<t_NtWaitForSingleObject>(GetProcAddress(ntdll, "NtWaitForSingleObject"));

        if (loadLibraryA == nullptr
            || ntOpenProcess == nullptr
            || ntAllocateVirtualMemoryEx == nullptr
            || ntWriteVirtualMemory == nullptr
            || ntCreateThreadEx == nullptr
            || ntReadVirtualMemory == nullptr
            || ntQueryInformationProcess == nullptr
            || ntQuerySystemInformation == nullptr
            || ntQueryInformationThread == nullptr
            || ntGetNextThread == nullptr
            || ntGetContextThread == nullptr
            || ntSuspendThread == nullptr
            || ntSetContextThread == nullptr
            || ntResumeThread == nullptr
            || ntWaitForSingleObject == nullptr) {
            PERROR("[-] Failed to load native functions.\n");
            return false;
        }

        InitializeObjectAttributes(&ntObjectAttribs, nullptr, 0, nullptr, nullptr);

        /*printf("Kernel32                    -> %p\n", kernel32);
        printf("Ntdll                       -> %p\n", ntdll);
        printf("NtOpenProcess               -> %p\n", ntOpenProcess);
        printf("NtAllocateVirtualMemoryEx   -> %p\n", ntAllocateVirtualMemoryEx);
        printf("NtWriteVirtualMemory        -> %p\n", ntWriteVirtualMemory);
        printf("NtCreateThreadEx            -> %p\n", ntCreateThreadEx);
        printf("NtReadVirtualMemory         -> %p\n", ntReadVirtualMemory);
        printf("NtQueryInformationProcess   -> %p\n", ntQueryInformationProcess);
        printf("NtQuerySystemInformation    -> %p\n", ntQuerySystemInformation);
        printf("NtQueryInformationThread    -> %p\n", ntQueryInformationThread);
        printf("NtGetNextThread             -> %p\n", ntGetNextThread);
        printf("NtGetContextThread          -> %p\n", ntGetContextThread);
        printf("NtSuspendThread             -> %p\n", ntSuspendThread);
        printf("NtSetContextThread          -> %p\n", ntSetContextThread);
        printf("NtResumeThread              -> %p\n\n", ntResumeThread);*/

        PINFO("[*] Native functions just initialised.\n\n");

        return true;
    }

    HANDLE GetProcessIdByName(const char* procName) {
        ULONG bufferSize = 0;

        ntQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufferSize);
        if (bufferSize == 0) {
            PERROR("[-] Failed to get buffer size.\n");
            return nullptr;
        }

        PSYSTEM_PROCESS_INFORMATION listBuffer = new SYSTEM_PROCESS_INFORMATION[bufferSize];
        if (ntQuerySystemInformation(SystemProcessInformation, listBuffer, bufferSize, nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to get process information.\n");
            return nullptr;
        }

        while (listBuffer->NextEntryOffset != 0) {
            listBuffer = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PBYTE>(listBuffer) + listBuffer->NextEntryOffset);

            char* imageName = new char[listBuffer->ImageName.Length];
            wcstombs(imageName, listBuffer->ImageName.Buffer, listBuffer->ImageName.Length);

            if (strcmp(imageName, procName) == 0) {
                return listBuffer->UniqueProcessId;
            }
        }

        return nullptr;
    }

    HANDLE OpenNtProcessById(HANDLE pid) {
        if (!pid) {
            PERROR("[-] Invalid process id.\n");
            return nullptr;
        }

        CLIENT_ID clientId;
        clientId.UniqueProcess = pid;
        clientId.UniqueThread = nullptr;

        HANDLE procHandle;
        ntOpenProcess(&procHandle, PROCESS_ALL_ACCESS, &ntObjectAttribs, &clientId);
        if (procHandle == nullptr) {
            PERROR("[-] Failed to open process.\n");
            return nullptr;
        }

        return procHandle;
    }

    ULONG_PTR GetNtModuleHandle(HANDLE procHandle, const char* moduleName) {
        PROCESS_BASIC_INFORMATION queryInfo;

        ULONG queryLength;
        if (ntQueryInformationProcess(procHandle, ProcessBasicInformation, &queryInfo, sizeof(PROCESS_BASIC_INFORMATION), &queryLength) != NTSTATUS_SUCCESS
            || queryLength == 0) {
            PERROR("[!] Failed to query process information.\n");
            return 0;
        }

        PEB peb;
        if (ntReadVirtualMemory(procHandle, queryInfo.PebBaseAddress, &peb, sizeof(PEB), nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[!] Failed to read PEB structure.\n");
            return 0;
        }

        PEB_LDR_DATA pebLdr;
        if (ntReadVirtualMemory(procHandle, peb.Ldr, &pebLdr, sizeof(PEB_LDR_DATA), nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[!] Failed to get loader data.\n");
            return 0;
        }

        PLIST_ENTRY firstModuleEntry = pebLdr.InLoadOrderModuleList.Flink; //get first entry address
        PLIST_ENTRY currentModuleEntry = firstModuleEntry;

        do {
            LDR_DATA_TABLE_ENTRY moduleTable;
            if (ntReadVirtualMemory(procHandle, currentModuleEntry, &moduleTable, sizeof(LDR_DATA_TABLE_ENTRY), nullptr) != NTSTATUS_SUCCESS) {
                PERROR("[!] Failed to get module table.\n");
                return 0;
            }

            USHORT wModuleNameLength = moduleTable.BaseDllName.Length;
            wchar_t* wModuleName = new wchar_t[wModuleNameLength];

            if (ntReadVirtualMemory(procHandle, moduleTable.BaseDllName.Buffer, wModuleName, wModuleNameLength, nullptr) != NTSTATUS_SUCCESS) {
                PERROR("[!] Failed to get module name.\n");
                return 0;
            }

            USHORT cModuleNameLength = wModuleNameLength/sizeof(wchar_t);

            char* cModuleName = new char[cModuleNameLength];
            wcstombs(cModuleName, wModuleName, cModuleNameLength);
            cModuleName[cModuleNameLength] = '\0';

            if (strcmpi(cModuleName, moduleName) == 0) {
                return reinterpret_cast<ULONG_PTR>(moduleTable.DllBase);
            }

            currentModuleEntry = moduleTable.InLoadOrderLinks.Flink;
        } while (firstModuleEntry != currentModuleEntry);

        return 0;
    }

    IMAGE_SECTION_HEADER GetSectionHeaderByVA(PIMAGE_NT_HEADERS ntHeader, DWORD va) {
        PIMAGE_SECTION_HEADER libSections = IMAGE_FIRST_SECTION(ntHeader);
        IMAGE_SECTION_HEADER foundSection = {};
        WORD numberOfSections = ntHeader->FileHeader.NumberOfSections;

        for (int i = 0; i < numberOfSections; i++) {
            if (va >= libSections[i].VirtualAddress && (i + 1 >= numberOfSections || va < libSections[i+1].VirtualAddress)) {
                foundSection = libSections[i];
                break;
            }
        }

        return foundSection;
    }

    ULONG_PTR GetFuncAddressFromFile(const char* modulePath, WORD biasedOrdinal, const char* name, char** forwardModule, char** forwardName) {
        std::ifstream libFile(modulePath, std::ifstream::binary);
        if (!libFile.is_open()) {
            PERROR("[-] Failed to open DLL file.\n");
            return false;
        }

        libFile.seekg(0, std::ifstream::end);
        size_t size = libFile.tellg();
        libFile.seekg(0, std::ifstream::beg);

        if (size < 0x1000) {
            PERROR("[-] Invalid file.\n");
            return false;
        }

        unsigned char* libBuff = static_cast<unsigned char*>(malloc(size * sizeof(unsigned char)));
        libFile.read(reinterpret_cast<char*>(libBuff), size);

	    PIMAGE_DOS_HEADER libDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(libBuff);

	    if (libDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		    PERROR("[-] Invalid PE file.\n");
	        libFile.close();
	        free(libBuff);
		    return 0;
	    }

	    PIMAGE_NT_HEADERS libNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(libBuff + libDosHeader->e_lfanew);

	    if (!(libNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		    PERROR("[-] Not a DLL file.\n");
	        libFile.close();
	        free(libBuff);
		    return 0;
	    }

	    IMAGE_DATA_DIRECTORY libExportDir = libNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	    IMAGE_SECTION_HEADER libExportSection = GetSectionHeaderByVA(libNtHeader, libExportDir.VirtualAddress);

	    if (!libExportSection.PointerToRawData) {
		    PERROR("[-] Invalid export section.\n");
	        libFile.close();
	        free(libBuff);
		    return 0;
	    }

	    PIMAGE_EXPORT_DIRECTORY EDT = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(libBuff + libExportSection.PointerToRawData + (libExportDir.VirtualAddress - libExportSection.VirtualAddress));

	    IMAGE_SECTION_HEADER funcsSection = GetSectionHeaderByVA(libNtHeader, EDT->AddressOfFunctions);
        IMAGE_SECTION_HEADER funcNamesSection = GetSectionHeaderByVA(libNtHeader, EDT->AddressOfNames);
        IMAGE_SECTION_HEADER ordinalsSection = GetSectionHeaderByVA(libNtHeader, EDT->AddressOfNameOrdinals);

        if (!funcsSection.PointerToRawData) {
            PERROR("[-] Invalid function table section.\n");
            libFile.close();
            free(libBuff);
            return 0;
        }

	    DWORD funcRva = 0;

	    if (biasedOrdinal) {
		    funcRva = *reinterpret_cast<PDWORD>(libBuff + (funcsSection.PointerToRawData + (EDT->AddressOfFunctions - funcsSection.VirtualAddress)) + 4 * (biasedOrdinal - EDT->Base));
 	    } else {
 	        PDWORD funcNamePtr = reinterpret_cast<PDWORD>(libBuff + (funcNamesSection.PointerToRawData + (EDT->AddressOfNames - funcNamesSection.VirtualAddress)));

 	        for (int i = 0; i < EDT->NumberOfNames; i++, funcNamePtr++) {
 	            IMAGE_SECTION_HEADER nameSection = GetSectionHeaderByVA(libNtHeader, *funcNamePtr);
                if (!nameSection.PointerToRawData) {
                    PERROR("[-] Invalid function name section.\n");
                    libFile.close();
                    free(libBuff);
                    return 0;
                }

 	            char* funcName = reinterpret_cast<char*>(libBuff + (nameSection.PointerToRawData + (*funcNamePtr - nameSection.VirtualAddress)));
 	            if (strcmp(funcName, name) == 0) {
 	                WORD funcOrdinal = *reinterpret_cast<PWORD>(libBuff + (ordinalsSection.PointerToRawData + (EDT->AddressOfNameOrdinals - ordinalsSection.VirtualAddress)) + 2*i);
 	                funcRva = *reinterpret_cast<PDWORD>(libBuff + (funcsSection.PointerToRawData + (EDT->AddressOfFunctions - funcsSection.VirtualAddress)) + 4 * funcOrdinal);

 	                break;
 	            }
 	        }
	    }

	    //lets check if its forwarder func
	    if (forwardModule && forwardName) {
		    IMAGE_SECTION_HEADER funcSection = GetSectionHeaderByVA(libNtHeader, funcRva);
	        if (!funcSection.PointerToRawData) {
	            PERROR("[-] Invalid function section.\n");
	            libFile.close();
	            free(libBuff);
	            return 0;
	        }

		    char* forwarder = reinterpret_cast<char*>(libBuff + (funcSection.PointerToRawData + (funcRva - funcSection.VirtualAddress)));
		    char* seperator = strchr(forwarder, '.');
		    if (seperator != nullptr) {
			    char moduleName[256] = "\0";
			    strncpy(moduleName, forwarder, seperator - forwarder);

			    char funcName[4096] = "\0";
			    strncpy(funcName, forwarder + (seperator - forwarder + 1), strlen(forwarder) - (seperator - forwarder + 1));

			    *forwardModule = static_cast<char*>(malloc(256));
			    *forwardName = static_cast<char*>(malloc(4096));

			    sprintf(*forwardModule, "%s.dll", moduleName);
			    strcpy(*forwardName, funcName);
		    }
	    }

        libFile.close();
        free(libBuff);

        return funcRva;
    }

    bool SearchForFullName(const char* name, char* fullName) {
        char winDir[MAX_PATH];
        if (GetWindowsDirectoryA(winDir, MAX_PATH) == 0) {
            PERROR("[-] Failed to get windows directory.\n");
            return false;
        }

        if (Utils::SearchFile(name, winDir, false, &fullName)) {
            return true;
        }

        char systemDir[MAX_PATH];
        if (GetSystemDirectoryA(systemDir, MAX_PATH) == 0) {
            PERROR("[-] Failed to get system directory.\n");
            return false;
        }

        if (Utils::SearchFile(name, systemDir, true, &fullName)) {
            return true;
        }

        char currentPath[MAX_PATH];
        if (GetModuleFileNameA(nullptr, currentPath, MAX_PATH) == 0) {
            PERROR("[-] Failed to get current directory.\n");
            return false;
        }

        char* dirEnd = strrchr(currentPath, '\\');
        size_t currentDirLen = dirEnd - currentPath;

        char currentDir[currentDirLen + 1];
        strncpy(currentDir, currentPath, currentDirLen);
        currentDir[currentDirLen] = '\0';

        if (Utils::SearchFile(name, currentDir, false, &fullName)) {
            return true;
        }

        size_t MAX_ENVPATH = 32767;
        char pathEnv[MAX_ENVPATH];
        if (GetEnvironmentVariableA("PATH", pathEnv, MAX_ENVPATH) == 0) {
            PERROR("[-] Failed to get environment variable.\n");
            return false;
        }

        char* first = strchr(pathEnv, ';');
        int prevOrder = 0;

        while (first != nullptr) {
            size_t pathLen =  (first - pathEnv)-prevOrder;

            char buffer[pathLen+1];
            strncpy(buffer, pathEnv + prevOrder, pathLen);
            buffer[pathLen] = '\0';

            if (Utils::SearchFile(name, buffer, false, &fullName)) {
                return true;
            }

            prevOrder = first - pathEnv + 1;
            first = strchr(first+1, ';');
        }

        return false;
    }

    bool OpenLibrary(const char* path, unsigned char** outData) {
        std::ifstream libFile(path, std::ifstream::binary);
        if (!libFile.is_open()) {
            PERROR("[-] Failed to open DLL file.\n");
            return false;
        }

        libFile.seekg(0, std::ifstream::end);
        size_t size = libFile.tellg();
        libFile.seekg(0, std::ifstream::beg);

        if (size < 0x1000) {
            PERROR("[-] Invalid file.\n");
            return false;
        }

        unsigned char* targetBuff;

        if (outData) {
            *outData = static_cast<unsigned char*>(malloc(size * sizeof(unsigned char)));
            targetBuff = *outData;
        } else {
            targetBuff = static_cast<unsigned char*>(malloc(size * sizeof(unsigned char)));
        }

        libFile.read(reinterpret_cast<char*>(targetBuff), size);

        PIMAGE_DOS_HEADER libDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(targetBuff);

        if (libDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            PERROR("[-] Invalid PE file.\n");
            free(targetBuff);
            return false;
        }

        PIMAGE_NT_HEADERS libNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(targetBuff + libDosHeader->e_lfanew);

        if (!(libNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
            PERROR("[-] Not a DLL file.\n");
            free(targetBuff);
            return false;
        }

        //0x10b is for pe32 and 0x20b is for pe64
#ifdef _WIN64
        if (libNtHeader->OptionalHeader.Magic != 0x20b) {
            PERROR("[-] DLL file built for 32-bit architecture, switch into 32-bit injector!");
            free(targetBuff);
            return false;
        }
#else
        if (libNtHeader->OptionalHeader.Magic != 0x10b) {
            PERROR("[-] DLL file built for 64-bit architecture, switch into 64-bit injector!");
            free(targetBuff);
            return false;
        }
#endif

        if (!outData) {
            free(targetBuff);
        }

        return true;
    }

    //Standart execution method
    bool ECreateThreadEx(HANDLE procHandle, PVOID shellCodeBase, PVOID shellArgBase) {
        HANDLE threadHandle;
        if (ntCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, &ntObjectAttribs, procHandle, reinterpret_cast<PUSER_THREAD_START_ROUTINE>(shellCodeBase), shellArgBase, 0, 0, 0, 0, nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to create thread.\n");
            return false;
        }

        return true;
    }

    //ThreadHijacking execution method
    bool EThreadHijack(HANDLE procHandle, PVOID shellCodeBase, PVOID shellArgBase) {
        HANDLE threadHandle;
        if (ntGetNextThread(procHandle, nullptr, THREAD_ALL_ACCESS, 0, 0, &threadHandle) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to get thread handle.\n");
            return false;
        }

        CONTEXT threadContext = {};
        threadContext.ContextFlags = CONTEXT_FULL;

        if (ntGetContextThread(threadHandle, &threadContext) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to get thread context.\n");
            return false;
        }

        PVOID jumpCodeBase = nullptr;
        SIZE_T jumpCodeSize = 0x100;

        ntAllocateVirtualMemoryEx(procHandle, &jumpCodeBase, &jumpCodeSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE, nullptr, 0);
        if (!jumpCodeBase) {
            PERROR("[-] Failed to allocate jumpcode memory. \n");
            return false;
        }

#ifdef _WIN64

        /*
            BITS 64
            PUSH RAX
            PUSH RCX
            SUB RSP, 8*5
            MOV RAX, strict qword 0x000000000000 ; Func Address
            MOV RCX, strict qword 0x000000000000 ; Args Address
            CALL RAX
            ADD RSP, 8*5
            POP RCX
            POP RAX
            MOV R11, strict qword 0x000000000000 ; Current Rip
            JMP R11
        */

        //this is a jump code in assembly for forwarding instruction to our shellcode
        unsigned char jumpCode[47] = {
            0x50, 0x51, 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28,
            0x59, 0x58, 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3
        };

        *(DWORD64*)(jumpCode + 8) = (DWORD64)shellCodeBase;
        *(DWORD64*)(jumpCode + 18) = (DWORD64)shellArgBase;
        *(DWORD64*)(jumpCode + 36) = threadContext.Rip;

        threadContext.Rip = reinterpret_cast<DWORD64>(jumpCodeBase);
#else
        /*
            BITS 32
            PUSHAD
            SUB ESP, 8*5
            MOV EAX, strict dword 0x00000000 ; Func Address
            MOV ECX, strict dword 0x00000000 ; Args Address
            PUSH ECX
            CALL EAX
            ADD ESP, 8*5
            POPAD
            MOV EDX, strict dword 0x00000000 ; Current Rip
            JMP EDX
        */

        unsigned char jumpCode[28] = {
            0x60, 0x83, 0xEC, 0x28, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x51, 0xFF,
            0xD0, 0x83, 0xC4, 0x28, 0x61, 0xBA, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE2
        };

        *reinterpret_cast<DWORD*>(jumpCode + 5) = reinterpret_cast<DWORD>(shellCodeBase);
        *reinterpret_cast<DWORD*>(jumpCode + 10) = reinterpret_cast<DWORD>(shellArgBase);
        *reinterpret_cast<DWORD*>(jumpCode + 22) = threadContext.Eip;

        threadContext.Eip = reinterpret_cast<DWORD32>(jumpCodeBase);
#endif

        if (ntWriteVirtualMemory(procHandle, jumpCodeBase, jumpCode, 0x100, nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to write jumpcode into memory.\n");
            return false;
        }

        if (ntSuspendThread(threadHandle, nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to suspend thread.\n");
            return false;
        }

        if (ntSetContextThread(threadHandle, &threadContext) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to change thread context.\n");
            return false;
        }

        if (ntResumeThread(threadHandle, nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to resume thread.\n");
            return false;
        }

        return true;
    }

    //basic LoadLibrary Injection Type
    bool ILdrLoadDll(HANDLE procHandle, const char* path, bool execution(HANDLE, PVOID, PVOID)) {
        if (!OpenLibrary(path)) {
            PERROR("[-] Invalid file.\n");
            return false;
        }

        SIZE_T pathSize = strlen(path);
        SIZE_T argSize = pathSize;
        PVOID argAddress = nullptr;

        ntAllocateVirtualMemoryEx(procHandle, &argAddress, &argSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE, nullptr, 0);
        if (!argAddress) {
            PERROR("[-] Failed to allocate args memory.\n");
            return false;
        }

        if (ntWriteVirtualMemory(procHandle, argAddress, const_cast<char*>(path), pathSize, nullptr) != NTSTATUS_SUCCESS) {
            PERROR("[-] Failed to write args into memory.\n");
            return false;
        }

        if (!execution(procHandle, reinterpret_cast<PVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")), argAddress)) {
            PERROR("[-] Failed to execute shellcode.\n");
            return false;
        }

        return true;
    }

    void __stdcall shellCode(DLL_MAIN_ARGS* args) {
        typedef void __stdcall (*TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);
        typedef bool __stdcall (*DLL_ENTRY_POINT)(PVOID hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

        if (args->tlsAddress != 0) {
            PIMAGE_TLS_DIRECTORY libTlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(reinterpret_cast<ULONG_PTR>(args->baseAddress) + args->tlsAddress);
            if (libTlsDir->AddressOfCallBacks != 0) {
                ULONG_PTR* tlsCallbackList = reinterpret_cast<ULONG_PTR*>(libTlsDir->AddressOfCallBacks);

                while (*tlsCallbackList != 0) {
                    reinterpret_cast<TLS_CALLBACK>(*tlsCallbackList)(args->baseAddress, DLL_PROCESS_ATTACH, nullptr);

                    tlsCallbackList++;
                }
            }
        }

        reinterpret_cast<DLL_ENTRY_POINT>((ULONG_PTR)args->baseAddress + args->entryPoint)(args->baseAddress, DLL_PROCESS_ATTACH, nullptr);
    }

    //ManualMapping Injection Type
    ULONG_PTR IManualLoad(HANDLE procHandle, const char* path, bool execution(HANDLE, PVOID, PVOID)) {
        unsigned char* libData;

        if (!OpenLibrary(path, &libData)) {
            PERROR("[-] Invalid file.\n");
            return 0;
        }

        PIMAGE_DOS_HEADER libDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(libData);
        PIMAGE_NT_HEADERS libNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(libData + libDosHeader->e_lfanew);

        //lets deep in
        //now we need to have baseAddress before calculating crazy things
        //thats why we are allocation memory
        PVOID baseAddress = nullptr;
        SIZE_T libAllocSize = libNtHeader->OptionalHeader.SizeOfImage;

        ntAllocateVirtualMemoryEx(procHandle, &baseAddress, &libAllocSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE, nullptr, 0);
        if (!baseAddress) {
            PERROR("[-] Failed to allocate memory.\n");
            free(libData);
            return 0;
        }

        PINFO("[*] Memory allocated at %p with size %lu\n", baseAddress, libAllocSize);

        //-- Relocation Table Fix --
        //Skip this fix if there is no difference between our baseAddress and ImageBase or if there is no reloc table (some of libraries dont have this)
        //Go to relocation dir
        //Loop all relocation entries
        //Locate the entry address in our file data (get entry section raw address by virtual address)
        //Read bytes until next entry address as 'oldOffset' (then the result is our virtual pointer offset of variable or whatever)
        //Then calculate new address (newAddress = libBaseAddress + (oldOffset - libImageBase)) and write this into the raw data

        IMAGE_DATA_DIRECTORY libRelocDir = libNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (libRelocDir.VirtualAddress != 0 && libNtHeader->OptionalHeader.ImageBase - reinterpret_cast<ULONG_PTR>(baseAddress) != 0) {
            IMAGE_SECTION_HEADER libRelocSection = GetSectionHeaderByVA(libNtHeader, libRelocDir.VirtualAddress);
            if (!libRelocSection.PointerToRawData) {
                PERROR("[-] Invalid relocation section.\n");
                free(libData);
                return 0;
            }

            PIMAGE_BASE_RELOCATION curRelocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(libData + libRelocSection.PointerToRawData);
            PIMAGE_BASE_RELOCATION lastRelocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(libData + libRelocSection.PointerToRawData + libRelocDir.Size);

            while (curRelocBlock < lastRelocBlock) {
                IMAGE_SECTION_HEADER relocPage = GetSectionHeaderByVA(libNtHeader, curRelocBlock->VirtualAddress);
                if (!relocPage.PointerToRawData) {
                    PERROR("[-] Failed to locate relocation section.\n");
                    free(libData);
                    return 0;
                }

                IMAGE_RELOCATION_ENTRY* curRelocEntry = reinterpret_cast<IMAGE_RELOCATION_ENTRY*>(reinterpret_cast<PBYTE>(curRelocBlock) + sizeof(IMAGE_BASE_RELOCATION));
                unsigned int entryCount = (curRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
                for (int i = 0; i < entryCount; i++) {
                    //Skip it if its padding block
                    if (curRelocEntry->Type == IMAGE_REL_BASED_ABSOLUTE) {
                        continue;
                    }

                    //getting section header by va doesnt give us proper raw data offset, we must find difference and sum it with raw offset (curRelocBlock->VirtualAddress - relocPageRVA.VirtualAddress)
                    //its happens cuz when we find the start of section
                    DWORD entryRawAddress = relocPage.PointerToRawData + (curRelocBlock->VirtualAddress - relocPage.VirtualAddress) + curRelocEntry->Offset;

                    ULONG_PTR entryTargetRva;
                    memcpy(&entryTargetRva, libData + entryRawAddress, sizeof(ULONG_PTR));

                    ULONG_PTR newTargetRva = (entryTargetRva - libNtHeader->OptionalHeader.ImageBase) + reinterpret_cast<ULONG_PTR>(baseAddress);
                    memcpy(libData + entryRawAddress, &newTargetRva, sizeof(ULONG_PTR));

                    curRelocEntry++;
                }

                curRelocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(curRelocBlock) + curRelocBlock->SizeOfBlock);
            }

            printf("[*] Relocation Table fixed.\n");
        }

        //-- Import Address Table (IAT) Fix --

        //Import Directory Table (IDT): Holds information about every dll files which imported.
        //Import Lookup Table (ILT): Holds reference for every functions that are being imported.
        //  (x86 -> 31) (x64 -> 63) bit holds Ordinal flag
        //  (x86 -> 30-15) (x64 -> 62-15) bit(s) holds ordinal number if Ordinal flag is 1
        //  (x86 -> 30-0) (x64 -> 62-31) bit(s) holds RVA of 'Hint/Name' Table if Ordinal flag is 0
        //Import Address Table (IAT) will be changed to the real memory address of the imported function.

        //IMAGE_IMPORT_DESCRIPTOR -> Import Directory Table (IDT)
        //  *.Name -> It's RVA of the DLL name. Go to this address and read it as a char*
        //  *.OriginalFirstThunk -> It's RVA of ILT.
        //  *.FirstThunk -> It's RVA of IAT.

        //IMAGE_IMPORT_BY_NAME -> 'Hint/Name' Table
        //  2 byte holds Hint, Remaining Bytes until 0 holds the name of imported function

        //IMAGE_THUNK_DATA -> It can use with ILT and IAT
        //  *.u1.Function -> Thunk, address of function.
        //  *.u1.AddressOfData -> RVA of Hint/Name table.

        //Loop all imported dll files
        //And loop for every functions which used
        //Go to address of firstThunk and change its bytes into our returned address which came from GetProcAddress call

        IMAGE_DATA_DIRECTORY libIDataDir = libNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (libIDataDir.VirtualAddress != 0) {
            IMAGE_SECTION_HEADER libIDataSection = GetSectionHeaderByVA(libNtHeader, libIDataDir.VirtualAddress);
            if (!libIDataSection.PointerToRawData) {
                PERROR("[-] Invalid import table section.\n");
                free(libData);
                return 0;
            }

            PIMAGE_IMPORT_DESCRIPTOR IDT = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(libData + (libIDataSection.PointerToRawData + (libIDataDir.VirtualAddress - libIDataSection.VirtualAddress)) );

            while (IDT->Name) {
                const char* moduleName = reinterpret_cast<char*>(libData + (IDT->Name - libIDataSection.VirtualAddress) + libIDataSection.PointerToRawData);

                char modulePath[MAX_PATH];
                if (!SearchForFullName(moduleName, modulePath)) {
                    PERROR("[-] Could not find full path of module named '%s'.. Injection process is being cancelled.\n", moduleName);
                    free(libData);
                    return 0;
                }

                ULONG_PTR moduleBase = GetNtModuleHandle(procHandle, moduleName);
                if (moduleBase == 0) {
                    printf("[*] Import depend '%s' module in progress.\n\n", moduleName);

                    moduleBase = IManualLoad(procHandle, modulePath, execution);
                    if (moduleBase == 0) {
                        PERROR("[-] Failed to load import module.. Injection process is being cancelled.\n");
                        free(libData);
                        return 0;
                    }
                }

                PIMAGE_THUNK_DATA ILT = reinterpret_cast<PIMAGE_THUNK_DATA>(libData + libIDataSection.PointerToRawData + (IDT->OriginalFirstThunk - libIDataSection.VirtualAddress));
                PIMAGE_THUNK_DATA IAT = reinterpret_cast<PIMAGE_THUNK_DATA>(libData + libIDataSection.PointerToRawData + (IDT->FirstThunk - libIDataSection.VirtualAddress));

                char lastForwardModule[256];
                char frwdModulePath[MAX_PATH];

                for (int i = 0; ILT->u1.Function != 0; ILT++, IAT++, i++) {

                    char* forwardModule = nullptr;
                    char* forwardName = nullptr;

                    //Get dll list from process
                    //If dll is already imported in process, get that dll information by using PEB
                    //Open PE Header of that dll file, locate the export table and search which function's rva and sum it with dll baseAddress which came from PEB
                    //If its not imported, find full dll path then call this function again for not imported dll then return the baseAddress and sum it with function rva
                    //IAT->u1.Function will be changed to new function address;

                    ULONG_PTR funcAddress = 0;
                    if (IMAGE_SNAP_BY_ORDINAL(ILT->u1.AddressOfData)) {
                        //Get Function Address by its ordinal number

                        funcAddress = GetFuncAddressFromFile(modulePath, ILT->u1.Ordinal, nullptr, &forwardModule, &forwardName);
                        if (funcAddress == 0) {
                            PERROR("[-] Failed to find imported ordinal function '%lX'.. Injection process is being cancelled.\n", ILT->u1.Ordinal);
                            free(libData);
                            return 0;
                        }
                    }
                    else
                    {
                        //Get Function Address by its name

                        PIMAGE_IMPORT_BY_NAME hintNameTable = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(libData + libIDataSection.PointerToRawData + (ILT->u1.AddressOfData - libIDataSection.VirtualAddress));
                        if (hintNameTable == nullptr) {
                            PERROR("[-] Failed to read hint/name table.\n");
                            free(libData);
                            return 0;
                        }

                        funcAddress = GetFuncAddressFromFile(modulePath, 0, hintNameTable->Name, &forwardModule, &forwardName);
                        if (funcAddress == 0) {
                            PERROR("[-] Failed to find imported function '%s' in '%s'.. Injection process is being cancelled.\n", hintNameTable->Name, moduleName);
                            free(libData);
                            return 0;
                        }
                    }

                    //Check if its a forwarder function
                    //DEBUG DEBUG DEBUG
                    if (forwardModule && forwardName) {
                        if (strcmp(forwardModule, lastForwardModule) != 0) {
                            strcpy(lastForwardModule, forwardModule);

                            if (!SearchForFullName(forwardModule, frwdModulePath)) {
                                PERROR("[-] Could not find full path of module named '%s'.. Injection process is being cancelled.\n", forwardModule);
                                free(libData);
                                return 0;
                            }
                        }

                        ULONG_PTR frwdModuleBase = GetNtModuleHandle(procHandle, forwardModule);
                        if (frwdModuleBase == 0) {
                            printf("[*] Import forwarder '%s' library in progress.\n", forwardModule);

                            frwdModuleBase = IManualLoad(procHandle, frwdModulePath, execution);
                            if (frwdModuleBase == 0) {
                                PERROR("[-] Failed to load import module.. Injection process is being cancelled.\n");
                                free(libData);
                                return 0;
                            }
                        }

                        funcAddress = GetFuncAddressFromFile(frwdModulePath, 0, forwardName);
                        if (funcAddress == 0) {
                            PERROR("[-] Failed to find forwarded function '%s'.. Injection process is being cancelled.\n", forwardName);
                            free(libData);
                            return 0;
                        }

                        IAT->u1.Function = frwdModuleBase + funcAddress;

                        continue;
                    }

                    IAT->u1.Function = moduleBase + funcAddress;
                }

                IDT++;
            }

            printf("[*] Import Address Table fixed.\n");
        }

        //Loop all sections from pe file header and write section bytes into process memory from file data
        PIMAGE_SECTION_HEADER libSections = IMAGE_FIRST_SECTION(libNtHeader);

        for (int i = 0; i < libNtHeader->FileHeader.NumberOfSections; i++) {
            if (ntWriteVirtualMemory(procHandle, reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(baseAddress) + libSections[i].VirtualAddress), libData + libSections[i].PointerToRawData, libSections[i].SizeOfRawData, nullptr) != NTSTATUS_SUCCESS) {
                PERROR("[-] Failed to write section address.\n");
                free(libData);
                return 0;
            }
        }

        printf("[*] All sections copied.\n");

        //Check if there is entry point in dll, if there is no entry point then you dont need to call this
        if (libNtHeader->OptionalHeader.AddressOfEntryPoint != 0) {
            //We need to write shellcode to execute our library in process
            //Write our shellcode into process memory that will allow us to run TLS fix and DllMain call
            PVOID shellCodeBase = nullptr;
            SIZE_T shellCodeSize = 0x1000;

            if (ntAllocateVirtualMemoryEx(procHandle, &shellCodeBase, &shellCodeSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE, nullptr, 0) != NTSTATUS_SUCCESS) {
                PERROR("[-] Failed to allocate shellcode.\n");
                free(libData);
                return 0;
            }

            PINFO("[*] Shellcode allocated at %p with size %lu\n", shellCodeBase, shellCodeSize);

            if (ntWriteVirtualMemory(procHandle, shellCodeBase, reinterpret_cast<PVOID>(shellCode), 0x1000, nullptr) != NTSTATUS_SUCCESS) {
                PERROR("[-] Failed to write shellcode.\n");
                free(libData);
                return 0;
            }

            PVOID shellCodeArgsBase = nullptr;
            ULONG_PTR shellCodeArgsSize = sizeof(DLL_MAIN_ARGS);

            DLL_MAIN_ARGS args = {};
            args.imageBase = libNtHeader->OptionalHeader.ImageBase;
            args.entryPoint = libNtHeader->OptionalHeader.AddressOfEntryPoint;
            args.tlsAddress = libNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            args.baseAddress = baseAddress;

            if (ntAllocateVirtualMemoryEx(procHandle, &shellCodeArgsBase, &shellCodeArgsSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE, nullptr, 0) != NTSTATUS_SUCCESS) {
                PERROR("[-] Failed to allocate shellcode parameters.\n");
                free(libData);
                return 0;
            }

            if (ntWriteVirtualMemory(procHandle, shellCodeArgsBase, &args, sizeof(args), nullptr) != NTSTATUS_SUCCESS) {
                PERROR("[-] Failed to write shellcode parameters.\n");
                free(libData);
                return 0;
            }

            //Execute the shellcode function
            if (!execution(procHandle, shellCodeBase, shellCodeArgsBase)) {
                PERROR("[-] Failed to execute shellcode.\n");
                free(libData);
                return 0;
            }

            printf("[*] Shellcode executed.\n");
        }

        free(libData);

        return reinterpret_cast<ULONG_PTR>(baseAddress);
    }
}