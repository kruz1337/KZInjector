#include "includes.h"
#include "nt.h"

int main(int argc, char *argv[])
{
	Utils::InitConsole();

	if (argc < 3) {
		PERROR("[-] Invalid parameters. Usage:\n");
		printf("> KZInjector.exe \"PID/PNAME\" \"LIB PATH\" --injection/-i [\"LoadLibrary\", \"ManualMap\"] --execution/-e [\"CreateThread\", \"ThreadHijack\"]\n");
		return -1;
	}

	long long inputProcId = strtoll(argv[1], nullptr, 10);

    if (!winNtInjection::Initialize()) {
        PERROR("[-] Failed to initialize NT Base.\n");
        return -1;
    }

	HANDLE processId = inputProcId ? reinterpret_cast<HANDLE>(inputProcId) : winNtInjection::GetProcessIdByName(argv[1]);
	if (!processId) {
		PERROR("[-] Failed to find process.\n");
		return -1;
	}

	HANDLE processHandle = winNtInjection::OpenNtProcessById(processId);
	if (!processHandle) {
		PERROR("[-] Failed to open process handle.\n");
		return -1;
	}

	char libPath[1024];
	GetFullPathNameA(argv[2], 1024, libPath, nullptr);

	const char* injType = Utils::GetArgValue(argv, "--injection", "-i");
	const char* excType = Utils::GetArgValue(argv, "--execution", "-e");

	injType = injType ? injType : "LoadLibrary";
	excType = excType ? excType : "CreateThread";

	printf("[*] INJECTION: %s\n", injType);
	printf("[*] EXECUTION: %s\n", excType);
	printf("[*] PID: %.6d\n", processId);
	printf("[*] DLL: %s\n\n", libPath);

	bool (*executeFunc)(HANDLE procHandle, PVOID shellCodeBase, PVOID shellArgBase) = winNtInjection::ECreateThreadEx;
	ULONG_PTR (*injectFunc)(HANDLE procHandle, const char* path, bool execution(HANDLE, PVOID, PVOID)) = (ULONG_PTR(*)(HANDLE procHandle, const char* path, bool execution(HANDLE, PVOID, PVOID)))winNtInjection::ILdrLoadDll;

	if (strcmp(injType, "ManualMap") == 0) {
		injectFunc = winNtInjection::IManualLoad;
	}

	if (strcmp(excType, "ThreadHijack") == 0) {
		executeFunc = winNtInjection::EThreadHijack;
	}

	if (injectFunc == nullptr) {
		PERROR("[-] Invalid injection function.\n");
		return -1;
	}

	if (!injectFunc(processHandle, libPath, executeFunc)) {
		PERROR("[-] Injection failed.\n");
		return -1;
	}

	PSUCCES("\n[+] Injection succeed.\n");

    return 0;
}
