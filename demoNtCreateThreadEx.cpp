#include<Windows.h>
#include<tchar.h>
#include"auxiliary.h"

BOOL demoNtCreateThreadEx(PCTSTR pszDllFile, DWORD dwProcessId)
{
	HANDLE hRemoteThread = NULL;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		_tprintf(_T("OpenProcess failed\n"));
		return FALSE;
	}

	DWORD dwDllNameSize = (DWORD)(_tcslen(pszDllFile) + 1) * sizeof(TCHAR);
	PVOID pszDllNameBuf = VirtualAllocEx(hProcess, NULL, dwDllNameSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszDllNameBuf == NULL) {
		_tprintf(_T("VirtualAllocEx failed\n"));
		return FALSE;
	}
	WriteProcessMemory(hProcess, pszDllNameBuf, pszDllFile, dwDllNameSize, NULL);

	HMODULE hKernel32 = GetModuleHandle(_T("Kernel32"));
	if (hKernel32 == NULL) {
		_tprintf(_T("GetModuleHandle failed\n"));
		return FALSE;
	}

	HMODULE hNtdll = GetModuleHandle(_T("Ntdll.dll"));
	if (hNtdll == NULL) {
		_tprintf(_T("GetModuleHandle failed\n"));
		return FALSE;
	}

	FNNtCreateThreadEx fnNtCreateThreadEx = (FNNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	NTSTATUS status = fnNtCreateThreadEx(&hRemoteThread, 0x1fffff, NULL, hProcess, (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW"), pszDllNameBuf, FALSE, NULL, NULL, NULL, NULL);
	if (status != NULL) {
		_tprintf(_T("NtCreateThreadEx failed\n"));
		return FALSE;
	}
	_tprintf(_T("Inject successfully\n"));
	VirtualFreeEx(hProcess, pszDllNameBuf,0,MEM_RELEASE);
	CloseHandle(hNtdll);
	CloseHandle(hKernel32);
	CloseHandle(hProcess);
	return TRUE;
}