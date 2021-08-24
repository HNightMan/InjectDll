#include<Windows.h>
#include<tchar.h>
#include"auxiliary.h"

BOOL demoRtlCreateUserThread(PCTSTR pszDllFile, DWORD dwProcessId)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		_tprintf(_T("OpenProcess failed\n"));
		return FALSE;
	}

	HMODULE hKernel32 = GetModuleHandle(_T("Kernel32"));
	if (hKernel32 == NULL) {
		_tprintf(_T("GetModuleHandle failed\n"));
		return FALSE;
	}

	HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
	if (hNtdll == NULL) {
		_tprintf(_T("GetModuleHandle failed\n"));
		return FALSE;
	}
	FNRtlCreateUserThread fnRtlCreateUserThread = (FNRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
	if (fnRtlCreateUserThread == NULL) {
		_tprintf(_T("GetProcAddress failed\n"));
		return FALSE;
	}

	DWORD dwDllNameSize = (DWORD)(_tcslen(pszDllFile) + 1) * sizeof(TCHAR);
	PVOID pszDllNameBuf = VirtualAllocEx(hProcess, NULL, dwDllNameSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszDllNameBuf == NULL) {
		_tprintf(_T("VirtualAllocEx failed\n"));
		return FALSE;
	}
	WriteProcessMemory(hProcess, pszDllNameBuf, pszDllFile, dwDllNameSize, NULL);

	HANDLE  hRemoteThread = NULL;
	NTSTATUS status = fnRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW"), pszDllNameBuf, &hRemoteThread, NULL);
	if (status != NULL) {
		_tprintf(_T("RtlCreateUserThread failed\n"));
		return FALSE;
	}
	_tprintf(_T("Inject successfully\n"));
	VirtualFreeEx(hProcess, pszDllNameBuf, 0, MEM_RELEASE);
	CloseHandle(hNtdll);
	CloseHandle(hKernel32);
	CloseHandle(hProcess);
	return TRUE;
}