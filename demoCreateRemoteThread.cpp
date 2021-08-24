#include<Windows.h>
#include<tchar.h>

BOOL demoCreateRemoteThread(PCTSTR pszDllFile, DWORD dwProcessId) {

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		_tprintf(_T("OpenProcess failed\n"));
		return FALSE;
	}

	DWORD dwDllNameSize = (DWORD)(_tcslen(pszDllFile) + 1) * sizeof(TCHAR);
	PVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwDllNameSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL) {
		_tprintf(_T("VirtualAllocEx failed\n"));
		return FALSE;
	}
	WriteProcessMemory(hProcess, pRemoteBuf, pszDllFile, dwDllNameSize, NULL);

	HMODULE hKernel32 = GetModuleHandle(_T("Kernel32"));
	if (hKernel32 == NULL) {
		_tprintf(_T("GetModuleHandle failed\n"));
		return FALSE;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW"), pRemoteBuf, 0, NULL);
	if (hThread == NULL) {
		_tprintf(_T("CreateRemoteThread failly [%d]\n"),GetLastError());
		return FALSE;
	}
	_tprintf(_T("Inject successfully\n"));

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hKernel32);
	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}