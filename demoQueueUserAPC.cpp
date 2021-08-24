#include<Windows.h>
#include<tchar.h>
#include<TlHelp32.h>

BOOL demoQueueUserAPC(PCTSTR pszDllFile, DWORD dwProccessId)
{
	BOOL result = TRUE;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProccessId);
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
	WriteProcessMemory(hProcess, pszDllNameBuf, pszDllFile, dwDllNameSize,NULL);

	HMODULE hKernel32 = GetModuleHandle(_T("Kernel32"));
	if (hKernel32 == NULL) {
		_tprintf(_T("GetModuleHandle failed\n"));
		return FALSE;
	}
	PVOID pfnLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
	if (pfnLoadLibraryW == NULL) {
		_tprintf(_T("GetProcAddress failed\n"));
		return FALSE;
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("CreateToolhelp32Snapshot failed\n"));
		return FALSE;
	}
	DWORD dwThreadId = 0;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == dwProccessId) {
				dwThreadId = threadEntry.th32ThreadID;
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, dwThreadId);
				if (hThread == NULL)
					_tprintf(_T("OpenThread %d failed\n"),dwThreadId);
				else {
					DWORD dwInjectResult = QueueUserAPC((PAPCFUNC)pfnLoadLibraryW, hThread, (ULONG_PTR)pszDllNameBuf);
					if (dwInjectResult)
						_tprintf(_T("Inject thread %d successfully\n"),dwThreadId);
					else
						_tprintf(_T("Inject thread %d failly\n"), dwThreadId);
					CloseHandle(hThread);
				}
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}
	if (!dwThreadId) {
		_tprintf(_T("No threads found in thr target process\n"));
		result = FALSE;
	}
	CloseHandle(hSnapshot);
	CloseHandle(hProcess);
	return result;
}