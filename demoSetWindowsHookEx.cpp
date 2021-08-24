#include<Windows.h>
#include<stdio.h>
#include<tchar.h>
#include"auxiliary.h"

BOOL demoSetWindowsHookEx(PCTSTR pszDllFile, DWORD dwProcessId)
{
	DWORD dwThreadId = getThreadID(dwProcessId);
	if (dwThreadId == 0) {
		_tprintf(_T("getAnyOneThreadID failed\n"));
		return FALSE;
	}

	getchar();
	HMODULE myDll = LoadLibraryEx(pszDllFile, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (myDll == NULL) {
		_tprintf(_T("LoadLibraryEx failed\n"));
		return FALSE;
	}
	HOOKPROC myHookProc = (HOOKPROC)GetProcAddress(myDll, "myhook");
	if (myHookProc == NULL) {
		_tprintf(_T("GetProcAddress failed\n"));
		return FALSE;
	}

	HHOOK hHook = SetWindowsHookEx(WH_KEYBOARD, myHookProc, myDll, dwThreadId);
	if (hHook == NULL) {
		_tprintf(_T("SetWindowsHookEx failed [%d]\n"), GetLastError());
		return FALSE;
	}
	_tprintf(_T("Hook successfully\nPress enter to unhook the function and stop the program.\n"));
	getchar();
	UnhookWindowsHookEx(hHook);
	CloseHandle(hHook);
	CloseHandle(myDll);
	return TRUE;
}