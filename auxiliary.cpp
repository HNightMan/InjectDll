#include<Windows.h>
#include<tchar.h>
#include<TlHelp32.h>
#include "auxiliary.h"

DWORD findPidByName(wchar_t* pname)
{
	PROCESSENTRY32 procEntry;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("CreateToolhelp32Snapshot failed\n"));
		return 0;
	}
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &procEntry)) {
		do {
			if (_tcscmp(procEntry.szExeFile, pname) == 0) {
				DWORD pid = procEntry.th32ProcessID;
				_tprintf(_T("%s pid: %d\n"), pname, pid);
				CloseHandle(hSnapshot);
				return pid;
			}
		} while (Process32Next(hSnapshot, &procEntry));
	}
	else
		_tprintf(_T("Process32First failed\n"));
	_tprintf(_T("Process not found\n"));
	CloseHandle(hSnapshot);
	return 0;
}

VOID displayHelp()
{
	_tprintf(_T("Options:\n"));
	_tprintf(_T("-1 CreateRemoteThread\n"));
	_tprintf(_T("-2 NtCreateThreadEx\n"));
	_tprintf(_T("-3 QueueUserAPC\n"));
	_tprintf(_T("-4 SetWindowsHookEx\n"));
	_tprintf(_T("-5 RtlCreateUserThread\n"));
	_tprintf(_T("-6 SetThreadContext\n"));
}

DWORD getThreadID(DWORD pid)
{
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("CreateToolhelp32Snapshot failed\n"));
		return 0;
	}
	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == pid) {
				_tprintf(_T("Thread %d found\n"), threadEntry.th32ThreadID);
				CloseHandle(hSnapshot);
				return threadEntry.th32ThreadID;
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}
	else
		_tprintf(_T("Thread32First failed\n"));
	_tprintf(_T("Thread not found\n"));
	CloseHandle(hSnapshot);
	return 0;
}
