#include<Windows.h>
#include<tchar.h>
#include"auxiliary.h"

int _tmain(int argc, TCHAR* argv[])
{
	if (argc != 4) {
		displayHelp();
		return -1;
	}
	if (_tcscmp(argv[1], _T("-1")) == 0) {
		demoCreateRemoteThread(argv[2], findPidByName(argv[3]));
	}
	else if (_tcscmp(argv[1], _T("-2")) == 0) {
		demoNtCreateThreadEx(argv[2], findPidByName(argv[3]));
	}
	else if (_tcscmp(argv[1], _T("-3")) == 0) {
		demoQueueUserAPC(argv[2], findPidByName(argv[3]));
	}
	else if (_tcscmp(argv[1], _T("-4")) == 0) {
		demoSetWindowsHookEx(argv[2], findPidByName(argv[3]));
	}
	else if (_tcscmp(argv[1], _T("-5")) == 0) {
		demoRtlCreateUserThread(argv[2], findPidByName(argv[3]));
	}
	else if (_tcscmp(argv[1], _T("-6")) == 0) {
		demoSetThreadContext(argv[2], findPidByName(argv[3]));
	}
	else {
		displayHelp();
		return -1;
	}
	return 0;
}

//int _tmain(int argc, TCHAR* argv[])
//{
//	return 0;
//}