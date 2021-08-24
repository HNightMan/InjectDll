#include<Windows.h>
#include<tchar.h>
#include"auxiliary.h"

#ifndef _WIN64
unsigned char payload[] =
{
	0x68, 0xef, 0xbe, 0xad, 0xde,	// push 0xDEADBEEF
	0x9c,							// pushfd
	0x60,							// pushad
	0x68, 0xef, 0xbe, 0xad, 0xde,	//push 0xDEADBEEF
	0xb8, 0xef, 0xbe, 0xad, 0xde,	// mov eax, 0xDEADBEEF
	0xff, 0xd0,						// call eax
	0x61,							// popad
	0x9d,							//popfd
	0xc3							//ret
};
#else
unsigned char payload[] = {
	// sub rsp, 28h
	0x48, 0x83, 0xec, 0x28,
	// mov [rsp + 18], rax
	0x48, 0x89, 0x44, 0x24, 0x18,
	// mov [rsp + 10h], rcx
	0x48, 0x89, 0x4c, 0x24, 0x10,
	// mov rcx, 11111111111111111h
	0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	// mov rax, 22222222222222222h
	0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	// call rax
	0xff, 0xd0,
	// mov rcx, [rsp + 10h]
	0x48, 0x8b, 0x4c, 0x24, 0x10,
	// mov rax, [rsp + 18h]
	0x48, 0x8b, 0x44, 0x24, 0x18,
	// add rsp, 28h
	0x48, 0x83, 0xc4, 0x28,
	// mov r11, 333333333333333333h
	0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	// jmp r11
	0x41, 0xff, 0xe3
};

//unsigned char payload[] = {
//	0x50, // push rax (save rax)
//	0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for return address)
//	0x9c,                                                                   // pushfq
//	0x51,                                                                   // push rcx
//	0x52,                                                                   // push rdx
//	0x53,                                                                   // push rbx
//	0x55,                                                                   // push rbp
//	0x56,                                                                   // push rsi
//	0x57,                                                                   // push rdi
//	0x41, 0x50,                                                             // push r8
//	0x41, 0x51,                                                             // push r9
//	0x41, 0x52,                                                             // push r10
//	0x41, 0x53,                                                             // push r11
//	0x41, 0x54,                                                             // push r12
//	0x41, 0x55,                                                             // push r13
//	0x41, 0x56,                                                             // push r14
//	0x41, 0x57,                                                             // push r15
//	0x68, 0xef,0xbe,0xad,0xde,
//	0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rcx, 0CCCCCCCCCCCCCCCCh (place holder for DLL path name)
//	0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for LoadLibrary)
//	0xFF, 0xD0,                // call rax (call LoadLibrary)
//	0x58, // pop dummy
//	0x41, 0x5F,                                                             // pop r15
//	0x41, 0x5E,                                                             // pop r14
//	0x41, 0x5D,                                                             // pop r13
//	0x41, 0x5C,                                                             // pop r12
//	0x41, 0x5B,                                                             // pop r11
//	0x41, 0x5A,                                                             // pop r10
//	0x41, 0x59,                                                             // pop r9
//	0x41, 0x58,                                                             // pop r8
//	0x5F,                                                                   // pop rdi
//	0x5E,                                                                   // pop rsi
//	0x5D,                                                                   // pop rbp
//	0x5B,                                                                   // pop rbx
//	0x5A,                                                                   // pop rdx
//	0x59,                                                                   // pop rcx
//	0x9D,                                                                   // popfq
//	0x58,                                                                   // pop rax
//	0xC3                                                                    // ret
//};
#endif

BOOL demoSetThreadContext(PCTSTR pszDllFile, DWORD dwProcessId)
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
	PVOID pfnLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
	if (pfnLoadLibraryW == NULL) {
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

	DWORD dwPayloadSize = sizeof(payload);
	PVOID payloadBuf = VirtualAllocEx(hProcess, NULL, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (payloadBuf == NULL) {
		_tprintf(_T("VirtualAllocEx failed\n"));
		return FALSE;
	}

	DWORD dwThrreadId = getThreadID(dwProcessId);
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, dwThrreadId);
	if (hThread == NULL) {
		_tprintf(_T("OpenThread failed\n"));
		return FALSE;
	}
	SuspendThread(hThread);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(hThread, &ctx) == 0) {
		_tprintf(_T("GetThreadContext failed\n"));
		return FALSE;
	}
#ifndef _WIN64
	DWORD dwOldIP = ctx.Eip;
	ctx.Eip = (DWORD)payloadBuf;
	memcpy(payload + 1, &dwOldIP, 4);
	memcpy(payload + 8, &pszDllNameBuf, 4);
	memcpy(payload + 13, &pfnLoadLibraryW, 4);
#else
	DWORD_PTR dwOldIP = ctx.Rip;
	ctx.Rip = (DWORD_PTR)payloadBuf;
	memcpy(payload + 52, &dwOldIP, 8);
	memcpy(payload + 16, &pszDllNameBuf, 8);
	memcpy(payload + 26, &pfnLoadLibraryW, 8);
#endif

	WriteProcessMemory(hProcess, payloadBuf, payload, dwPayloadSize, NULL);

	SetThreadContext(hThread, &ctx);
	ResumeThread(hThread);
	_tprintf(_T("Inject seccessfully\n"));
	Sleep(6000);

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, payloadBuf, dwPayloadSize, MEM_COMMIT);
	VirtualFreeEx(hProcess, pszDllNameBuf, dwDllNameSize, MEM_COMMIT);
	CloseHandle(hKernel32);
	CloseHandle(hProcess);

	return TRUE;
}