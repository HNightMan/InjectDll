#pragma once
DWORD findPidByName(wchar_t* pname);
VOID displayHelp();
DWORD checkOS();
DWORD getThreadID(DWORD pid);
BOOL SetSePrivilege();
BOOL demoCreateRemoteThread(PCTSTR pszDllFile, DWORD dwProcessId);
BOOL demoNtCreateThreadEx(PCTSTR pszDllFile, DWORD dwProcessId);
BOOL demoQueueUserAPC(PCTSTR pszDllFile, DWORD dwProcessId);
BOOL demoSetWindowsHookEx(PCTSTR pszDllFile, DWORD dwProcessId);
BOOL demoRtlCreateUserThread(PCTSTR pszDllFile, DWORD dwProcessId);
BOOL demoSetThreadContext(PCTSTR pszDllFile, DWORD dwProcessId);

struct NtCreateThreadExBuffer {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};

typedef NTSTATUS(WINAPI* FNNtCreateThreadEx) (
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer
	);

typedef DWORD(WINAPI* FNRtlCreateUserThread)(
	IN HANDLE 					ProcessHandle,
	IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	IN BOOL 					CreateSuspended,
	IN ULONG					StackZeroBits,
	IN OUT PULONG				StackReserved,
	IN OUT PULONG				StackCommit,
	IN LPVOID					StartAddress,
	IN LPVOID					StartParameter,
	OUT HANDLE 					ThreadHandle,
	OUT LPVOID					ClientID
	);