#ifndef _THREADHOOK
#define _THREADHOOK
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <winternl.h>
#include "src/Detours/include/detours.h"
#pragma comment(lib, "psapi.lib")
#pragma comment(lib,"detours.lib")

#ifdef _WIN64
typedef DWORD64 DWORDX;
#else
typedef DWORD32 DWORDX;
#endif // _WIN64



static uintptr_t g_ThreadAdr[10];
static int g_ThreadAdrNum = 0;
static HANDLE g_ThreadHandle;
typedef DWORDX(WINAPI* NTCREATETHREADEX)(
	PHANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES,
	HANDLE,
	PTHREAD_START_ROUTINE,
	PVOID,
	BOOLEAN,
	ULONG,
	SIZE_T,
	SIZE_T,
	LPVOID);
typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;    //退出状态
	PVOID TebBaseAddress;   //Teb基地址
	CLIENT_ID ClientId;     //客户端ID
	ULONG_PTR AffinityMask; //关联掩码
	LONG Priority;          //优先级
	LONG BasePriority;      //基本优先级
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS2 {
	ThreadQuerySetWin32StartAddress = 9,
	ThreadBasicInformation = 0
} THREADINFOCLASS2;

typedef NTSTATUS(WINAPI* ZWQUERYINFORMATIONTHREAD)(
	HANDLE ThreadHandle,
	THREADINFOCLASS2 ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);

static NTCREATETHREADEX fpNtCreateThreadEX = NULL;

void cheatThread();
DWORDX WINAPI DetourNtCreateThreadEX(PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PTHREAD_START_ROUTINE lpStartAddress,
	PVOID Parameter,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	SIZE_T StackCommit,
	SIZE_T StackReserve,
	LPVOID pThreadExData);
void ShowConsoleOutput();
void EnumerateThreadsInModule(DWORD dwProcessId, std::vector<DWORD>& m_threadIds);
std::wstring RegularProcessingText(TCHAR* modname);
void one(DWORD _Threadid);
void two(LPCWSTR _dllname);
void three();
void A_main();
#endif // !THREADHOOK