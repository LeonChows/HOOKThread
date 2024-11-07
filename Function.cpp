#include "Function.h"

void cheatThread()
{
	std::cout << "Create + 1" << std::endl;
	SuspendThread(g_ThreadHandle);
	BOOL status = TerminateThread(g_ThreadHandle, 0);
	std::cout << "Kill!!!!" << std::endl;
}

DWORDX __stdcall DetourNtCreateThreadEX(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PTHREAD_START_ROUTINE lpStartAddress, PVOID Parameter, BOOLEAN CreateSuspended, ULONG StackZeroBits, SIZE_T StackCommit, SIZE_T StackReserve, LPVOID pThreadExData)
{
	DWORD status;
	//std::cout << "all thread to address" << lpStartAddress << std::endl;
	for (size_t i = 1; i < g_ThreadAdrNum + 1; i++)
	{
		//std::cout << "my thread to address：" << std::hex << std::uppercase << g_ThreadAdr[i] << std::endl;
		DWORDX TempAdr = (DWORDX)lpStartAddress;
		if (TempAdr == g_ThreadAdr[i])
		{
			//std::cout << "find to threads address：" << std::hex << std::uppercase << g_ThreadAdr[i] << std::endl;
			lpStartAddress = (PTHREAD_START_ROUTINE)&cheatThread;
			//std::cout << "cheats to threads address：" << lpStartAddress << std::endl;
			g_ThreadHandle = ThreadHandle;
			status = fpNtCreateThreadEX(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, Parameter, CreateSuspended, StackZeroBits, StackCommit, StackReserve, pThreadExData);
			return status;
		}
	}
	status = fpNtCreateThreadEX(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, Parameter, CreateSuspended, StackZeroBits, StackCommit, StackReserve, pThreadExData);
	return status;
}

// 使用 Unicode 宽字符版本的控制台输出
void ShowConsoleOutput()
{
	// 分配一个新的控制台
	if (AllocConsole())
	{
		// 将标准输出流和标准输入流重定向到新的控制台
		FILE* fp;
		freopen_s(&fp, "CONOUT$", "w", stdout);
		freopen_s(&fp, "CONOUT$", "w", stderr);
		freopen_s(&fp, "CONIN$", "r", stdin);

		// 获取控制台句柄
		HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

		// 设置文本颜色
		SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

		// 输出 ASCII 图案
		std::cout <<
			"  .----------------.  .----------------.  .-----------------. .------------------. \n" <<
			"  | .--------------. || .--------------. || .--------------. || .--------------. |\n" <<
			"  | |  ___  ____   | || |     _____    | || | ____  _____  | || |    ______    | |\n" <<
			"  | | |_  ||_  _|  | || |    |_   _|   | || ||_   \\|_   _| | || |  .' ___  |   | |\n" <<
			"  | |   | |_/ /    | || |      | |     | || |  |   \\ | |   | || | / .'   \\_|   | |\n" <<
			"  | |   |  __'.    | || |      | |     | || |  | |\\ \\| |   | || | | |    ____  | |\n" <<
			"  | |  _| |  \\ \\_  | || |     _| |_    | || | _| |_\\   |_  | || | \\ `.___]  _| | |\n" <<
			"  | | |____||____| | || |    |_____|   | || ||_____|\\____| | || |  `._____.'   | |\n" <<
			"  | |              | || |              | || |              | || |              | |\n" <<
			"  | '--------------' || '--------------' || '--------------' || '--------------' |\n" <<
			"  '----------------'  '----------------'  '----------------'  '------------------' \n";
		std::cout << "I'am come here.." << std::endl;
		std::cout << "Do you want kill to threads?" << std::endl;
		std::cout << "Maybe I can help you.." << std::endl;
		std::cout << "Do you want to kill one thread or want to kill in module to threads or kill all threads?" << std::endl;
		std::cout << "Please tell me.." << std::endl;
		std::cout << "1. one thread" << std::endl;
		std::cout << "2. in module to threads" << std::endl;
		std::cout << "3. all threads" << std::endl;

		int SParam;
		std::cin >> SParam;
		std::wstring Param;

		switch (SParam)
		{
		case 1:
			std::cout << "input your want kill in Thread ID" << std::endl;
			std::wcin >> Param;
			std::wcout << _wtoi(Param.c_str()) << std::endl;
			#ifdef _WIN64
			one(_wtoi64(Param.c_str()));
			#else
			one(_wtoi(Param.c_str()));
			#endif // _WIN64
			break;
		case 2:
			std::cout << "input your want kill in module" << std::endl;
			std::wcin >> Param;
			two(Param.c_str());
			break;
		case 3:
			three();
			getchar();
			break;
		default:
			break;
		}
	}
	else
	{
		std::cerr << "Failed to allocate console." << std::endl;
	}
}

void EnumerateThreadsInModule(DWORD dwProcessId, std::vector<DWORD>& m_threadIds)
{
	// 创建线程快照
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnapshot == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to create thread snapshot." << std::endl;
		return;
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	// 遍历线程快照
	if (Thread32First(hThreadSnapshot, &te))
	{
		do
		{
			if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
				sizeof(te.th32OwnerProcessID))
			{
				// 检查线程是否属于指定进程
				if (te.th32OwnerProcessID == dwProcessId)
				{
					std::cout << "Thread ID :\t" << te.th32ThreadID << std::endl;
					m_threadIds.push_back(te.th32ThreadID);
				}
			}
			te.dwSize = sizeof(THREADENTRY32);
		} while (Thread32Next(hThreadSnapshot, &te));
	}
	CloseHandle(hThreadSnapshot);
}

std::wstring RegularProcessingText(TCHAR* modname)
{
	std::wstring text = modname;

	// 找到最后一个反斜杠的位置
	size_t lastSlashPos = text.find_last_of(L'\\');

	if (lastSlashPos != std::wstring::npos && lastSlashPos < text.length() - 1) {
		std::wstring result = text.substr(lastSlashPos + 1);
		//std::wcout << L"最后一个反斜杠后面的文本: " << result << std::endl;
		return result;
	}
	else {
		//std::wcout << L"没有找到最后一个反斜杠或者反斜杠后面没有文本。" << std::endl;
		return L"";
	}
}

void one(DWORD _Threadid) 
{
	std::vector<DWORD> threadIds;
	PVOID startaddr;                    // 用来接收线程入口地址
	std::wstring TempUText;
	NTSTATUS status;
	DWORD processId = GetCurrentProcessId();
	std::cout << "ProcessID:\t" << processId << std::endl;

	EnumerateThreadsInModule(processId, threadIds);
	for (DWORD dwThreadId : threadIds) {
		DWORD m_ThreadID = dwThreadId;
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
		// 将区域设置设置为从操作系统获取的ANSI代码页
		setlocale(LC_ALL, ".ACP");
		// 获取 ntdll.dll 的模块句柄
		HINSTANCE hNTDLL = ::GetModuleHandle(L"ntdll");
		// 从 ntdll.dll 中取出 ZwQueryInformationThread
		ZWQUERYINFORMATIONTHREAD ZwQueryInformationThread = reinterpret_cast<ZWQUERYINFORMATIONTHREAD>(GetProcAddress(hNTDLL, "ZwQueryInformationThread"));
		if (ZwQueryInformationThread == NULL) {
			std::cerr << "Error: GetProcAddress failed." << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		// 获取线程的所有信息
		THREAD_BASIC_INFORMATION threadBasicInfo;
		status = ZwQueryInformationThread(
			hThread,
			ThreadBasicInformation,
			&threadBasicInfo,
			sizeof(threadBasicInfo),
			NULL
		);
		if (status != 0) {
			std::cerr << "Error: ZwQueryInformationThread failed with status 0x" << std::hex << status << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		//std::cout << "===================================================================" << std::endl;
		//std::cout << "进程ID：\t" << threadBasicInfo.ClientId.UniqueThread << std::endl;
		//std::cout << "线程ID：\t" << hThread << std::endl;
		//std::cout << "线程地址：\t" << threadBasicInfo.TebBaseAddress << std::endl;
		//std::cout << "线程退出代码：\t" << threadBasicInfo.ExitStatus << std::endl;
		//std::cout << dwThreadId << std::endl;
		status = ZwQueryInformationThread(
			hThread,                            // 线程句柄
			ThreadQuerySetWin32StartAddress,    // 线程信息类型，ThreadQuerySetWin32StartAddress ：线程入口地址
			&startaddr,                            // 指向缓冲区的指针
			sizeof(startaddr),                    // 缓冲区的大小
			NULL
		);
		if (status != 0) {
			std::cerr << "Error: ZwQueryInformationThread failed with status 0x" << std::hex << status << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		CloseHandle(hThread);
		//std::cout << "线程起始地址：\t" << startaddr << std::endl;
		if (_Threadid == m_ThreadID)
		{
			//std::cout << "确认线程起始地址：\t" << startaddr << std::endl;
			std::cout << "=============================KILL=========================" << std::endl;
			std::cout << "Thread id is: \t" << m_ThreadID << std::endl;
			std::cout << "Thread adr is：\t" << startaddr << std::endl;
			g_ThreadAdrNum++;
			g_ThreadAdr[g_ThreadAdrNum] = reinterpret_cast<uintptr_t>(startaddr);
			std::cout << "num：\t" << g_ThreadAdrNum << std::endl;
			std::cout << "adr：\t" << std::hex << std::uppercase << g_ThreadAdr[g_ThreadAdrNum] << std::endl;
			HANDLE m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_ThreadID);
			BOOL status = TerminateThread(m_hThread, threadBasicInfo.ExitStatus);
			//BYTE byte[] = {0xC2,0x01,0X00};
			//WriteProcessMemory(GetCurrentProcess(), (LPVOID)startaddr, &byte, sizeof(byte), NULL);
			CloseHandle(m_hThread);
			if (!status)
				std::cout << "Thread Close error...!" << std::endl;
			std::cout << "=============================KILLend=========================" << std::endl;
		}
	}

}

void two(LPCWSTR _dllname)
{

	std::vector<DWORD> threadIds;
	PVOID startaddr;                    // 用来接收线程入口地址
	std::wstring TempUText;
	NTSTATUS status;
	DWORD processId = GetCurrentProcessId();
	std::cout << "ProcessID:\t" << processId << std::endl;
	EnumerateThreadsInModule(processId, threadIds);
	for (DWORD dwThreadId : threadIds) {
		DWORD m_ThreadID = dwThreadId;
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
		// 将区域设置设置为从操作系统获取的ANSI代码页
		setlocale(LC_ALL, ".ACP");
		// 获取 ntdll.dll 的模块句柄
		HINSTANCE hNTDLL = ::GetModuleHandle(L"ntdll");
		// 从 ntdll.dll 中取出 ZwQueryInformationThread
		ZWQUERYINFORMATIONTHREAD ZwQueryInformationThread = reinterpret_cast<ZWQUERYINFORMATIONTHREAD>(GetProcAddress(hNTDLL, "ZwQueryInformationThread"));
		if (ZwQueryInformationThread == NULL) {
			std::cerr << "Error: GetProcAddress failed." << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		// 获取线程的所有信息
		THREAD_BASIC_INFORMATION threadBasicInfo;
		status = ZwQueryInformationThread(
			hThread,
			ThreadBasicInformation,
			&threadBasicInfo,
			sizeof(threadBasicInfo),
			NULL
		);
		if (status != 0) {
			std::cerr << "Error: ZwQueryInformationThread failed with status 0x" << std::hex << status << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		status = ZwQueryInformationThread(
			hThread,                            // 线程句柄
			ThreadQuerySetWin32StartAddress,    // 线程信息类型，ThreadQuerySetWin32StartAddress ：线程入口地址
			&startaddr,                            // 指向缓冲区的指针
			sizeof(startaddr),                    // 缓冲区的大小
			NULL
		);
		if (status != 0) {
			std::cerr << "Error: ZwQueryInformationThread failed with status 0x" << std::hex << status << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		CloseHandle(hThread);
		//std::cout << "线程起始地址：\t" << startaddr << std::endl;
		TCHAR modname[MAX_PATH];
		// 检查入口地址是否位于某模块中
		GetMappedFileName(
			GetCurrentProcess(),
			startaddr,                            // 要检查的地址
			modname,                            // 用来接收模块名的指针
			MAX_PATH                            // 缓冲区大小
		);
		// 处理模块路径
		TempUText = RegularProcessingText(modname);
		if (TempUText == L"")
			std::cout << "error path...!" << std::endl;
		//std::wcout << TempUText << std::endl;
		if (TempUText == _dllname)
		{
			std::cout << "=============================KILL=========================" << std::endl;
			std::wcout << _dllname;
			std::cout << "Thread id is: \t" << m_ThreadID << std::endl;
			std::wcout << _dllname;
			std::cout << "Thread adr is：\t" << startaddr << std::endl;
			g_ThreadAdrNum++;
			g_ThreadAdr[g_ThreadAdrNum] = reinterpret_cast<uintptr_t>(startaddr);
			std::cout << "num：\t" << g_ThreadAdrNum << std::endl;
			std::cout << "adr：\t" << std::hex << std::uppercase << g_ThreadAdr[g_ThreadAdrNum] << std::endl;
			HANDLE m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_ThreadID);
			BOOL status = TerminateThread(m_hThread, threadBasicInfo.ExitStatus);
			//BYTE byte[] = {0xC2,0x01,0X00};
			//WriteProcessMemory(GetCurrentProcess(), (LPVOID)startaddr, &byte, sizeof(byte), NULL);
			CloseHandle(m_hThread);
			if (!status)
				std::cout << "Thread Close error...!" << std::endl;
			std::cout << "=============================KILLend=========================" << std::endl;
		}
	}
}

void three()
{
	std::vector<DWORD> threadIds;
	PVOID startaddr;                    // 用来接收线程入口地址
	std::wstring TempUText;
	NTSTATUS status;
	DWORD processId = GetCurrentProcessId();
	std::cout << "ProcessID:\t" << processId << std::endl;

	EnumerateThreadsInModule(processId, threadIds);
	for (DWORD dwThreadId : threadIds) {
		DWORD m_ThreadID = dwThreadId;
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
		// 将区域设置设置为从操作系统获取的ANSI代码页
		setlocale(LC_ALL, ".ACP");
		// 获取 ntdll.dll 的模块句柄
		HINSTANCE hNTDLL = ::GetModuleHandle(L"ntdll");
		// 从 ntdll.dll 中取出 ZwQueryInformationThread
		ZWQUERYINFORMATIONTHREAD ZwQueryInformationThread = reinterpret_cast<ZWQUERYINFORMATIONTHREAD>(GetProcAddress(hNTDLL, "ZwQueryInformationThread"));
		if (ZwQueryInformationThread == NULL) {
			std::cerr << "Error: GetProcAddress failed." << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		// 获取线程的所有信息
		THREAD_BASIC_INFORMATION threadBasicInfo;
		status = ZwQueryInformationThread(
			hThread,
			ThreadBasicInformation,
			&threadBasicInfo,
			sizeof(threadBasicInfo),
			NULL
		);
		if (status != 0) {
			std::cerr << "Error: ZwQueryInformationThread failed with status 0x" << std::hex << status << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		status = ZwQueryInformationThread(
			hThread,                            // 线程句柄
			ThreadQuerySetWin32StartAddress,    // 线程信息类型，ThreadQuerySetWin32StartAddress ：线程入口地址
			&startaddr,                            // 指向缓冲区的指针
			sizeof(startaddr),                    // 缓冲区的大小
			NULL
		);
		if (status != 0) {
			std::cerr << "Error: ZwQueryInformationThread failed with status 0x" << std::hex << status << std::endl;
			CloseHandle(hThread);
			CloseHandle(hNTDLL);
		}
		CloseHandle(hThread);
		std::cout << "=============================KILL=========================" << std::endl;
		std::cout << "Thread id is: \t" << m_ThreadID << std::endl;
		std::cout << "Thread adr is：\t" << startaddr << std::endl;
		g_ThreadAdrNum++;
		g_ThreadAdr[g_ThreadAdrNum] = reinterpret_cast<uintptr_t>(startaddr);
		std::cout << "num：\t" << g_ThreadAdrNum << std::endl;
		std::cout << "adr：\t" << std::hex << std::uppercase << g_ThreadAdr[g_ThreadAdrNum] << std::endl;
		HANDLE m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_ThreadID);
		BOOL status = TerminateThread(m_hThread, threadBasicInfo.ExitStatus);
		CloseHandle(m_hThread);
		if (!status)
			std::cout << "Thread Close error...!" << std::endl;
		std::cout << "=============================KILLend=========================" << std::endl;
	}
}

void A_main()
{
	ShowConsoleOutput();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	fpNtCreateThreadEX = (NTCREATETHREADEX)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (fpNtCreateThreadEX == NULL) {
		std::cerr << "Failed to get address of NtCreateThreadEX function" << std::endl;
	}
	std::cout << " NtCreateThreadEX: " << fpNtCreateThreadEX << std::endl;
	DetourAttach((PVOID*)&fpNtCreateThreadEX, DetourNtCreateThreadEX);
	DetourTransactionCommit();
}