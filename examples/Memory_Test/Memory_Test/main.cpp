#include "pch.h"
#include "../../../mem/mem.h"

#if defined(UCS) //Unicode
#define PROCESS_NAME L"Memory_Test.exe"
#define WINDOW_TITLE L"Memory_Test"
#elif defined(MBCS) //Multibyte
#define PROCESS_NAME "Memory_Test.exe"
#define WINDOW_TITLE "Memory_Test"
#endif

#define DELAY 1000
#define NEW_VALUE (int)500

#if defined(MEMORY)
int main()
{
	int targetVariable = 100;
	//--Windows--
#	if defined(WIN)
	SetConsoleTitle(WINDOW_TITLE); //Making sure the console window title is WINDOW_TITLE
	Sleep(DELAY);
	//External Test (Targetting this process)
	HANDLE ntHandle = Memory::Ex::Nt::GetProcessHandle(PROCESS_NAME);

	pid_t pid = Memory::Ex::GetProcessIdByName(PROCESS_NAME);
	pid_t window_pid = Memory::Ex::GetProcessIdByWindow(WINDOW_TITLE);
	pid_t ntpid = Memory::Ex::Nt::GetProcessID(PROCESS_NAME);
	pid_t ntHandlePid = Memory::Ex::GetProcessIdByHandle(ntHandle);
	HANDLE hProc = Memory::Ex::GetProcessHandle(pid);

	std::cout << "NtHandle: " << ntHandle << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "Window PID: " << window_pid << std::endl;
	std::cout << "Nt PID: " << ntpid << std::endl;
	std::cout << "Nt Handle PID: " << ntHandlePid << std::endl;
	std::cout << "Handle: " << hProc << std::endl;

	int buffer;
	Memory::Ex::ReadBuffer(hProc, (mem_t)&targetVariable, &buffer, sizeof(buffer));
	std::cout << "Buffer: " << buffer << std::endl;

	Memory::Ex::ReadBuffer(ntHandle, (mem_t)&targetVariable, &buffer, sizeof(buffer));

	std::cout << "Buffer (Nt): " << buffer << std::endl;

	Memory::Ex::WriteBuffer(hProc, (mem_t)&targetVariable, new int(NEW_VALUE), sizeof(targetVariable));
	std::cout << "TargetVariable: " << targetVariable << std::endl;

	Memory::Ex::WriteBuffer(ntHandle, (mem_t)&targetVariable, new int(buffer), sizeof(targetVariable));
	std::cout << "TargetVariable (resetted): " << targetVariable << std::endl;

	//Internal Test (Targetting this process)
#	endif

	//Pause
	std::cout << "Press ENTER to close..." << std::endl;
	getchar();
	return 0;
}
#endif