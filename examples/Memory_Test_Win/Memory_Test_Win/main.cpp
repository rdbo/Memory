#include "pch.h"
#define PROCESS_NAME AUTO_STR("Memory_Test_Win.exe")
#define DEFAULT_VALUE 100
#define NEW_VALUE 500
#define MULT 2
#if defined(ARCH_X86)
#define HOOK_LENGTH 9
#elif defined(ARCH_X64)
#define HOOK_LENGTH 13
#endif
int buffer = DEFAULT_VALUE;

#if defined(ARCH_X86)
#define CALL __cdecl
#elif defined(ARCH_X64)
#define CALL __fastcall
#endif

byte_t scan[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
cstr_t mask = (cstr_t)"xxxxxxxxxxxxxxx";

bool TestPID(pid_t& pid)
{
	pid = Memory::Ex::GetProcessIdByName(PROCESS_NAME);
	pid_t ntPid = Memory::Ex::Nt::GetProcessID(PROCESS_NAME);
	pid_t zwPid = Memory::Ex::Zw::GetProcessID(PROCESS_NAME);
	std::cout << "PID: " << pid << std::endl;
	std::cout << "Nt PID: " << ntPid << std::endl;
	std::cout << "Zw PID: " << zwPid << std::endl;
	return pid == ntPid && pid == zwPid;
}

bool TestHandle(pid_t pid, HANDLE& handle)
{
	handle = Memory::Ex::GetProcessHandle(pid);
	HANDLE ntHandle = Memory::Ex::Nt::GetProcessHandle(PROCESS_NAME);
	HANDLE zwHandle = Memory::Ex::Zw::GetProcessHandle(PROCESS_NAME);
	std::cout << "Handle: " << handle << std::endl;
	std::cout << "Nt Handle: " << ntHandle << std::endl;
	std::cout << "Zw Handle: " << zwHandle << std::endl;
	return handle && handle != INVALID_HANDLE_VALUE && ntHandle && ntHandle != INVALID_HANDLE_VALUE && zwHandle && zwHandle != INVALID_HANDLE_VALUE;
}

bool TestBuffer(HANDLE handle)
{
	int read;
	Memory::Ex::ReadBuffer(handle, (mem_t)&buffer, &read, sizeof(read));
	Memory::Ex::WriteBuffer(handle, (mem_t)&buffer, new int(NEW_VALUE), sizeof(NEW_VALUE));
	
	int ntRead;
	Memory::Ex::Nt::ReadBuffer(handle, (mem_t)&buffer, &ntRead, sizeof(ntRead));
	Memory::Ex::Nt::WriteBuffer(handle, (mem_t)&buffer, new int(NEW_VALUE * MULT), sizeof(NEW_VALUE * MULT));

	int zwRead;
	Memory::Ex::Zw::ReadBuffer(handle, (mem_t)&buffer, &zwRead, sizeof(zwRead));
	Memory::Ex::Zw::WriteBuffer(handle, (mem_t)&buffer, new int(DEFAULT_VALUE), sizeof(DEFAULT_VALUE));

	std::cout << "Read: " << read << std::endl;
	std::cout << "Nt Read: " << ntRead << std::endl;
	std::cout << "Zw Read: " << zwRead << std::endl;

	return read == DEFAULT_VALUE && ntRead == NEW_VALUE && zwRead == NEW_VALUE * MULT && buffer == DEFAULT_VALUE;
}

bool TestPatternScan()
{
	mem_t pscan = Memory::In::PatternScan(Memory::In::GetModuleAddress(PROCESS_NAME), Memory::In::GetModuleInfo(PROCESS_NAME).SizeOfImage, scan, mask);
	mem_t pscanmod = Memory::In::PatternScanModule(PROCESS_NAME, scan, mask);
	return pscan == pscanmod && pscan == (mem_t)scan;
}

void Separator()
{
	std::cout << "========================" << std::endl;
}

bool CALL TestHook(bool value)
{
	return value;
}

typedef bool(CALL* TestHook_t)(bool);
TestHook_t oTestHook;

bool CALL hkTestHook(bool value)
{
	std::cout << "Hooked!" << std::endl;
	std::cout << "Old value: " << value << std::endl;
	value = true;
	std::cout << "New value: " << value << std::endl;
	return oTestHook(value);
}

int main()
{
	pid_t pid;
	HANDLE hProc;
	std::cout << "Test PID: " << TestPID(pid) << std::endl;
	Separator();
	std::cout << "Test Handle: " << TestHandle(pid, hProc) << std::endl;
	Separator();
	std::cout << "Test Buffer: " << TestBuffer(hProc) << std::endl;
	Separator();
	std::cout << "Test Pattern Scan: " << TestPatternScan() << std::endl;
	Separator();


	std::cout << "Function Address: " << TestHook << std::endl;
	mem_t offset = 0;
	mem_t addr = 0;
	memcpy((void*)&offset, (void*)((mem_t)TestHook + 1), 4);
	std::cout << "Function offset: " << std::hex << offset << std::endl;
	addr = (mem_t)TestHook + JUMP_LENGTH_X86 + offset;
	std::cout << "Address: " << std::hex << addr << std::endl;
	std::cout << "Press ENTER to hook function" << std::endl;
	getchar();
	oTestHook = (TestHook_t)Memory::In::Hook::TrampolineHook((byte_t*)addr, (byte_t*)hkTestHook, HOOK_LENGTH);
	std::cout << "Test Hook: " << TestHook(false) << std::endl;
	Separator();

	return 0;
}