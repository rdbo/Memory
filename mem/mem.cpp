#include "mem.h"

//Windows
#if defined(WIN) && !defined(LINUX)
//Memory::Ex
#if INCLUDE_EXTERNALS
pid_t Memory::Ex::GetProcessIdByName(str_t processName)
{
	pid_t pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!_tcscmp(procEntry.szExeFile, processName.c_str()))
				{
					pid = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
	return pid;
}
//--------------------------------------------
pid_t Memory::Ex::GetProcessIdByWindow(str_t windowName)
{
	pid_t pid;
	GetWindowThreadProcessId(FindWindow(NULL, windowName.c_str()), &pid);
	return pid;
}
//--------------------------------------------
pid_t Memory::Ex::GetProcessIdByWindow(str_t windowClass, str_t windowName)
{
	pid_t pid;
	GetWindowThreadProcessId(FindWindow(windowClass.c_str(), windowName.c_str()), &pid);
	return pid;
}
//--------------------------------------------
HANDLE Memory::Ex::GetProcessHandle(pid_t pid)
{
	return OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
}
//--------------------------------------------
mem_t Memory::Ex::GetModuleAddress(pid_t pid, str_t moduleName)
{
	mem_t moduleAddr = NULL;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!lstrcmp(modEntry.szModule, moduleName.c_str()))
				{
					moduleAddr = (mem_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return moduleAddr;
}
//--------------------------------------------
mem_t Memory::Ex::GetPointer(HANDLE hProc, mem_t baseAddress, std::vector<mem_t> offsets)
{
	if (hProc == INVALID_HANDLE_VALUE || hProc == 0) return BAD_RETURN;
	mem_t addr = baseAddress;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		addr += offsets[i];
		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
	}
	return addr;
}
//--------------------------------------------
BOOL Memory::Ex::WriteBuffer(HANDLE hProc, mem_t address, const void* value, SIZE_T size)
{
	if (hProc == INVALID_HANDLE_VALUE || hProc == 0) return BAD_RETURN;
	return WriteProcessMemory(hProc, (BYTE*)address, value, size, nullptr);
}
//--------------------------------------------
BOOL Memory::Ex::ReadBuffer(HANDLE hProc, mem_t address, void* buffer, SIZE_T size)
{
	if (hProc == INVALID_HANDLE_VALUE || hProc == 0) return BAD_RETURN;
	return ReadProcessMemory(hProc, (BYTE*)address, buffer, size, nullptr);
}

//Memory::Ex::Injection

//Memory::Ex::Injection::DLL

bool Memory::Ex::Injection::DLL::LoadLib(HANDLE hProc, str_t dllPath)
{
	if (dllPath.length() == 0 || hProc == INVALID_HANDLE_VALUE || hProc == 0) return false;

	void* loc = VirtualAllocEx(hProc, 0, (dllPath.length() + 1) * sizeof(TCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (loc == 0) return false;

	if (!WriteProcessMemory(hProc, loc, dllPath.c_str(), (dllPath.length() + 1) * sizeof(TCHAR), 0)) return false;
	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, loc, 0, 0);
	if (hThread == INVALID_HANDLE_VALUE || hThread == 0) return false;
	WaitForSingleObject(hThread, -1);
	CloseHandle(hThread);
	VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);

	return true;
}


#endif //INCLUDE_EXTERNALS
//Memory::In
#if INCLUDE_INTERNALS
void Memory::In::ZeroMem(void* src, size_t size)
{
	memset(src, 0x0, size + 1);
}
//--------------------------------------------
bool Memory::In::IsBadPointer(void* pointer)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (VirtualQuery(pointer, &mbi, sizeof(mbi)))
	{
		DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		bool b = !(mbi.Protect & mask);
		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

		return b;
	}
	return true;
}
//--------------------------------------------
pid_t Memory::In::GetCurrentProcessID()
{
	return GetCurrentProcessId();
}
//--------------------------------------------
HANDLE Memory::In::GetCurrentProcessHandle()
{
	return GetCurrentProcess();
}
//--------------------------------------------
mem_t Memory::In::GetModuleAddress(str_t moduleName)
{
	return (mem_t)GetModuleHandle(moduleName.c_str());
}
//--------------------------------------------
mem_t Memory::In::GetPointer(mem_t baseAddress, std::vector<mem_t> offsets)
{
	mem_t addr = baseAddress;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		addr += offsets[i];
		addr = *(mem_t*)addr;
	}
	return addr;
}
//--------------------------------------------
bool Memory::In::WriteBuffer(mem_t address, const void* value, SIZE_T size)
{
	DWORD oProtection;
	if (VirtualProtect((LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oProtection))
	{
		memcpy((void*)(address), value, size);
		VirtualProtect((LPVOID)address, size, oProtection, NULL);
		return true;
	}

	return false;
}
//--------------------------------------------
bool Memory::In::ReadBuffer(mem_t address, void* buffer, SIZE_T size)
{
	WriteBuffer((mem_t)buffer, (void*)address, size);
	return true;
}

//Memory::In::Hook

std::map<mem_t, std::vector<byte_t>> Memory::In::Hook::restore_arr;
bool Memory::In::Hook::Restore(mem_t address)
{
	if (restore_arr.count(address) <= 0) return false;
	std::vector<byte_t> obytes = restore_arr.at(address);
	WriteBuffer(address, obytes.data(), obytes.size());
	return true;
}
//--------------------------------------------
bool Memory::In::Hook::Detour(byte_t* src, byte_t* dst, size_t size)
{
	if (size < HOOK_MIN_SIZE) return false;

	//Save stolen bytes
	byte_t* bytes = new byte_t(size);
	ZeroMem(bytes, size);
	memcpy(bytes, src, size);
	std::vector<byte_t> vbytes;
	vbytes.reserve(size);
	for (int i = 0; i < size; i++)
	{
		vbytes.insert(vbytes.begin() + i, bytes[i]);
	}
	restore_arr.insert(std::pair<mem_t, std::vector<byte_t>>((mem_t)src, vbytes));

	//Detour
	DWORD  oProtect;
	VirtualProtect(src, size, PAGE_EXECUTE_READWRITE, &oProtect);
#	if defined(ARCH_X86)
	mem_t  jmpAddr = (mem_t)(dst - (mem_t)src) - HOOK_MIN_SIZE;
	*src = JMP;
	*(mem_t*)((mem_t)src + BYTE_SIZE) = jmpAddr;
#	elif defined(ARCH_X64)
	mem_t jmpAddr = (mem_t)dst;
	*(byte_t*)src = MOV_RAX[0];
	*(byte_t*)((mem_t)src + BYTE_SIZE) = MOV_RAX[1];
	*(mem_t*)((mem_t)src + BYTE_SIZE + BYTE_SIZE) = jmpAddr;
	*(byte_t*)((mem_t)src + BYTE_SIZE + BYTE_SIZE + sizeof(mem_t)) = JMP_RAX[0];
	*(byte_t*)((mem_t)src + BYTE_SIZE + BYTE_SIZE + sizeof(mem_t) + BYTE_SIZE) = JMP_RAX[1];
#	endif
	VirtualProtect(src, size, oProtect, &oProtect);
	return true;
}
//--------------------------------------------
byte_t* Memory::In::Hook::TrampolineHook(byte_t* src, byte_t* dst, size_t size)
{
	if (size < HOOK_MIN_SIZE) return 0;
	void* gateway = VirtualAlloc(0, size + HOOK_MIN_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(gateway, src, size);
#	if defined(ARCH_X86)
	mem_t jmpBack = ((mem_t)src - (mem_t)gateway) - HOOK_MIN_SIZE;
	*(byte_t*)((mem_t)gateway + size) = JMP;
	*(mem_t*)((mem_t)gateway + size + BYTE_SIZE) = jmpBack;
#	elif defined(ARCH_X64)
	mem_t jmpBack = (mem_t)src + size;
	//mov rax, jmpBack
	*(byte_t*)((mem_t)gateway + size) = MOV_RAX[0];
	*(byte_t*)((mem_t)gateway + size + BYTE_SIZE) = MOV_RAX[1];
	*(mem_t*)((mem_t)gateway + size + BYTE_SIZE + BYTE_SIZE) = jmpBack;

	//jmp rax
	*(byte_t*)((mem_t)gateway + size + BYTE_SIZE + BYTE_SIZE + sizeof(mem_t)) = JMP_RAX[0];
	*(byte_t*)((mem_t)gateway + size + BYTE_SIZE + BYTE_SIZE + sizeof(mem_t) + BYTE_SIZE) = JMP_RAX[1];
#	endif
	Detour(src, dst, size);
	return (byte_t*)gateway;
}
#endif //INCLUDE_INTERNALS
#endif //Windows
//============================================
//============================================
//============================================

//Linux
#if defined(LINUX) && !defined(WIN)

//Memory::Ex
#if INCLUDE_EXTERNALS
pid_t Memory::Ex::GetProcessIdByName(str_t processName)
{
	pid_t pid = INVALID_PID;
	DIR* pdir = opendir("/proc");
	if (!pdir)
		return INVALID_PID;

	struct dirent* pdirent;
	while (pid < 0 && (pdirent = readdir(pdir)))
	{
		int id = atoi(pdirent->d_name);
		if (id > 0)
		{
			str_t cmdpath = str_t("/proc/") + pdirent->d_name + "/cmdline";
			std::ifstream cmdfile(cmdpath.c_str());
			str_t cmdline;
			getline(cmdfile, cmdline);
			size_t pos = cmdline.find('\0');
			if (!cmdline.empty())
			{
				if (pos != str_t::npos)
					cmdline = cmdline.substr(0, pos);
				pos = cmdline.rfind('/');
				if (pos != str_t::npos)
					cmdline = cmdline.substr(pos + 1);
				if (processName == cmdline.c_str())
					pid = id;
			}
		}
	}
	closedir(pdir);
	return pid;
}
//--------------------------------------------
void Memory::Ex::ReadBuffer(pid_t pid, mem_t address, void* buffer, size_t size)
{
	char file[MAX_FILENAME];
	sprintf(file, "/proc/%ld/mem", (long)pid);
	int fd = open(file, O_RDWR);
	ptrace(PTRACE_ATTACH, pid, 0, 0);
	waitpid(pid, NULL, 0);
	pread(fd, buffer, size, address);
	ptrace(PTRACE_DETACH, pid, 0, 0);
	close(fd);
}
//--------------------------------------------
void Memory::Ex::WriteBuffer(pid_t pid, mem_t address, void* value, size_t size)
{
	char file[MAX_FILENAME];
	sprintf(file, "/proc/%ld/mem", (long)pid);
	int fd = open(file, O_RDWR);
	ptrace(PTRACE_ATTACH, pid, 0, 0);
	waitpid(pid, NULL, 0);
	pwrite(fd, value, size, address);
	ptrace(PTRACE_DETACH, pid, 0, 0);
	close(fd);
}
//--------------------------------------------
bool Memory::Ex::IsProcessRunning(pid_t pid)
{
	char dirbuf[MAX_FILENAME];
	sprintf(dirbuf, "/proc/%ld", (long)pid);
	struct stat status;
	stat(dirbuf, &status);
	return status.st_mode & S_IFDIR != 0;
}
#endif //INCLUDE_EXTERNALS

#if INCLUDE_INTERNALS
//Memory::In
void Memory::In::ZeroMem(void* src, size_t size)
{
	memset(src, 0x0, size + 1);
}
//--------------------------------------------
bool Memory::In::IsBadPointer(void* pointer)
{
	int fh = open((const char*)pointer, 0, 0);
	int e = errno;

	if (fh == -1 && e != EFAULT)
	{
		close(fh);
		return false;
	}

	return true;
}
//--------------------------------------------
pid_t Memory::In::GetCurrentProcessID()
{
	return getpid();
}
//--------------------------------------------
bool Memory::In::ReadBuffer(mem_t address, void* buffer, size_t size)
{
	memcpy((void*)buffer, (void*)address, size);
	return true;
}
//--------------------------------------------
bool Memory::In::WriteBuffer(mem_t address, void* value, size_t size)
{
	memcpy((void*)address, (void*)value, size);
	return true;
}
#endif //INCLUDE_INTERNALS
#endif //Linux