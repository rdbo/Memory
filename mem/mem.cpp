#include "mem.h"

//Windows
#if defined(WIN) && !defined(LINUX)
//Variables
HWND Memory::g_hWnd;
//Helper Functions
BOOL CALLBACK Memory::EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	pid_t wndPid;
	GetWindowThreadProcessId(hWnd, &wndPid);
	if (wndPid != (pid_t)lParam) return TRUE;

	g_hWnd = hWnd;
	return FALSE;
}

char* Memory::ParseMask(char* mask)
{
	size_t length = strlen(mask);
	for (size_t i = 0; i < length; i++)
	{
		if (mask[i] != KNOWN_BYTE)
		{
			if (mask[i] == KNOWN_BYTE_UPPER)
				mask[i] = KNOWN_BYTE;
			else
				mask[i] = UNKNOWN_BYTE;
		}
	}

	return mask;
}

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
pid_t Memory::Ex::GetProcessIdByWindow(HWND hWnd)
{
	pid_t pid = 0;
	GetWindowThreadProcessId(hWnd, &pid);
	return pid;
}
//--------------------------------------------
pid_t Memory::Ex::GetProcessIdByHandle(HANDLE hProcess)
{
	return GetProcessId(hProcess);
}
//--------------------------------------------
HANDLE Memory::Ex::GetProcessHandle(pid_t pid, DWORD dwAccess)
{
	return OpenProcess(dwAccess, NULL, pid);
}
//--------------------------------------------
HWND Memory::Ex::GetWindowHandle(pid_t pid)
{
	g_hWnd = NULL;
	EnumWindows(EnumWindowsCallback, pid);
	return g_hWnd;
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
				if (!_tcscmp(modEntry.szModule, moduleName.c_str()))
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
vstr_t Memory::Ex::GetModuleList(pid_t pid)
{
	vstr_t modList;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 entry;
	entry.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnap, &entry))
	{
		do
		{
			modList.push_back(entry.szModule);
		} while (Module32Next(hSnap, &entry));
	}

	return modList;
}
//--------------------------------------------
bool Memory::Ex::IsModuleLoaded(str_t moduleName, vstr_t moduleList)
{
	for (size_t i = 0; i < moduleList.size(); i++)
	{
		if (!_tcscmp(moduleName.c_str(), moduleList.at(i).c_str()))
			return true;
	}

	return false;
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
//--------------------------------------------
MODULEINFO Memory::Ex::GetModuleInfo(HANDLE hProcess, str_t moduleName)
{
	HMODULE hMod;
	GetModuleHandleEx(NULL, moduleName.c_str(), &hMod);

	MODULEINFO modInfo = { 0 };
	GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo));

	return modInfo;
}
//--------------------------------------------
mem_t Memory::Ex::PatternScan(HANDLE hProcess, mem_t beginAddr, mem_t endAddr, byte_t* pattern, char* mask)
{
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return 0;
	mask = ParseMask(mask);
	mem_t patternLength = strlen(mask);
	size_t scanSize = (size_t)endAddr - beginAddr;
	for (size_t i = 0; i < scanSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			byte_t curByte;
			ReadBuffer(hProcess, (mem_t)(beginAddr + i + j), &curByte, sizeof(curByte));
			found &= mask[j] == UNKNOWN_BYTE || pattern[j] == curByte;
		}

		if (found) return beginAddr + i;
	}

	return 0;
}
//--------------------------------------------
mem_t Memory::Ex::PatternScanModule(HANDLE hProcess, str_t moduleName, byte_t* pattern, char* mask)
{
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return 0;
	MODULEINFO modInfo = GetModuleInfo(hProcess, moduleName);
	mem_t patternLength = strlen(mask);
	mem_t baseAddr = (mem_t)modInfo.lpBaseOfDll;
	size_t scanSize = (size_t)modInfo.SizeOfImage;

	return PatternScan(hProcess, baseAddr, baseAddr + scanSize, pattern, mask);
}

//Memory::Ex::Nt
HANDLE Memory::Ex::Nt::GetProcessHandle(str_t processName, ACCESS_MASK dwAccess)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return INVALID_HANDLE_VALUE;
	NtGetNextProcess_t NtGetNextProcess = (NtGetNextProcess_t)GetProcAddress(ntdll, NTGETNEXTPROCESS_STR);
	if (!NtGetNextProcess) return INVALID_HANDLE_VALUE;

	HANDLE hProcess = 0;
	TCHAR buffer[MAX_PATH];
	while (NtGetNextProcess(hProcess, dwAccess, 0, 0, &hProcess) == 0)
	{
		GetModuleFileNameEx(hProcess, 0, buffer, sizeof(buffer) / sizeof(TCHAR));
		str_t str = buffer;
		if (str.find(processName) != str.npos) break;
	}

	CloseHandle(ntdll);
	return hProcess;
}
//--------------------------------------------
pid_t Memory::Ex::Nt::GetProcessID(str_t processName)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return 0;
	NtGetNextProcess_t NtGetNextProcess = (NtGetNextProcess_t)GetProcAddress(ntdll, NTGETNEXTPROCESS_STR);
	if (!NtGetNextProcess) return 0;

	HANDLE hProcess = 0;
	pid_t processId = 0;
	TCHAR buffer[MAX_PATH];
	while (NtGetNextProcess(hProcess, MAXIMUM_ALLOWED, 0, 0, &hProcess) == 0)
	{
		GetModuleFileNameEx(hProcess, 0, buffer, sizeof(buffer) / sizeof(TCHAR));
		str_t str = buffer;
		if (str.find(processName) != str.npos)
		{
			processId = GetProcessId(hProcess);
			break;
		}
	}
	CloseHandle(ntdll);
	return processId;
}
//--------------------------------------------
HANDLE Memory::Ex::Nt::OpenProcessHandle(pid_t pid, ACCESS_MASK dwAccess)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return INVALID_HANDLE_VALUE;
	NtOpenProcess_t NtOpenProcess = (NtOpenProcess_t)GetProcAddress(ntdll, NTOPENPROCESS_STR);
	if (!NtOpenProcess) return INVALID_HANDLE_VALUE;

	HANDLE hProcess = 0;
	OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };
	CLIENT_ID clId = {};
	clId.UniqueProcess = (HANDLE)pid;
	NtOpenProcess(&hProcess, dwAccess, &objAttr, &clId);
	CloseHandle(ntdll);
	return hProcess;
}
//--------------------------------------------
bool Memory::Ex::Nt::CloseProcessHandle(HANDLE hProcess)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return false;
	NtClose_t NtClose = (NtClose_t)GetProcAddress(ntdll, NTCLOSE_STR);
	if (!NtClose) return false;

	NtClose(hProcess);
	CloseHandle(ntdll);
	return true;
}
//--------------------------------------------
void Memory::Ex::Nt::WriteBuffer(HANDLE hProcess, mem_t address, const void* buffer, size_t size)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return;
	NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(ntdll, NTWRITEVIRTUALMEMORY_STR);
	if (!NtWriteVirtualMemory) return;

	NtWriteVirtualMemory(hProcess, (PVOID)address, buffer, size, NULL);
	CloseHandle(ntdll);
}
//--------------------------------------------
void Memory::Ex::Nt::ReadBuffer(HANDLE hProcess, mem_t address, void* buffer, size_t size)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return;
	NtReadVirtualMemory_t NtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(ntdll, NTREADVIRTUALMEMORY_STR);
	if (!NtReadVirtualMemory) return;

	NtReadVirtualMemory(hProcess, (PVOID)address, buffer, size, NULL);
	CloseHandle(ntdll);
}

//Memory::Ex::Zw
HANDLE Memory::Ex::Zw::GetProcessHandle(str_t processName, ACCESS_MASK dwAccess)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return INVALID_HANDLE_VALUE;
	ZwGetNextProcess_t ZwGetNextProcess = (ZwGetNextProcess_t)GetProcAddress(ntdll, ZWGETNEXTPROCESS_STR);
	if (!ZwGetNextProcess) return INVALID_HANDLE_VALUE;

	HANDLE hProcess = 0;
	TCHAR buffer[MAX_PATH];
	while (ZwGetNextProcess(hProcess, dwAccess, 0, 0, &hProcess) == 0)
	{
		GetModuleFileNameEx(hProcess, 0, buffer, sizeof(buffer) / sizeof(TCHAR));
		str_t str = buffer;
		if (str.find(processName) != str.npos) break;
	}

	CloseHandle(ntdll);
	return hProcess;
}
//--------------------------------------------
pid_t Memory::Ex::Zw::GetProcessID(str_t processName)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return 0;
	ZwGetNextProcess_t ZwGetNextProcess = (ZwGetNextProcess_t)GetProcAddress(ntdll, ZWGETNEXTPROCESS_STR);
	if (!ZwGetNextProcess) return 0;

	HANDLE hProcess = 0;
	pid_t processId = 0;
	TCHAR buffer[MAX_PATH];
	while (ZwGetNextProcess(hProcess, MAXIMUM_ALLOWED, 0, 0, &hProcess) == 0)
	{
		GetModuleFileNameEx(hProcess, 0, buffer, sizeof(buffer) / sizeof(TCHAR));
		str_t str = buffer;
		if (str.find(processName) != str.npos)
		{
			processId = GetProcessId(hProcess);
			break;
		}
	}
	CloseHandle(ntdll);
	return processId;
}
//--------------------------------------------
HANDLE Memory::Ex::Zw::OpenProcessHandle(pid_t pid, ACCESS_MASK dwAccess)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return INVALID_HANDLE_VALUE;
	ZwOpenProcess_t ZwOpenProcess = (ZwOpenProcess_t)GetProcAddress(ntdll, ZWOPENPROCESS_STR);
	if (!ZwOpenProcess) return INVALID_HANDLE_VALUE;

	HANDLE hProcess = 0;
	OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };
	CLIENT_ID clId = {};
	clId.UniqueProcess = (HANDLE)pid;
	ZwOpenProcess(&hProcess, dwAccess, &objAttr, &clId);
	CloseHandle(ntdll);
	return hProcess;
}
//--------------------------------------------
bool Memory::Ex::Zw::CloseProcessHandle(HANDLE hProcess)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return false;
	ZwClose_t ZwClose = (ZwClose_t)GetProcAddress(ntdll, ZWCLOSE_STR);
	if (!ZwClose) return false;

	ZwClose(hProcess);
	CloseHandle(ntdll);
	return true;
}
//--------------------------------------------
void Memory::Ex::Zw::WriteBuffer(HANDLE hProcess, mem_t address, const void* buffer, size_t size)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return;
	ZwWriteVirtualMemory_t ZwWriteVirtualMemory = (ZwWriteVirtualMemory_t)GetProcAddress(ntdll, ZWWRITEVIRTUALMEMORY_STR);
	if (!ZwWriteVirtualMemory) return;

	ZwWriteVirtualMemory(hProcess, (PVOID)address, buffer, size, NULL);
	CloseHandle(ntdll);
}
//--------------------------------------------
void Memory::Ex::Zw::ReadBuffer(HANDLE hProcess, mem_t address, void* buffer, size_t size)
{
	HMODULE ntdll = GetModuleHandle(NTDLL_NAME);
	if (!ntdll) return;
	ZwReadVirtualMemory_t ZwReadVirtualMemory = (ZwReadVirtualMemory_t)GetProcAddress(ntdll, ZWREADVIRTUALMEMORY_STR);
	if (!ZwReadVirtualMemory) return;

	ZwReadVirtualMemory(hProcess, (PVOID)address, buffer, size, NULL);
	CloseHandle(ntdll);
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
	memset(src, 0x0, size);
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
HWND Memory::In::GetCurrentWindowHandle()
{
	g_hWnd = NULL;
	EnumWindows(EnumWindowsCallback, GetCurrentProcessID());
	return g_hWnd;
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
//--------------------------------------------
MODULEINFO Memory::In::GetModuleInfo(str_t moduleName)
{
	MODULEINFO modInfo = { 0 };
	HMODULE hMod = GetModuleHandle(moduleName.c_str());
	if (!hMod) return modInfo;
	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo));
	return modInfo;
}
//--------------------------------------------
mem_t Memory::In::PatternScan(mem_t baseAddr, mem_t endAddr, byte_t* pattern, char* mask)
{
	mask = ParseMask(mask);
	size_t patternLength = strlen(mask);
	size_t scanSize = endAddr - baseAddr;
	for (size_t i = 0; i < scanSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			found &= mask[j] == UNKNOWN_BYTE || pattern[j] == *(byte_t*)(baseAddr + i + j);
		}

		if (found) return baseAddr + i;
	}

	return 0;
}
//--------------------------------------------
mem_t Memory::In::PatternScanModule(str_t moduleName, byte_t* pattern, char* mask)
{
	MODULEINFO modInfo = GetModuleInfo(moduleName);
	size_t patternLength = strlen(mask);
	mem_t baseAddr = (mem_t)modInfo.lpBaseOfDll;
	size_t scanSize = (size_t)modInfo.SizeOfImage;
	return PatternScan(baseAddr, baseAddr + scanSize, pattern, mask);
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
	byte_t* bytes = new byte_t[size];
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
	byte_t CodeCave[] = { JMP, 0x0, 0x0, 0x0, 0x0 };
	mem_t  jmpAddr = (mem_t)(dst - (mem_t)src) - HOOK_MIN_SIZE;
	*(mem_t*)((mem_t)CodeCave + sizeof(JMP)) = jmpAddr;
	memcpy(src, CodeCave, sizeof(CodeCave));

#	elif defined(ARCH_X64)
	byte_t CodeCave[] = { MOV_RAX[0], MOV_RAX[1], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, JMP_RAX[0], JMP_RAX[1] };
	mem_t jmpAddr = (mem_t)dst;
	*(mem_t*)((mem_t)CodeCave + sizeof(MOV_RAX)) = jmpAddr;
	memcpy(src, CodeCave, sizeof(CodeCave));
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
	byte_t GatewayCodeCave[] = { JMP, 0x0, 0x0, 0x0, 0x0 };
	mem_t jmpBack = ((mem_t)src - (mem_t)gateway) - HOOK_MIN_SIZE;
	*(mem_t*)((mem_t)GatewayCodeCave + sizeof(JMP)) = jmpBack;
	memcpy((void*)((mem_t)gateway + size), GatewayCodeCave, sizeof(GatewayCodeCave));
#	elif defined(ARCH_X64)
	mem_t jmpBack = (mem_t)src + size;
	byte_t GatewayCodeCave[] = { MOV_RAX[0], MOV_RAX[1], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, JMP_RAX[0], JMP_RAX[1] };
	*(mem_t*)((mem_t)GatewayCodeCave + sizeof(MOV_RAX)) = jmpBack;
	memcpy((void*)((mem_t)gateway + size), GatewayCodeCave, sizeof(GatewayCodeCave));
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

//Memory
//Helper functions
char* Memory::ParseMask(char* mask)
{
	size_t length = strlen(mask);
	for (size_t i = 0; i < length; i++)
	{
		if (mask[i] != KNOWN_BYTE)
		{
			if (mask[i] == KNOWN_BYTE_UPPER)
				mask[i] = KNOWN_BYTE;
			else
				mask[i] = UNKNOWN_BYTE;
		}
	}

	return mask;
}

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
mem_t Memory::Ex::GetModuleAddress(pid_t pid, str_t moduleName)
{
	char path_buffer[DEFAULT_BUFFER_SIZE];
	char baseAddress[MAX_BUFFER_SIZE];
	snprintf(path_buffer, sizeof(path_buffer), PROC_MAPS_STR, pid);
	int proc_maps = open(path_buffer, O_RDONLY);
	size_t size = lseek(proc_maps, 0, SEEK_END);
	char* file_buffer = new char[size + 1];
	if (size == 0 || !proc_maps || !file_buffer) return BAD_RETURN;
	memset(file_buffer, 0x0, size + 1);
	for (size_t i = 0; read(proc_maps, file_buffer + i, 1) > 0; i++);

	char* ptr = NULL;
	if (moduleName.c_str() != NULL && (ptr = strstr(file_buffer, moduleName.c_str())) == NULL)
		if ((ptr = strstr(file_buffer, moduleName.c_str())) == NULL) return BAD_RETURN;
		else if ((ptr = strstr(file_buffer, "r-xp")) == NULL) return BAD_RETURN;

	while (*ptr != '\n' && ptr >= file_buffer)
	{
		ptr--;
	}
	ptr++;

	for (int i = 0; *ptr != '-'; i++)
	{
		baseAddress[i] = *ptr;
		ptr++;
	}

	mem_t base = (mem_t)strtol(baseAddress, NULL, 16);
	close(proc_maps);
	free(file_buffer);

	return base;
}
//--------------------------------------------
bool Memory::Ex::ReadBuffer(pid_t pid, mem_t address, void* buffer, size_t size)
{
	if (size == 0 || buffer == 0 || pid == INVALID_PID) return false;

	char path_buffer[DEFAULT_BUFFER_SIZE];
	snprintf(path_buffer, sizeof(path_buffer), PROC_MEM_STR, pid);

	int proc_mem = open(path_buffer, O_RDONLY);
	lseek(proc_mem, address, SEEK_SET);
	read(proc_mem, buffer, size);
	return true;
}
//--------------------------------------------
bool Memory::Ex::WriteBuffer(pid_t pid, mem_t address, void* value, size_t size)
{
	if (size == 0 || value == 0 || pid == INVALID_PID) return false;

	char path_buffer[DEFAULT_BUFFER_SIZE];
	snprintf(path_buffer, sizeof(path_buffer), PROC_MEM_STR, pid);

	int proc_mem = open(path_buffer, O_WRONLY);
	lseek(proc_mem, address, SEEK_SET);
	write(proc_mem, value, size);
	return true;
}
//--------------------------------------------
int Memory::Ex::VmReadBuffer(pid_t pid, mem_t address, void* buffer, size_t size)
{
	struct iovec src;
	struct iovec dst;
	dst.iov_base = buffer;
	dst.iov_len = size;
	src.iov_base = (void*)address;
	src.iov_len = size;
	return process_vm_readv(pid, &dst, 1, &src, 1, 0);
}
//--------------------------------------------
int Memory::Ex::VmWriteBuffer(pid_t pid, mem_t address, void* value, size_t size)
{
	struct iovec src;
	struct iovec dst;
	src.iov_base = value;
	src.iov_len = size;
	dst.iov_base = (void*)address;
	dst.iov_len = size;
	return process_vm_writev(pid, &src, 1, &dst, 1, 0);
}
//--------------------------------------------
void Memory::Ex::PtraceReadBuffer(pid_t pid, mem_t address, void* buffer, size_t size)
{
	char path_buffer[DEFAULT_BUFFER_SIZE];
	snprintf(path_buffer, sizeof(path_buffer), PROC_MEM_STR, pid);
	int proc_mem = open(path_buffer, O_RDWR);
	ptrace(PTRACE_ATTACH, pid, 0, 0);
	waitpid(pid, NULL, 0);
	pread(proc_mem, buffer, size, address);
	ptrace(PTRACE_DETACH, pid, 0, 0);
	close(proc_mem);
}
//--------------------------------------------
void Memory::Ex::PtraceWriteBuffer(pid_t pid, mem_t address, void* value, size_t size)
{
	char path_buffer[DEFAULT_BUFFER_SIZE];
	snprintf(path_buffer, sizeof(path_buffer), PROC_MEM_STR, pid);
	int proc_mem = open(path_buffer, O_RDWR);
	ptrace(PTRACE_ATTACH, pid, 0, 0);
	waitpid(pid, NULL, 0);
	pwrite(proc_mem, value, size, address);
	ptrace(PTRACE_DETACH, pid, 0, 0);
	close(proc_mem);
}
//--------------------------------------------
mem_t Memory::Ex::PatternScan(pid_t pid, mem_t beginAddr, mem_t endAddr, byte_t* pattern, char* mask)
{
	mask = ParseMask(mask);
	size_t patternLength = strlen(mask);
	size_t scanSize = (size_t)endAddr - beginAddr;
	for (size_t i = 0; i < scanSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			byte_t curByte;
			ReadBuffer(pid, (mem_t)(beginAddr + i + j), &curByte, sizeof(curByte));
			found &= mask[j] == UNKNOWN_BYTE || pattern[j] == curByte;
		}

		if (found) return beginAddr + i;
	}

	return 0;
}
//--------------------------------------------
bool Memory::Ex::IsProcessRunning(pid_t pid)
{
	char dirbuf[DEFAULT_BUFFER_SIZE];
	snprintf(dirbuf, sizeof(dirbuf), PROC_STR, pid);
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
int Memory::In::ProtectMemory(mem_t address, size_t size, int protection)
{
	long pagesize = sysconf(_SC_PAGE_SIZE);
	address = address - (address % pagesize);
	return mprotect((void*)address, size, protection);
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
//--------------------------------------------
mem_t Memory::In::PatternScan(mem_t baseAddr, mem_t endAddr, byte_t* pattern, char* mask)
{
	mask = ParseMask(mask);
	size_t patternLength = strlen(mask);
	size_t scanSize = endAddr - baseAddr;
	ProtectMemory(baseAddr, scanSize, PROT_EXEC | PROT_READ | PROT_WRITE);
	for (size_t i = 0; i < scanSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			found &= mask[j] == UNKNOWN_BYTE || pattern[j] == *(byte_t*)(baseAddr + i + j);
		}

		if (found) return baseAddr + i;
	}

	return BAD_RETURN;
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
	if (ProtectMemory((mem_t)src, size, PROT_EXEC | PROT_READ | PROT_WRITE) != 0) return false;

	//Save stolen bytes
	byte_t* bytes = new byte_t[size];
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
#	if defined(ARCH_X86)
	mem_t jmpAddr = ((mem_t)dst - (mem_t)src) - HOOK_MIN_SIZE;
	byte_t CodeCave[] = { JMP, 0x0, 0x0, 0x0, 0x0 };
	*(mem_t*)((mem_t)CodeCave + sizeof(JMP)) = jmpAddr;
	memcpy(src, CodeCave, sizeof(CodeCave));
#	elif defined(ARCH_X64)
	mem_t jmpAddr = (mem_t)dst;
	byte_t CodeCave[] = { MOV_RAX[0], MOV_RAX[1], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, JMP_RAX[0], JMP_RAX[1] };
	*(mem_t*)((mem_t)CodeCave + sizeof(MOV_RAX)) = jmpAddr;
	memcpy(src, CodeCave, sizeof(CodeCave));
#	endif
	return true;
}
//--------------------------------------------
byte_t* Memory::In::Hook::TrampolineHook(byte_t* src, byte_t* dst, size_t size)
{
	if (size < HOOK_MIN_SIZE) return 0;
	byte_t* gateway = new byte_t[size + HOOK_MIN_SIZE];
	ProtectMemory((mem_t)gateway, size + HOOK_MIN_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE);
	memcpy(gateway, src, size);
#	if defined(ARCH_X86)
	mem_t jmpBack = (mem_t)src - (mem_t)gateway - HOOK_MIN_SIZE;
	byte_t GatewayCodeCave[] = { JMP, 0x0, 0x0, 0x0, 0x0 };
	*(mem_t*)((mem_t)GatewayCodeCave + sizeof(JMP)) = jmpBack;
	memcpy((void*)((mem_t)gateway + size), (void*)GatewayCodeCave, sizeof(GatewayCodeCave));
#	elif defined(ARCH_X64)
	mem_t jmpBack = (mem_t)src + size;
	byte_t GatewayCodeCave[] = { MOV_RAX[0], MOV_RAX[1], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, JMP_RAX[0], JMP_RAX[1] };
	*(mem_t*)((mem_t)GatewayCodeCave + sizeof(MOV_RAX)) = jmpBack;
	memcpy((void*)((mem_t)gateway + size), (void*)GatewayCodeCave, sizeof(GatewayCodeCave));
#	endif
	Detour(src, dst, size);
	return gateway;
}
#endif //INCLUDE_INTERNALS
#endif //Linux