//Made by: rdbo
//Repository: github.com/rdbo/Memory

//Notes
//1. There can be duplicated/identical functions declared due to cross-platforming between Windows and Linux, and for organization.
//2. Make sure mem.h and mem.cpp (or mem.lib) are both updated to avoid any problems

//Usage notes
//1. The pattern scan default format is 'x' for known byte and '?' for unknown byte.
#pragma once
//## Pre-Includes

#define INCLUDE_EXTERNALS 1
#define INCLUDE_INTERNALS 1

//##Defines

//OS
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) && !defined(linux)
#define WIN
#elif defined(linux)
#define LINUX
#endif

//Architecture
#if defined(_M_IX86) || defined(__i386__)
#define ARCH_X86
#elif defined(_M_X64) || defined(__LP64__) || defined(_LP64)
#define ARCH_X64
#endif

//Character Set
#if defined(_UNICODE)
#define UCS
#else
#define MBCS
#endif

//Memory
#if defined(WIN) || defined(LINUX) //Check compatibility
#define MEMORY
#endif

//Other
#define BAD_RETURN 0

#define BYTE_SIZE 1
#if defined(ARCH_X86)
#define HOOK_MIN_SIZE 5
#elif defined(ARCH_X64)
#define HOOK_MIN_SIZE 12
#endif

#define KNOWN_BYTE 'x'
#define KNOWN_BYTE_UPPER 'X'
#define UNKNOWN_BYTE '?'

#define PAD_STR __pad
#define CONCAT_STR(a, b) a##b
#define CONCAT_STR_WRAPPER(a, b) CONCAT_STR(a, b)
#define NEW_PAD(size) CONCAT_STR_WRAPPER(PAD_STR, __COUNTER__)[size]
#define CREATE_UNION_MEMBER(type, varname, offset) struct { unsigned char NEW_PAD(offset); type varname; }

#if defined(UCS)
#define AUTO_STR(str) CONCAT_STR_WRAPPER(L, str)
#elif defined(MBCS)
#define AUTO_STR(str) str
#endif

//## Includes / types

#include <iostream>
#include <fstream>
#include <map>
#include <functional>

//Windows
#if defined(WIN)
#include <iostream>
#include <vector>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
typedef DWORD pid_t;
typedef uintptr_t mem_t;
//Linux
#elif defined(LINUX)
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <vector>
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#define INVALID_PID -1
#define DEFAULT_BUFFER_SIZE 64
#define MAX_BUFFER_SIZE 1024
#define PROC_STR "/proc/%i"
#define PROC_MAPS_STR "/proc/%i/maps"
#define PROC_MEM_STR "/proc/%i/mem"
#define EXECUTABLE_MEMORY_STR "r-xp"
typedef off_t mem_t;
typedef char TCHAR;
#endif

typedef unsigned char byte_t;
typedef TCHAR* tstr_t;
typedef char* cstr_t;
typedef std::basic_string<TCHAR> str_t;
typedef std::vector<str_t> vstr_t;

//## Nt / Zw
#if defined(WIN)
#define NTDLL_NAME AUTO_STR("ntdll.dll")
#define NTGETNEXTPROCESS_STR "NtGetNextProcess"
#define NTOPENPROCESS_STR "NtOpenProcess"
#define NTCLOSE_STR "NtClose"
#define NTREADVIRTUALMEMORY_STR "NtReadVirtualMemory"
#define NTWRITEVIRTUALMEMORY_STR "NtWriteVirtualMemory"

#define ZWGETNEXTPROCESS_STR "ZwGetNextProcess"
#define ZWOPENPROCESS_STR "ZwOpenProcess"
#define ZWCLOSE_STR "ZwClose"
#define ZWREADVIRTUALMEMORY_STR "ZwReadVirtualMemory"
#define ZWWRITEVIRTUALMEMORY_STR "ZwWriteVirtualMemory"

//## Nt / Zw Definitions
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING, ** PPUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

//## Nt / Zw Functions
typedef NTSTATUS(NTAPI* NtGetNextProcess_t)(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewProcessHandle);
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, const void* Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* ZwGetNextProcess_t)(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewProcessHandle);
typedef NTSTATUS(NTAPI* ZwOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* ZwClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI* ZwReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* ZwWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, const void* Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
#endif
//## Assembly Instructions

#if defined(ARCH_X86)

const byte_t JMP = 0xE9;

#elif defined(ARCH_X64)

const byte_t MOV_RAX[] = { 0x48, 0xB8 };
const byte_t JMP_RAX[] = { 0xFF, 0xE0 };

#endif

//## Memory Namespace

#if defined(MEMORY) && defined(WIN)

namespace Memory
{
	//Variables
	extern HWND g_hWnd;
	//Helper Functions
	BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam);
	char* ParseMask(char* mask);
#	if INCLUDE_EXTERNALS
	namespace Ex
	{
		pid_t GetProcessIdByName(str_t processName);
		pid_t GetProcessIdByWindow(str_t windowName);
		pid_t GetProcessIdByWindow(str_t windowClass, str_t windowName);
		pid_t GetProcessIdByWindow(HWND hWnd);
		pid_t GetProcessIdByHandle(HANDLE hProcess);
		HANDLE GetProcessHandle(pid_t pid, DWORD dwAccess = PROCESS_ALL_ACCESS);
		HWND GetWindowHandle(pid_t pid);
		mem_t GetModuleAddress(pid_t pid, str_t moduleName);
		vstr_t GetModuleList(pid_t pid);
		bool IsModuleLoaded(str_t moduleName, vstr_t moduleList);
		mem_t GetPointer(HANDLE hProc, mem_t ptr, std::vector<mem_t> offsets);
		BOOL WriteBuffer(HANDLE hProc, mem_t address, const void* value, SIZE_T size);
		BOOL ReadBuffer(HANDLE hProc, mem_t address, void* buffer, SIZE_T size);
		MODULEINFO GetModuleInfo(HANDLE hProcess, str_t moduleName);
		mem_t PatternScan(HANDLE hProcess, mem_t beginAddr, mem_t endAddr, byte_t* pattern, char* mask);
		mem_t PatternScanModule(HANDLE hProcess, str_t moduleName, byte_t* pattern, char* mask);

		namespace Nt
		{
			HANDLE GetProcessHandle(str_t processName, ACCESS_MASK dwAccess = MAXIMUM_ALLOWED);
			pid_t GetProcessID(str_t processName);
			HANDLE OpenProcessHandle(pid_t pid, ACCESS_MASK dwAccess = PROCESS_ALL_ACCESS);
			bool CloseProcessHandle(HANDLE hProcess);
			void WriteBuffer(HANDLE hProcess, mem_t address, const void* buffer, size_t size);
			void ReadBuffer(HANDLE hProcess, mem_t address, void* buffer, size_t size);
		}

		namespace Zw
		{
			HANDLE GetProcessHandle(str_t processName, ACCESS_MASK dwAccess = MAXIMUM_ALLOWED);
			pid_t GetProcessID(str_t processName);
			HANDLE OpenProcessHandle(pid_t pid, ACCESS_MASK dwAccess = PROCESS_ALL_ACCESS);
			bool CloseProcessHandle(HANDLE hProcess);
			void WriteBuffer(HANDLE hProcess, mem_t address, const void* buffer, size_t size);
			void ReadBuffer(HANDLE hProcess, mem_t address, void* buffer, size_t size);
		}

		namespace Injection
		{
			namespace DLL //Dynamic Link Library
			{
				bool LoadLib(HANDLE hProc, str_t dllPath);
			}
		}
	}
#	endif

#	if INCLUDE_INTERNALS
	namespace In
	{
		void ZeroMem(void* src, size_t size);
		bool IsBadPointer(void* pointer);
		pid_t GetCurrentProcessID();
		HANDLE GetCurrentProcessHandle();
		HWND GetCurrentWindowHandle();
		mem_t GetModuleAddress(str_t moduleName);
		mem_t GetPointer(mem_t baseAddress, std::vector<mem_t> offsets);
		bool WriteBuffer(mem_t address, const void* value, SIZE_T size);
		bool ReadBuffer(mem_t address, void* buffer, SIZE_T size);
		MODULEINFO GetModuleInfo(str_t moduleName);
		mem_t PatternScan(mem_t baseAddr, mem_t endAddr, byte_t* pattern, char* mask);;
		mem_t PatternScanModule(str_t moduleName, byte_t* pattern, char* mask);
		template <class type_t>
		type_t Read(mem_t address)
		{
			return *(type_t*)(address);
		}
		template <class type_t>
		void Write(mem_t address, type_t value)
		{
			*(type_t*)(address) = value;
		}

		namespace Hook
		{
			extern std::map<mem_t, std::vector<byte_t>> restore_arr;
			bool Restore(mem_t address);
			bool Detour(byte_t* src, byte_t* dst, size_t size);
			byte_t* TrampolineHook(byte_t* src, byte_t* dst, size_t size);
		}
	}
#	endif
}

//============================================
//============================================
//============================================

#elif defined(MEMORY) && defined(LINUX)

namespace Memory
{
	char* ParseMask(char* mask);
#	if INCLUDE_EXTERNALS
	namespace Ex
	{
		pid_t GetProcessIdByName(str_t processName);
		mem_t GetModuleAddress(pid_t pid, str_t moduleName);
		bool ReadBuffer(pid_t pid, mem_t address, void* buffer, size_t size);
		bool WriteBuffer(pid_t pid, mem_t address, void* value, size_t size);
		int VmReadBuffer(pid_t pid, mem_t address, void* buffer, size_t size);
		int VmWriteBuffer(pid_t pid, mem_t address, void* value, size_t size);
		void PtraceReadBuffer(pid_t pid, mem_t address, void* buffer, size_t size);
		void PtraceWriteBuffer(pid_t pid, mem_t address, void* value, size_t size);
		mem_t PatternScan(pid_t pid, mem_t beginAddr, mem_t endAddr, byte_t* pattern, char* mask);
		bool IsProcessRunning(pid_t pid);
	}
#	endif //INCLUDE_EXTERNALS
#	if INCLUDE_INTERNALS
	namespace In
	{
		void ZeroMem(void* src, size_t size);
		int ProtectMemory(mem_t address, size_t size, int protection);
		bool IsBadPointer(void* pointer);
		pid_t GetCurrentProcessID();
		bool ReadBuffer(mem_t address, void* buffer, size_t size);
		bool WriteBuffer(mem_t address, void* value, size_t size);
		mem_t PatternScan(mem_t baseAddr, mem_t endAddr, byte_t* pattern, char* mask);
		template <class type_t>
		type_t Read(mem_t address)
		{
			if (IsBadPointer((void*)address)) return (type_t)BAD_RETURN;
			return *(type_t*)(address);
		}
		template <class type_t>
		bool Write(mem_t address, type_t value)
		{
			if (IsBadPointer((void*)address)) return false;
			*(type_t*)(address) = value;
			return true;
		}

		namespace Hook
		{
			extern std::map<mem_t, std::vector<byte_t>> restore_arr;
			bool Restore(mem_t address);
			bool Detour(byte_t* src, byte_t* dst, size_t size);
			byte_t* TrampolineHook(byte_t* src, byte_t* dst, size_t size);
		}
	}
#	endif
}

#endif