#ifndef linux
#define linux
#endif

//Made by rdbo
//Repository: https://github.com/rdbo/Memory
//Notes
//1. There can be duplicated/identical functions declared due to cross-platforming between Windows and Linux, and for organization.
//2. Make all the files are up-to-date to avoid any problems

//Usage notes
//1. The pattern scan default format is 'x' for known byte and '?' for unknown byte.

#pragma once
#ifndef MEMORY
//# Defines

//Operating System
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

//Pre-Includes

#define INCLUDE_EXTERNALS 1
#define INCLUDE_INTERNALS 1

//Functions
#define PAD_STR __pad
#define _CONCAT_STR(a, b) a##b
#define CONCAT_STR(a, b) _CONCAT_STR(a, b)
#define _MERGE_STR(a, b) a b
#define MERGE_STR(a, b) _MERGE_STR(a, b)
#define NEW_PAD(size) CONCAT_STR(PAD_STR, __COUNTER__)[size]
#define CREATE_UNION_MEMBER(type, varname, offset) struct { unsigned char NEW_PAD(offset); type varname; } //Create relative offset variable from union

#if defined(UCS)
#define AUTO_STR(str) CONCAT_STR(L, str)
#elif defined(MBCS)
#define AUTO_STR(str) str
#endif

#if defined(WIN)
#define NT_STR "Nt"
#define ZW_STR "Zw"
#define NT_FUNCTION_STR(str) MERGE_STR(NT_STR, str)
#define ZW_FUNCTION_STR(str) MERGE_STR(ZW_STR, str)
#define FUNCTION_STR MERGE_STR(__DllFunction, __COUNTER__)
#define RUN_DLL_FUNCTION(strDllName, strFunctionName, Function_t, ...) Function_t FUNCTION_STR = (Function_t)GetProcAddress(GetModuleHandle(strDllName), strFunctionName); if(FUNCTION_STR) FUNCTION_STR(##__VA_ARGS__)
#endif

//Assembly Operations
const unsigned char JMP_OP = 0xE9;
const unsigned char MOVABS_RAX_OP[] = { 0x48, 0xB8 };
const unsigned char JMP_RAX_OP[] = { 0xFF, 0xE0 };
const unsigned char EMPTY_DWORD[] = { 0x0, 0x0, 0x0, 0x0 };
const unsigned char EMPTY_QWORD[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

//Other

#define BYTE_SIZE 1
#define JUMP_LENGTH_X86 5
#define JUMP_LENGTH_X64 12

#if defined(ARCH_X86)
#define JUMP_LENGTH JUMP_LENGTH_X86
#elif defined(ARCH_X64)
#define JUMP_LENGTH JUMP_LENGTH_X64
#endif

#define KNOWN_BYTE       'x'
#define KNOWN_BYTE_UPPER 'X'
#define UNKNOWN_BYTE     '?'

#define INVALID_PID -1
#define BAD_RETURN   0
#define DEFAULT_BUFFER_SIZE 64
#define MAX_BUFFER_SIZE 1024

#if defined(WIN)
#define NTDLL_NAME AUTO_STR("ntdll.dll")
#define GETNEXTPROCESS_STR "GetNextProcess"
#define OPENPROCESS_STR "OpenProcess"
#define CLOSE_STR "Close"
#define READVIRTUALMEMORY_STR "ReadVirtualMemory"
#define WRITEVIRTUALMEMORY_STR "WriteVirtualMemory"
#endif

//Linux
#if defined(LINUX)
#define PROC_STR "/proc/%i"
#define PROC_MAPS_STR "/proc/%i/maps"
#define PROC_MEM_STR "/proc/%i/mem"
#define EXECUTABLE_MEMORY_STR "r-xp"
#endif

//# Includes

//Any
#include <iostream>
#include <fstream>
#include <map>

//Windows
#if defined(WIN)
#include <iostream>
#include <vector>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#endif

//Linux

#if defined(LINUX)
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
#endif

//# Types

//Windows
#if defined(WIN)
typedef DWORD pid_t;
#endif

//Linux
#if defined(LINUX)
typedef char TCHAR;
#endif

//Any
#if defined(ARCH_X86)
typedef unsigned int mem_t;
#elif defined(ARCH_X64)
typedef unsigned long long mem_t;
#endif
typedef void* ptr_t;
typedef unsigned char byte_t;
typedef TCHAR* tstr_t;
typedef char* cstr_t;
typedef std::basic_string<TCHAR> str_t;
typedef std::vector<str_t> vstr_t;

//# Dependencies

#if defined(WIN)
typedef struct _UNICODE_STRING;
typedef _UNICODE_STRING UNICODE_STRING, * PUNICODE_STRING, ** PPUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES;
typedef _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID;
typedef _CLIENT_ID CLIENT_ID, *PCLIENT_ID;
typedef NTSTATUS(NTAPI* NtGetNextProcess_t)(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewProcessHandle);
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, const ptr_t Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* ZwGetNextProcess_t)(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewProcessHandle);
typedef NTSTATUS(NTAPI* ZwOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* ZwClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI* ZwReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* ZwWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, const ptr_t Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

#elif defined(LINUX)
#endif

//# Memory Namespace

#if defined(WIN)
namespace Memory
{
	//Variables
	extern HWND g_hWnd;
	//Helper Functions
	BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam);
	cstr_t ParseMask(cstr_t mask);
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
		BOOL WriteBuffer(HANDLE hProc, mem_t address, const ptr_t value, SIZE_T size);
		BOOL ReadBuffer(HANDLE hProc, mem_t address, ptr_t buffer, SIZE_T size);
		MODULEINFO GetModuleInfo(HANDLE hProcess, str_t moduleName);
		mem_t PatternScan(HANDLE hProcess, mem_t beginAddr, mem_t endAddr, byte_t* pattern, cstr_t mask);
		mem_t PatternScanModule(HANDLE hProcess, str_t moduleName, byte_t* pattern, cstr_t mask);

		namespace Nt
		{
			HANDLE GetProcessHandle(str_t processName, ACCESS_MASK dwAccess = MAXIMUM_ALLOWED);
			pid_t GetProcessID(str_t processName);
			HANDLE OpenProcessHandle(pid_t pid, ACCESS_MASK dwAccess = PROCESS_ALL_ACCESS);
			bool CloseProcessHandle(HANDLE hProcess);
			void WriteBuffer(HANDLE hProcess, mem_t address, const ptr_t buffer, size_t size);
			void ReadBuffer(HANDLE hProcess, mem_t address, ptr_t buffer, size_t size);
		}

		namespace Zw
		{
			HANDLE GetProcessHandle(str_t processName, ACCESS_MASK dwAccess = MAXIMUM_ALLOWED);
			pid_t GetProcessID(str_t processName);
			HANDLE OpenProcessHandle(pid_t pid, ACCESS_MASK dwAccess = PROCESS_ALL_ACCESS);
			bool CloseProcessHandle(HANDLE hProcess);
			void WriteBuffer(HANDLE hProcess, mem_t address, const ptr_t buffer, size_t size);
			void ReadBuffer(HANDLE hProcess, mem_t address, ptr_t buffer, size_t size);
		}

		namespace DLL //Dynamic Link Library
		{
			bool LoadLib(HANDLE hProc, str_t dllPath);
		}
	}
#	endif //INCLUDE_EXTERNALS

#	if INCLUDE_INTERNALS
	namespace In
	{
		void ZeroMem(ptr_t src, size_t size);
		bool IsBadPointer(ptr_t pointer);
		pid_t GetCurrentProcessID();
		HANDLE GetCurrentProcessHandle();
		HWND GetCurrentWindowHandle();
		mem_t GetModuleAddress(str_t moduleName);
		mem_t GetPointer(mem_t baseAddress, std::vector<mem_t> offsets);
		bool WriteBuffer(mem_t address, const ptr_t value, SIZE_T size);
		bool ReadBuffer(mem_t address, ptr_t buffer, SIZE_T size);
		MODULEINFO GetModuleInfo(str_t moduleName);
		mem_t PatternScan(mem_t baseAddr, mem_t endAddr, byte_t* pattern, cstr_t mask);;
		mem_t PatternScanModule(str_t moduleName, byte_t* pattern, cstr_t mask);
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
			bool Detour(ptr_t src, ptr_t dst, size_t size);
			byte_t* TrampolineHook(ptr_t src, ptr_t dst, size_t size);
		}
	}
#	endif //INCLUDE_INTERNALS
}

//============================================
//============================================
//============================================

//Linux
#elif defined(LINUX)

namespace Memory
{
	cstr_t ParseMask(cstr_t mask);
#	if INCLUDE_EXTERNALS
	namespace Ex
	{
		enum class API
		{
			Default, VM, Ptrace
		};

		pid_t GetProcessIdByName(str_t processName);
		mem_t GetModuleAddress(pid_t pid, str_t moduleName);
		bool ReadBuffer(pid_t pid, mem_t address, ptr_t buffer, size_t size, API method = API::Default);
		bool WriteBuffer(pid_t pid, mem_t address, ptr_t value, size_t size, API method =  API::Default);
		mem_t PatternScan(pid_t pid, mem_t beginAddr, mem_t endAddr, byte_t* pattern, cstr_t mask, API method = API::Default);
		bool IsProcessRunning(pid_t pid);
		namespace Ptrace
		{
			void ReadBuffer(pid_t pid, mem_t address, ptr_t buffer, size_t size);
			void WriteBuffer(pid_t pid, mem_t address, ptr_t value, size_t size);
		}

		namespace VM
		{
			int ReadBuffer(pid_t pid, mem_t address, ptr_t buffer, size_t size);
			int WriteBuffer(pid_t pid, mem_t address, ptr_t value, size_t size);
		}
	}
#	endif //INCLUDE_EXTERNALS
#	if INCLUDE_INTERNALS
	namespace In
	{
		void ZeroMem(ptr_t src, size_t size);
		int ProtectMemory(mem_t address, size_t size, int protection);
		bool IsBadPointer(ptr_t pointer);
		pid_t GetCurrentProcessID();
		bool ReadBuffer(mem_t address, ptr_t buffer, size_t size);
		bool WriteBuffer(mem_t address, ptr_t value, size_t size);
		mem_t PatternScan(mem_t baseAddr, mem_t endAddr, byte_t* pattern, cstr_t mask);
		template <class type_t>
		type_t Read(mem_t address)
		{
			if (IsBadPointer((ptr_t)address)) return (type_t)BAD_RETURN;
			return *(type_t*)(address);
		}
		template <class type_t>
		bool Write(mem_t address, type_t value)
		{
			if (IsBadPointer((ptr_t)address)) return false;
			*(type_t*)(address) = value;
			return true;
		}

		namespace Hook
		{
			extern std::map<mem_t, std::vector<byte_t>> restore_arr;
			bool Restore(mem_t address);
			bool Detour(ptr_t src, ptr_t dst, size_t size);
			byte_t* TrampolineHook(ptr_t src, ptr_t dst, size_t size);
		}
	}
#	endif //Internals
}

#endif //Linux

//# Dependency Declarations

#if defined(WIN)
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};
#elif defined(LINUX)
#endif

#define MEMORY
#endif //MEMORY