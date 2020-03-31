//Made by: rdbo
//Repository: github.com/rdbo/Memory

//Notes
//1. There can be duplicated/identical functions declared due to cross-platforming between Windows and Linux, and for organization.

#pragma once

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
typedef DWORD pid_t;
typedef uintptr_t mem_t;
//Linux
#elif defined(LINUX)
#endif

typedef unsigned char byte_t;
typedef TCHAR* tstr_t;
typedef char* cstr_t;
typedef std::basic_string<TCHAR> str_t;

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
	namespace Ex
	{
		pid_t GetProcessIdByName(str_t processName);
		pid_t GetProcessIdByWindow(str_t windowName);
		pid_t GetProcessIdByWindow(str_t windowClass, str_t windowName);
		HANDLE GetProcessHandle(pid_t pid);
		mem_t GetModuleAddress(str_t moduleName, pid_t pid);
		mem_t GetPointer(HANDLE hProc, mem_t ptr, std::vector<mem_t> offsets);
		BOOL WriteBuffer(HANDLE hProc, mem_t address, const void* value, SIZE_T size);
		BOOL ReadBuffer(HANDLE hProc, mem_t address, void* buffer, SIZE_T size);
	}

	namespace In
	{
		void ZeroMem(void* src, size_t size);
		bool IsBadPointer(void* pointer);
		pid_t GetCurrentProcessID();
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
		HANDLE GetCurrentProcessHandle();
		mem_t GetModuleAddress(str_t moduleName);
		mem_t GetPointer(mem_t baseAddress, std::vector<mem_t> offsets);
		bool WriteBuffer(mem_t address, const void* value, SIZE_T size);
		bool ReadBuffer(mem_t address, void* buffer, SIZE_T size);

		namespace Hook
		{
			extern std::map<mem_t, std::vector<byte_t>> restore_arr;
			bool Restore(mem_t address);
			bool Detour(byte_t* src, byte_t* dst, size_t size);
			byte_t* TrampolineHook(byte_t* src, byte_t* dst, size_t size);
		}
	}
}

#elif defined(MEMORY) && defined(LINUX)

namespace Memory
{

}

#endif