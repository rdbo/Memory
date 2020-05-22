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

#include "defines.h"
#include "types.h"
#include "includes.h"
#include "dependencies.h"

//## Memory Namespace

#if defined(WIN)

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
		BOOL WriteBuffer(HANDLE hProc, mem_t address, const ptr_t value, SIZE_T size);
		BOOL ReadBuffer(HANDLE hProc, mem_t address, ptr_t buffer, SIZE_T size);
		MODULEINFO GetModuleInfo(HANDLE hProcess, str_t moduleName);
		mem_t PatternScan(HANDLE hProcess, mem_t beginAddr, mem_t endAddr, byte_t* pattern, char* mask);
		mem_t PatternScanModule(HANDLE hProcess, str_t moduleName, byte_t* pattern, char* mask);

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

		namespace Injection
		{
			namespace DLL //Dynamic Link Library
			{
				bool LoadLib(HANDLE hProc, str_t dllPath);
			}
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
#	endif //INCLUDE_INTERNALS
}

//============================================
//============================================
//============================================

//Linux
#elif defined(LINUX)

namespace Memory
{
	char* ParseMask(char* mask);
#	if INCLUDE_EXTERNALS
	namespace Ex
	{
		pid_t GetProcessIdByName(str_t processName);
		mem_t GetModuleAddress(pid_t pid, str_t moduleName);
		bool ReadBuffer(pid_t pid, mem_t address, ptr_t buffer, size_t size);
		bool WriteBuffer(pid_t pid, mem_t address, ptr_t value, size_t size);
		int VmReadBuffer(pid_t pid, mem_t address, ptr_t buffer, size_t size);
		int VmWriteBuffer(pid_t pid, mem_t address, ptr_t value, size_t size);
		void PtraceReadBuffer(pid_t pid, mem_t address, ptr_t buffer, size_t size);
		void PtraceWriteBuffer(pid_t pid, mem_t address, ptr_t value, size_t size);
		mem_t PatternScan(pid_t pid, mem_t beginAddr, mem_t endAddr, byte_t* pattern, char* mask);
		bool IsProcessRunning(pid_t pid);
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
		mem_t PatternScan(mem_t baseAddr, mem_t endAddr, byte_t* pattern, char* mask);
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
			bool Detour(byte_t* src, byte_t* dst, size_t size);
			byte_t* TrampolineHook(byte_t* src, byte_t* dst, size_t size);
		}
	}
#	endif //Internals
}

#endif //Linux

#ifndef MEMORY
#define MEMORY
#endif