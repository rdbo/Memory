#ifndef linux
#define  linux
#endif

#pragma once
#ifndef MEMORY
#include "defs.h"
#if MEM_COMPATIBLE
#include "includes.h"
#include "types.h"
#include "deps.h"

//Memory Namespace
#if defined(MEM_WIN)
#elif defined(MEM_LINUX)
namespace Memory
{
    cstr_t ParseMask(cstr_t mask);
#   if INCLUDE_EXTERNALS
    namespace Ex
    {

    }
#   endif //INCLUDE_EXTERNALS

#   if INCLUDE_INTERNALS
    namespace In
    {
        void ZeroMem(ptr_t src, size_t size);
		int ProtectMemory(mem_t address, size_t size, int protection);
		bool IsBadPointer(ptr_t pointer);
		pid_t GetCurrentProcessID();
		bool ReadBuffer(mem_t address, ptr_t buffer, size_t size);
		bool WriteBuffer(mem_t address, ptr_t value, size_t size);
		mem_t PatternScan(mem_t baseAddr, mem_t endAddr, buffer_t pattern, cstr_t mask);
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
            enum class Method
            {
                mJump0,
                mJump1,
                mPush0,
                mCall0,
            };

            extern std::map<mem_t, std::vector<byte_t>> restore_arr;
            size_t GetHookSize(Method method);
            bool Restore(mem_t address);
			bool Detour(buffer_t src, buffer_t dst, size_t size, Method method);
			buffer_t TrampolineHook(buffer_t src, buffer_t dst, size_t size, Method method);
        }
    }
#   endif //INCLUDE_INTERNALS
}
#endif //Memory Namespace

#endif //MEM_COMPATIBLE
#define MEMORY
#endif //MEMORY