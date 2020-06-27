#ifndef linux //Delete this if I forgot to
#define linux
#endif

#pragma once
#ifndef MEMORY

//Pre-Includes

#define MEM_INCLUDE_EXTERNALS 1
#define MEM_INCLUDE_INTERNALS 1

//Operating System

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) && !defined(linux)
#define MEM_WIN
#elif defined(linux)
#define MEM_LINUX
#endif

//Architecture

#if defined(_M_IX86) || defined(__i386__)
#define MEM_86
#elif defined(_M_X64) || defined(__LP64__) || defined(_LP64)
#define MEM_64
#endif

//Charset

#if defined(_UNICODE)
#define MEM_UCS
#else
#define MEM_MBCS
#endif

//Compatibility

#define MEM_COMPATIBLE (defined(MEM_WIN) || defined(MEM_LINUX)) && (defined(MEM_86) || defined(MEM_64))
#define MEM_INCLUDE MEM_INCLUDE_EXTERNALS || MEM_INCLUDE_INTERNALS

#if MEM_COMPATIBLE

//Functions

#define PP_NARG(...) \
         PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
         PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#define PP_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0

#define PAD_STR __pad
#define _CONCAT_STR(a, b) a##b
#define CONCAT_STR(a, b) _CONCAT_STR(a, b)
#define _MERGE_STR(a, b) a b
#define MERGE_STR(a, b) _MERGE_STR(a, b)
#define NEW_PAD(size) CONCAT_STR(PAD_STR, __COUNTER__)[size]
#define CREATE_UNION_MEMBER(type, varname, offset) struct { unsigned char NEW_PAD(offset); type varname; } //Create relative offset variable from union
#define _BUFFER_GENERATE(...) { __VA_ARGS__ }
#define ASM_GENERATE(...) _BUFFER_GENERATE(__VA_ARGS__)
#define _CALC_ARG_LENGTH(...) PP_NARG(__VA_ARGS__)
#define CALC_ARG_LENGTH(...) _CALC_ARG_LENGTH(__VA_ARGS__)
#define CALC_ASM_LENGTH(...) CALC_ARG_LENGTH(__VA_ARGS__)

#if defined(MEM_UCS)
#define MEM_STR(str) CONCAT_STR(L, str)
#elif defined(MEM_MBCS)
#define MEM_STR(str) str
#endif

//Assembly

#define _MEM_JMP        0xE9
#define _MEM_JMP_RAX    0xFF, 0xE0
#define _MEM_JMP_EAX    0xFF, 0xE0
#define _MEM_CALL       0xE8
#define _MEM_CALL_EAX   0xFF, 0xD0
#define _MEM_CALL_RAX   0xFF, 0xD0
#define _MEM_MOVABS_RAX 0x48, 0xB8
#define _MEM_MOV_EAX    0xB8
#define _MEM_PUSH       0x68
#define _MEM_PUSH_RAX   0x50
#define _MEM_PUSH_EAX   0x50
#define _MEM_RET        0xC3
#define _MEM_BYTE       0x0
#define _MEM_WORD       0x0, 0x0
#define _MEM_DWORD      0x0, 0x0, 0x0, 0x0
#define _MEM_QWORD      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0

//Memory Protections

#if defined(MEM_WIN)
#elif defined(MEM_LINUX)
#define MEM_PROT_X   PROT_EXEC
#define MEM_PROT_R   PROT_READ
#define MEM_PROT_W   PROT_WRITE
#define MEM_PROT_XRW MEM_PROT_X | MEM_PROT_R | MEM_PROT_W
#endif

//Other

#define DEFAULT_BUFFER_SIZE 64
#define MAX_BUFFER_SIZE 1024
#define KNOWN_BYTE       'x'
#define KNOWN_BYTE_UPPER 'X'
#define UNKNOWN_BYTE     '?'
#define BAD_RETURN -1

//## Includes

#include <iostream>
#include <map>
#include <vector>
#include <string.h>
#include <stdint.h>

#if defined(MEM_WIN)
#elif defined(MEM_LINUX)
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#endif

//## Types

typedef uint8_t  byte_t;
typedef uint16_t word_t;
typedef uint32_t dword_t;
typedef uint64_t qword_t;
typedef void*    addr_t;
typedef byte_t*  buffer_t;

#if defined(MEM_WIN)
typedef TCHAR     char_t;
#elif defined(MEM_LINUX)
typedef char     char_t;
#endif

#if defined(MEM_86)
typedef dword_t mem_t;
#elif defined(MEM_64)
typedef qword_t mem_t;
#endif

typedef char* cstr_t;
typedef std::basic_string<char_t> str_t;

//## Memory

#if MEM_INCLUDE
#if defined(MEM_WIN)
namespace Memory
{
#   if MEM_INCLUDE_EXTERNALS
    namespace Ex
    {

    }
#   endif //MEM_INCLUDE_EXTERNALS

#   if MEM_INCLUDE_INTERNALS
    namespace In
    {

    }
#   endif //MEM_INCLUDE_INTERNALS
}
#elif defined(MEM_LINUX)
namespace Memory
{
    str_t ParseMask(str_t mask);
#   if MEM_INCLUDE_EXTERNALS
    namespace Ex
    {
        pid_t GetProcessIdByName(str_t processName);
		addr_t GetModuleAddress(pid_t pid, str_t moduleName);
        int Read(pid_t pid, addr_t src, addr_t dst, size_t size);
		int Write(pid_t pid, addr_t src, addr_t data, size_t size);
        addr_t PatternScan(pid_t pid, addr_t begin, addr_t end, buffer_t pattern, str_t mask);
		bool IsProcessRunning(pid_t pid);
    }
#   endif //MEM_INCLUDE_EXTERNALS

#   if MEM_INCLUDE_INTERNALS
    namespace In
    {
        pid_t GetProcessId();
        addr_t Allocate(size_t size, int protection);
        bool IsBadPointer(addr_t pointer); //Not recommended
        int Protect(addr_t src, size_t size, int protection);
        void Zero(addr_t src, size_t size);
        void Read(addr_t src, addr_t dst, size_t size);
        void Write(addr_t src, addr_t data, size_t size);
        addr_t PatternScan(addr_t begin, addr_t end, buffer_t pattern, str_t mask);

        //Detour

        enum class DetourClass
        {
            Method0,
            //mov *ax, ABS_ADDR
            //jmp *ax

            Method1,
            //jmp REL_ADDR

            Method2,
            //mov *ax, ABS_ADDR
            //push *ax
            //ret

            Method3,
            //push ABS_ADDR_DWORD
            //ret

            Method4,
            //mov *ax, ABS_ADDR
            //call *ax

            Method5,
            //call REL_ADDR

        };

        int DetourRestore(addr_t src);
        int DetourLength(DetourClass method);
        int Detour(addr_t src, addr_t dst, int size, DetourClass method = DetourClass::Method0);
        addr_t DetourTrampoline(addr_t src, addr_t dst, int size, DetourClass method = DetourClass::Method0, addr_t gateway_out = NULL);

    }
#   endif //MEM_INCLUDE_INTERNALS
}
#endif
#endif //MEM_INCLUDE

#endif //MEM_COMPATIBLE
#define MEMORY
#endif //MEMORY