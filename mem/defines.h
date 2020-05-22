#pragma once

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

//Functions
#define PAD_STR __pad
#define CONCAT_STR(a, b) a##b
#define CONCAT_STR_WRAPPER(a, b) CONCAT_STR(a, b)
#define NEW_PAD(size) CONCAT_STR_WRAPPER(PAD_STR, __COUNTER__)[size]
#define CREATE_UNION_MEMBER(type, varname, offset) struct { unsigned char NEW_PAD(offset); type varname; } //Create relative offset variable from union

#if defined(UCS)
#define AUTO_STR(str) CONCAT_STR_WRAPPER(L, str)
#elif defined(MBCS)
#define AUTO_STR(str) str
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
#endif

//Linux
#if defined(LINUX)
#define PROC_STR "/proc/%i"
#define PROC_MAPS_STR "/proc/%i/maps"
#define PROC_MEM_STR "/proc/%i/mem"
#define EXECUTABLE_MEMORY_STR "r-xp"
#endif