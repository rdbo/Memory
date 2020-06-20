//## Defines

#pragma once
#ifndef MEMORY

//Pre-Includes

#define INCLUDE_EXTERNALS 1
#define INCLUDE_INTERNALS 1

//Operating System

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) && !defined(linux)
#define MEM_WIN
#elif defined(linux)
#define MEM_LINUX
#endif

//Architecture

#if defined(_M_IX86) || defined(__i386__)
#define MEM_X86
#elif defined(_M_X64) || defined(__LP64__) || defined(_LP64)
#define MEM_X64
#endif

//Compatibility

#define MEM_COMPATIBLE (defined(MEM_WIN) || defined(MEM_LINUX)) && (defined(MEM_X86) || defined(MEM_X64))

//Character Set

#if defined(_UNICODE)
#define MEM_UCS
#else
#define MEM_MBCS
#endif

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
#define AUTO_STR(str) CONCAT_STR(L, str)
#elif defined(MEM_MBCS)
#define AUTO_STR(str) str
#endif

#if defined(MEM_WIN) //Windows Macros
#define NT_STR "Nt"
#define ZW_STR "Zw"
#define NT_FUNCTION_STR(str) MERGE_STR(NT_STR, str)
#define ZW_FUNCTION_STR(str) MERGE_STR(ZW_STR, str)
#define FUNCTION_STR MERGE_STR(__DllFunction, __COUNTER__)
#define RUN_DLL_FUNCTION(strDllName, strFunctionName, Function_t, ...) Function_t FUNCTION_STR = (Function_t)GetProcAddress(GetModuleHandle(strDllName), strFunctionName); if(FUNCTION_STR) FUNCTION_STR(##__VA_ARGS__)
#elif defined(MEM_LINUX) //Linux Macros
#endif

//Assembly

#define _MEM_JMP        0xE9
#define _MEM_JMP_RAX    0xFF, 0xE0
#define _MEM_JMP_EAX    0xFF, 0xE0
#define _MEM_CALL_EAX   0xFF, 0xD0
#define _MEM_CALL_RAX   0xFF, 0xD0
#define _MEM_MOVABS_RAX 0x48, 0xB8
#define _MEM_MOV_EAX    0xB8
#define _MEM_PUSH_RAX   0x50
#define _MEM_PUSH_EAX   0x50
#define _MEM_RET        0xC3
#define _MEM_BYTE       0x0
#define _MEM_WORD       0x0, 0x0
#define _MEM_DWORD      0x0, 0x0, 0x0, 0x0
#define _MEM_QWORD      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0

#if defined(MEM_X86)
#define _MEM_MAXWORD _MEM_DWORD
#elif defined(MEM_X64)
#define _MEM_MAXWORD _MEM_QWORD
#endif

//Assembly Buffers

const unsigned char MEM_JMP          = ASM_GENERATE(_MEM_JMP);
const unsigned char MEM_JMP_RAX[]    = ASM_GENERATE(_MEM_JMP_RAX);
const unsigned char MEM_JMP_EAX[]    = ASM_GENERATE(_MEM_JMP_EAX);
const unsigned char MEM_MOVABS_RAX[] = ASM_GENERATE(_MEM_MOVABS_RAX);
const unsigned char MEM_MOV_EAX[]    = ASM_GENERATE(_MEM_MOV_EAX);
const unsigned char MEM_PUSH_RAX[]   = ASM_GENERATE(_MEM_PUSH_RAX);
const unsigned char MEM_PUSH_EAX[]   = ASM_GENERATE(_MEM_PUSH_EAX);
const unsigned char MEM_RET          = ASM_GENERATE(_MEM_RET);
const unsigned char MEM_BYTE[]       = ASM_GENERATE(_MEM_BYTE);
const unsigned char MEM_WORD[]       = ASM_GENERATE(_MEM_WORD);
const unsigned char MEM_DWORD[]      = ASM_GENERATE(_MEM_DWORD);
const unsigned char MEM_QWORD[]      = ASM_GENERATE(_MEM_QWORD);

//Others

#define KNOWN_BYTE       'x'
#define KNOWN_BYTE_UPPER 'X'
#define UNKNOWN_BYTE     '?'

#define INVALID_PID         -1
#define BAD_RETURN          0
#define DEFAULT_BUFFER_SIZE 64
#define MAX_BUFFER_SIZE     1024

//Strings

#if defined(WIN) //Windows strings
#define NTDLL_NAME AUTO_STR("ntdll.dll")
#define GETNEXTPROCESS_STR "GetNextProcess"
#define OPENPROCESS_STR "OpenProcess"
#define CLOSE_STR "Close"
#define READVIRTUALMEMORY_STR "ReadVirtualMemory"
#define WRITEVIRTUALMEMORY_STR "WriteVirtualMemory"
#elif defined(MEM_LINUX) //Linux strings
#define PROC_STR "/proc/%i"
#define PROC_MAPS_STR "/proc/%i/maps"
#define PROC_MEM_STR "/proc/%i/mem"
#define EXECUTABLE_MEMORY_STR "r-xp"
#endif

#endif //MEMORY