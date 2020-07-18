//Made by rdbo
//https://github.com/rdbo/Memory

#ifndef MEM
#define MEM

//Operating System

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) && !defined(linux)
#define MEM_WIN
#elif defined(linux) || defined(__linux__)
#define MEM_LINUX
#endif

//Architecture

#if defined(_M_IX86) || defined(__i386__) || __WORDSIZE == 32
#define MEM_86
#elif defined(_M_X64) || defined(__LP64__) || defined(_LP64) || __WORDSIZE == 64
#define MEM_64
#endif

//Charset

#if defined(_UNICODE) && defined(MEM_WIN)
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

#if defined(MEM_86)
#define _MEM_DETOUR_METHOD0    _MEM_MOV_EAX, _MEM_DWORD, _MEM_JMP_EAX
#define _MEM_DETOUR_METHOD1    _MEM_JMP, _MEM_DWORD
#define _MEM_DETOUR_METHOD2    _MEM_MOV_EAX, _MEM_DWORD, _MEM_PUSH_EAX, _MEM_RET
#define _MEM_DETOUR_METHOD3    _MEM_PUSH, _MEM_DWORD, _MEM_RET
#define _MEM_DETOUR_METHOD4    _MEM_MOV_EAX, _MEM_DWORD, _MEM_CALL_EAX
#define _MEM_DETOUR_METHOD5    _MEM_CALL, _MEM_DWORD
#elif defined(MEM_64)
#define _MEM_DETOUR_METHOD0    _MEM_MOVABS_RAX, _MEM_QWORD, _MEM_JMP_RAX
#define _MEM_DETOUR_METHOD1    _MEM_JMP, _MEM_DWORD
#define _MEM_DETOUR_METHOD2    _MEM_MOVABS_RAX, _MEM_QWORD, _MEM_PUSH_RAX, _MEM_RET
#define _MEM_DETOUR_METHOD3    _MEM_PUSH, _MEM_DWORD, _MEM_RET
#define _MEM_DETOUR_METHOD4    _MEM_MOVABS_RAX, _MEM_QWORD, _MEM_CALL_RAX
#define _MEM_DETOUR_METHOD5    _MEM_CALL, _MEM_DWORD
#endif

//Other
#define MEM_BAD_RETURN -1
#define MEM_KNOWN_BYTE       'x'
#define MEM_UNKNOWN_BYTE     '?'

//Compatibility

#define MEM_COMPATIBLE_OS   defined(MEM_WIN) || defined(MEM_LINUX)
#define MEM_COMPATIBLE_ARCH defined(MEM_86) || defined(MEM_64)
#define MEM_COMPATIBLE MEM_COMPATIBLE_OS && MEM_COMPATIBLE_ARCH

#if MEM_COMPATIBLE

//Includes
#include <iostream>
#include <array>
#include <vector>
#include <map>
#include <string.h>
#include <fstream>
#include <sstream>
#if defined(MEM_WIN)
#elif defined(MEM_LINUX)
#include <fstream>
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

namespace mem
{
    typedef bool               bool_t;
    typedef char               char_t;
    typedef int                int_t;
    typedef void               void_t;

    typedef char               int8_t;
    typedef short              int16_t;
    typedef int                int32_t;
    typedef long long          int64_t;

    typedef unsigned char      uint8_t;
    typedef unsigned short     uint16_t;
    typedef unsigned int       uint32_t;
    typedef unsigned long long uint64_t;

#   if defined(MEM_WIN)
    typedef uint32_t pid_t;
#   elif defined(MEM_LINUX)
    typedef int32_t  pid_t;
#   endif

#   if defined(MEM_86)
    typedef int32_t  intptr_t;
    typedef uint32_t uintptr_t;
#   elif defined(MEM_64)
    typedef int64_t  intptr_t;
    typedef uint64_t uintptr_t;
#   endif

    typedef uint8_t  byte_t;
    typedef uint16_t word_t;
    typedef uint32_t dword_t;
    typedef uint64_t qword_t;

    typedef byte_t*                   byteptr_t;
    typedef std::basic_string<int8_t> bytearray_t;
    typedef void_t*                   voidptr_t;
    typedef unsigned long             size_t;
    typedef std::basic_string<char_t> string_t;

    typedef struct
    {
        string_t name;
        voidptr_t base;
        uintptr_t size;
        voidptr_t end;
#       if defined(MEM_WIN)
#       elif defined(MEM_LINUX)
#       endif
    }moduleinfo_t;

    typedef struct
    {
        string_t name;
        pid_t    pid;
#       if defined(MEM_WIN)
#       elif defined(MEM_LINUX)
#       endif
    }process_t;

    enum class detour_int
    {
        method0,
        method1,
        method2,
        method3,
        method4,
        method5
    };

    string_t parse_mask(string_t mask);

    namespace ex
    {
        pid_t        get_pid (string_t process_name);
        process_t    get_process(string_t process_name);
        process_t    get_process(pid_t pid);
        string_t     get_process_name(pid_t pid);
        moduleinfo_t get_module_info (process_t process, string_t module_name);
        int_t        read  (process_t process, voidptr_t src, voidptr_t dst,  size_t size);
        int_t        write (process_t process, voidptr_t src, byteptr_t data, size_t size);
        int_t        set   (process_t process, voidptr_t src, byte_t byte,    size_t size);
        voidptr_t    pattern_scan(process_t process, bytearray_t pattern, string_t mask, voidptr_t base, voidptr_t end);
        voidptr_t    pattern_scan(process_t process, bytearray_t pattern, string_t mask, voidptr_t base, size_t size);
    }

    namespace in
    {
        pid_t        get_pid();
        process_t    get_process();
        string_t     get_process_name();
        moduleinfo_t get_module_info(string_t module_name);
        voidptr_t    pattern_scan(bytearray_t pattern, string_t mask, voidptr_t base, voidptr_t end);
        voidptr_t    pattern_scan(bytearray_t pattern, string_t mask, voidptr_t base, size_t size);
        void_t       read (voidptr_t src, voidptr_t dst,  size_t size);
        void_t       write(voidptr_t src, byteptr_t data, size_t size);
        void_t       set(voidptr_t src, byte_t byte, size_t size);
        int_t        protect(voidptr_t src, int_t protection, size_t size);
        voidptr_t    allocate(int_t protection, size_t size);
        int_t        detour_length(detour_int method);
        int_t        detour(voidptr_t src, voidptr_t dst, detour_int method, int_t size);
        voidptr_t    detour_trampoline(voidptr_t src, voidptr_t dst, detour_int method, int_t size, voidptr_t gateway_out = NULL);
        void_t       detour_restore(voidptr_t src);
    }
}

#endif //MEM_COMPATIBLE
#endif //MEM