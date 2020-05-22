#pragma once
#include "includes.h"

//Windows-specific types
#if defined(WIN)
typedef DWORD pid_t;
#endif

//Linux-specific types
#if defined(LINUX)
typedef char TCHAR;
#endif


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