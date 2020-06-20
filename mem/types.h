//## Types

#ifndef MEMORY
#include "defs.h"
#include "includes.h"

typedef unsigned char      byte_t;
typedef unsigned short     word_t;
typedef unsigned int       dword_t;
typedef unsigned long long qword_t;

typedef void*              ptr_t;
typedef byte_t*            buffer_t;

#if defined(MEM_X86)
typedef dword_t            mem_t;
#elif defined(MEM_X64)
typedef qword_t            mem_t;
#endif

#if defined(MEM_WIN)
typedef TCHAR char_t;
#elif defined(MEM_LINUX)
typedef char char_t;
#else
typedef char char_t;
#endif

typedef char*                     cstr_t;
typedef std::basic_string<char_t> str_t;
typedef std::vector<str_t>        vstr_t;

#endif