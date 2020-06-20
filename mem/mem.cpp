#include "mem.h"

#if defined(MEMORY)

#if defined(MEM_WIN)



#elif defined(MEM_LINUX)

//Memory
cstr_t Memory::ParseMask(cstr_t mask)
{
	size_t length = strlen(mask);
	for (size_t i = 0; i < length; i++)
	{
		if (mask[i] != KNOWN_BYTE)
		{
			if (mask[i] == KNOWN_BYTE_UPPER)
				mask[i] = KNOWN_BYTE;
			else
				mask[i] = UNKNOWN_BYTE;
		}
	}

	return mask;
}

//Memory::Ex
#if INCLUDE_EXTERNALS
#endif //INCLUDE_EXTERNALS

//Memory::In
#if INCLUDE_INTERNALS
void Memory::In::ZeroMem(ptr_t src, size_t size)
{
	memset(src, 0x0, size + 1);
}
//--------------------------------------------
int Memory::In::ProtectMemory(mem_t address, size_t size, int protection)
{
	long pagesize = sysconf(_SC_PAGE_SIZE);
	address = address - (address % pagesize);
	return mprotect((ptr_t)address, size, protection);
}
//--------------------------------------------
bool Memory::In::IsBadPointer(ptr_t pointer)
{
	int fh = open((const char*)pointer, 0, 0);
	int e = errno;

	if (fh == -1 && e != EFAULT)
	{
		close(fh);
		return false;
	}

	return true;
}
//--------------------------------------------
pid_t Memory::In::GetCurrentProcessID()
{
	return getpid();
}
//--------------------------------------------
bool Memory::In::ReadBuffer(mem_t address, ptr_t buffer, size_t size)
{
	memcpy((ptr_t)buffer, (ptr_t)address, size);
	return true;
}
//--------------------------------------------
bool Memory::In::WriteBuffer(mem_t address, ptr_t value, size_t size)
{
	memcpy((ptr_t)address, (ptr_t)value, size);
	return true;
}
//--------------------------------------------
mem_t Memory::In::PatternScan(mem_t baseAddr, mem_t endAddr, buffer_t pattern, cstr_t mask)
{
	mask = ParseMask(mask);
	size_t patternLength = strlen(mask);
	size_t scanSize = endAddr - baseAddr;
	ProtectMemory(baseAddr, scanSize, PROT_EXEC | PROT_READ | PROT_WRITE);
	for (size_t i = 0; i < scanSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			found &= mask[j] == UNKNOWN_BYTE || pattern[j] == *(byte_t*)(baseAddr + i + j);
		}

		if (found) return baseAddr + i;
	}

	return BAD_RETURN;
}

//Memory::In::Hook
std::map<mem_t, std::vector<byte_t>> restore_arr;

size_t Memory::In::Hook::GetHookSize(Method method)
{
    switch(method)
    {
#       if defined(MEM_X86)
        case Method::mJump0: return CALC_ASM_LENGTH(_MEM_MOV_EAX, _MEM_DWORD, _MEM_JMP_EAX); break;
        case Method::mJump1: return CALC_ASM_LENGTH(_MEM_JMP, _MEM_DWORD); break;
        case Method::mPush0: return CALC_ASM_LENGTH(_MEM_MOV_EAX, _MEM_DWORD, _MEM_PUSH_EAX, _MEM_JMP_EAX); break;
        case Method::mCall0: return CALC_ASM_LENGTH(_MEM_MOV_EAX, _MEM_DWORD, _MEM_CALL_EAX); break;
#       elif defined(MEM_X64)
        case Method::mJump0: return CALC_ASM_LENGTH(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_JMP_RAX); break;
        case Method::mJump1: return CALC_ASM_LENGTH(_MEM_JMP, _MEM_DWORD); break;
        case Method::mPush0: return CALC_ASM_LENGTH(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_PUSH_RAX, _MEM_RET); break;
        case Method::mCall0: return CALC_ASM_LENGTH(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_CALL_RAX); break;
#       endif
    }
    return BAD_RETURN;
}
//--------------------------------------------
bool Memory::In::Hook::Restore(mem_t address)
{
    return true;
}
//--------------------------------------------
bool Memory::In::Hook::Detour(buffer_t src, buffer_t dst, size_t size, Method method)
{
    size_t hook_size = GetHookSize(method);
    if(size < hook_size || hook_size == BAD_RETURN) return BAD_RETURN;
    if(ProtectMemory((mem_t)src, size, PROT_EXEC | PROT_READ | PROT_WRITE) != 0) return BAD_RETURN;
    switch(method)
    {
#   if defined(MEM_X86)
        case Method::mJump0:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_JMP_EAX);
            *(dword_t*)((mem_t)CodeCave + sizeof(MEM_MOV_EAX)) = (dword_t)dst;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        case Method::mJump1:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_JMP, _MEM_DWORD);
            *(dword_t*)((mem_t)CodeCave + sizeof(MEM_JMP)) = (mem_t)dst - (mem_t)src - hook_size;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        case Method::mPush0:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_PUSH_EAX, _MEM_RET);
            *(dword_t*)((mem_t)CodeCave + sizeof(MEM_MOV_EAX)) = (dword_t)dst;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        case Method::mCall0:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_CALL_RAX);
            *(dword_t*)((mem_t)CodeCave + sizeof(MEM_MOV_EAX)) = (dword_t)dst;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        default:
        return BAD_RETURN;
        break;
#   elif defined(MEM_X64)
        case Method::mJump0:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_JMP_RAX);
            *(qword_t*)((mem_t)CodeCave + sizeof(MEM_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        case Method::mJump1:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_JMP, _MEM_DWORD);
            *(dword_t*)((mem_t)CodeCave + sizeof(MEM_JMP)) = (mem_t)dst - (mem_t)src - hook_size;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        case Method::mPush0:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_PUSH_RAX, _MEM_RET);
            *(qword_t*)((mem_t)CodeCave + sizeof(MEM_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        case Method::mCall0:
        {
            byte_t CodeCave[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_CALL_RAX);
            *(qword_t*)((mem_t)CodeCave + sizeof(MEM_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, CodeCave, sizeof(CodeCave));
        }
        break;

        default:
        return BAD_RETURN;
        break;
#   endif
    }
    return true;
}
//--------------------------------------------
buffer_t Memory::In::Hook::TrampolineHook(buffer_t src, buffer_t dst, size_t size, Method method)
{
    size_t hook_size = GetHookSize(method);
    if(size < hook_size || hook_size == BAD_RETURN) return BAD_RETURN;

    //Gateway Code Cave
#   if defined(MEM_X86)
    byte_t GatewayCodeCave[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_JMP_EAX);
    *(dword_t*)((mem_t)GatewayCodeCave + sizeof(MEM_MOV_EAX)) = (dword_t)((mem_t)src + size);
#   elif defined(MEM_X64)
    byte_t GatewayCodeCave[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_JMP_RAX);
    *(qword_t*)((mem_t)GatewayCodeCave + sizeof(MEM_MOVABS_RAX)) = (qword_t)((mem_t)src + size);
#   endif

    //Allocate gateway
    size_t gateway_size = size + sizeof(GatewayCodeCave);
    buffer_t gateway = (buffer_t)mmap(NULL, gateway_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(!gateway) return BAD_RETURN;
    if(ProtectMemory((mem_t)src, size, PROT_EXEC | PROT_READ | PROT_WRITE) != 0) return BAD_RETURN;
    ZeroMem(gateway, sizeof(gateway));

    //Setup gateway
    memcpy(gateway, src, size);
    memcpy((void*)((mem_t)gateway + size), GatewayCodeCave, sizeof(GatewayCodeCave));
    ProtectMemory((mem_t)gateway, gateway_size, PROT_EXEC | PROT_READ);

    //Call Detour
    Detour(src, dst, size, method);

    return gateway;
}

#endif //INCLUDE_INTERNALS
#endif //Memory Declarations
#endif //MEMORY