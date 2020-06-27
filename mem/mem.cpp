#include "mem.hpp"
#if defined(MEMORY) && MEM_COMPATIBLE && MEM_INCLUDE

//Variables/Buffers

const byte_t MEM_JMP[]        = ASM_GENERATE(_MEM_JMP);
const byte_t MEM_JMP_RAX[]    = ASM_GENERATE(_MEM_JMP_RAX);
const byte_t MEM_JMP_EAX[]    = ASM_GENERATE(_MEM_JMP_EAX);
const byte_t MEM_CALL[]       = ASM_GENERATE(_MEM_CALL);
const byte_t MEM_CALL_EAX[]   = ASM_GENERATE(_MEM_CALL_EAX);
const byte_t MEM_CALL_RAX[]   = ASM_GENERATE(_MEM_CALL_RAX);
const byte_t MEM_MOVABS_RAX[] = ASM_GENERATE(_MEM_MOVABS_RAX);
const byte_t MEM_MOV_EAX[]    = ASM_GENERATE(_MEM_MOV_EAX);
const byte_t MEM_PUSH[]       = ASM_GENERATE(_MEM_PUSH);
const byte_t MEM_PUSH_RAX[]   = ASM_GENERATE(_MEM_PUSH_RAX);
const byte_t MEM_PUSH_EAX[]   = ASM_GENERATE(_MEM_PUSH_EAX);
const byte_t MEM_RET[]        = ASM_GENERATE(_MEM_RET);
const byte_t MEM_BYTE[]       = ASM_GENERATE(_MEM_BYTE);
const byte_t MEM_WORD[]       = ASM_GENERATE(_MEM_WORD);
const byte_t MEM_DWORD[]      = ASM_GENERATE(_MEM_DWORD);
const byte_t MEM_QWORD[]      = ASM_GENERATE(_MEM_QWORD);

std::map<addr_t, std::vector<byte_t>> g_DetourArray;

#if defined(MEM_WIN)
//Windows

#if MEM_INCLUDE_EXTERNALS
#endif //MEM_INCLUDE_EXTERNALS

#if MEM_INCLUDE_INTERNALS
#endif //MEM_INCLUDE_INTERNALS

#elif defined(MEM_LINUX)
//Linux

str_t Memory::ParseMask(str_t mask)
{
    size_t length = mask.length();
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
//--------------------
//Memory::Ex
#if MEM_INCLUDE_EXTERNALS
pid_t Memory::Ex::GetProcessIdByName(str_t processName)
{
    pid_t pid = (pid_t)BAD_RETURN;
	DIR* pdir = opendir("/proc");
	if (!pdir)
		return pid;

	struct dirent* pdirent;
	while (pid < 0 && (pdirent = readdir(pdir)))
	{
		int id = atoi(pdirent->d_name);
		if (id > 0)
		{
			str_t cmdpath = str_t("/proc/") + pdirent->d_name + "/cmdline";
			std::ifstream cmdfile(cmdpath.c_str());
			str_t cmdline;
			getline(cmdfile, cmdline);
			size_t pos = cmdline.find('\0');
			if (!cmdline.empty())
			{
				if (pos != str_t::npos)
					cmdline = cmdline.substr(0, pos);
				pos = cmdline.rfind('/');
				if (pos != str_t::npos)
					cmdline = cmdline.substr(pos + 1);
				if (processName == cmdline.c_str())
					pid = id;
			}
		}
	}
	closedir(pdir);
	return pid;
}


addr_t Memory::Ex::GetModuleAddress(pid_t pid, str_t moduleName)
{
    char path_buffer[DEFAULT_BUFFER_SIZE];
	char baseAddress[MAX_BUFFER_SIZE];
	snprintf(path_buffer, sizeof(path_buffer), "/proc/%i/maps", pid);
	int proc_maps = open(path_buffer, O_RDONLY);
	size_t size = lseek(proc_maps, 0, SEEK_END);
	char* file_buffer = new char[size + 1];
	if (size == 0 || !proc_maps || !file_buffer) return (addr_t)BAD_RETURN;
	memset(file_buffer, 0x0, size + 1);
	for (size_t i = 0; read(proc_maps, file_buffer + i, 1) > 0; i++);

	char* ptr = NULL;
	if (moduleName.c_str() != NULL && (ptr = strstr(file_buffer, moduleName.c_str())) == NULL)
		if ((ptr = strstr(file_buffer, moduleName.c_str())) == NULL) return (addr_t)BAD_RETURN;
		else if ((ptr = strstr(file_buffer, "r-xp")) == NULL) return (addr_t)BAD_RETURN;

	while (*ptr != '\n' && ptr >= file_buffer)
	{
		ptr--;
	}
	ptr++;

	for (int i = 0; *ptr != '-'; i++)
	{
		baseAddress[i] = *ptr;
		ptr++;
	}

	addr_t base = (addr_t)strtol(baseAddress, NULL, 16);
	close(proc_maps);
	free(file_buffer);

	return base;
}


int Memory::Ex::Read(pid_t pid, addr_t src, addr_t dst, size_t size)
{
    struct iovec iosrc;
	struct iovec iodst;
	iodst.iov_base = dst;
	iodst.iov_len = size;
	iosrc.iov_base = src;
	iosrc.iov_len = size;
	return process_vm_readv(pid, &iodst, 1, &iosrc, 1, 0);
}


int Memory::Ex::Write(pid_t pid, addr_t src, addr_t data, size_t size)
{
    struct iovec iosrc;
	struct iovec iodst;
	iosrc.iov_base = data;
	iosrc.iov_len = size;
	iodst.iov_base = src;
	iodst.iov_len = size;
	return process_vm_writev(pid, &iosrc, 1, &iodst, 1, 0);
}


addr_t Memory::Ex::PatternScan(pid_t pid, addr_t begin, addr_t end, buffer_t pattern, str_t mask)
{
    mask = ParseMask(mask);
	size_t patternLength = mask.length();
	size_t scanSize = (size_t)((mem_t)end - (mem_t)begin);
	for (size_t i = 0; i < scanSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			byte_t curByte;
			Read(pid, (addr_t)((mem_t)begin + i + j), &curByte, sizeof(curByte));
			found &= mask[j] == UNKNOWN_BYTE || pattern[j] == curByte;
		}

		if (found) return (addr_t)((mem_t)begin + i);
	}

	return (addr_t)BAD_RETURN;
}


bool Memory::Ex::IsProcessRunning(pid_t pid)
{
    char dirbuf[DEFAULT_BUFFER_SIZE];
	snprintf(dirbuf, sizeof(dirbuf), "/proc/%i", pid);
	struct stat status;
	stat(dirbuf, &status);
	return (status.st_mode & S_IFDIR) != 0;
}


#endif //MEM_INCLUDE_EXTERNALS
//--------------------
//Memory::In
#if MEM_INCLUDE_INTERNALS

pid_t Memory::In::GetProcessId()
{
    return getpid();
}


addr_t Memory::In::Allocate(size_t size, int protection)
{
    #if defined(MEM_WIN)
    #elif defined(MEM_LINUX)
    return mmap(NULL, size, protection, MAP_ANON | MAP_PRIVATE, -1, 0);
    #endif
    return (addr_t)BAD_RETURN;
}


int Memory::In::Protect(addr_t src, size_t size, int protection)
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    long pagesize = sysconf(_SC_PAGE_SIZE);
	src = (addr_t)((mem_t)src - ((mem_t)src % pagesize));
	return mprotect(src, size, protection);
#   endif
    return BAD_RETURN;
}


void Memory::In::Zero(addr_t src, size_t size)
{
    memset(src, 0x0, size);
}


bool Memory::In::IsBadPointer(addr_t src)
{
    int fh = open((const char*)src, 0, 0);
	int e = errno;

	if (fh == -1 && e != EFAULT)
	{
		close(fh);
		return false;
	}

	return true;
}


void Memory::In::Read(addr_t src, addr_t dst, size_t size)
{
    memcpy(dst, src, size);
}

void Memory::In::Write(addr_t src, addr_t data, size_t size)
{
    memcpy(src, data, size);
}


addr_t Memory::In::PatternScan(addr_t begin, addr_t end, buffer_t pattern, str_t mask)
{
    mask = ParseMask(mask);
	size_t patternLength = mask.length();
	size_t scanSize = (mem_t)end - (mem_t)begin;
	Protect(begin, scanSize, MEM_PROT_XRW);
	for (size_t i = 0; i < scanSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			found &= mask[j] == UNKNOWN_BYTE || pattern[j] == *(byte_t*)((mem_t)begin + i + j);
		}

		if (found) return (addr_t)((mem_t)begin + i);
	}

	return (addr_t)BAD_RETURN;
}


int Memory::In::DetourLength(DetourClass method)
{
    switch(method)
    {
#       if defined(MEM_86)
        case DetourClass::Method0: return CALC_ASM_LENGTH(_MEM_MOV_EAX, _MEM_DWORD, _MEM_JMP_EAX); break;
        case DetourClass::Method1: return CALC_ASM_LENGTH(_MEM_JMP, _MEM_DWORD); break;
        case DetourClass::Method2: return CALC_ASM_LENGTH(_MEM_MOV_EAX, _MEM_DWORD, _MEM_PUSH_EAX, _MEM_RET); break;
        case DetourClass::Method3: return CALC_ASM_LENGTH(_MEM_PUSH, _MEM_DWORD, _MEM_RET); break;
        case DetourClass::Method4: return CALC_ASM_LENGTH(_MEM_MOV_EAX, _MEM_DWORD, _MEM_CALL_EAX); break;
        case DetourClass::Method5: return CALC_ASM_LENGTH(_MEM_CALL, _MEM_DWORD); break;
#       elif defined(MEM_64)
        case DetourClass::Method0: return CALC_ASM_LENGTH(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_JMP_RAX); break;
        case DetourClass::Method1: return CALC_ASM_LENGTH(_MEM_JMP, _MEM_DWORD); break;
        case DetourClass::Method2: return CALC_ASM_LENGTH(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_PUSH_RAX, _MEM_RET); break;
        case DetourClass::Method3: return CALC_ASM_LENGTH(_MEM_PUSH, _MEM_DWORD, _MEM_RET); break;
        case DetourClass::Method4: return CALC_ASM_LENGTH(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_CALL_RAX); break;
        case DetourClass::Method5: return CALC_ASM_LENGTH(_MEM_CALL, _MEM_DWORD); break;
#       endif
    }

    return BAD_RETURN;
}

int Memory::In::DetourRestore(addr_t src)
{
    if (g_DetourArray.count(src) <= 0) return BAD_RETURN;
	Write(src, g_DetourArray.at(src).data(), g_DetourArray.at(src).size());
	return 0;
}


int Memory::In::Detour(addr_t src, addr_t dst, int size, DetourClass method)
{
    int detour_size = DetourLength(method);
    if(detour_size == BAD_RETURN || size < detour_size || Protect(src, size, MEM_PROT_XRW) != 0) return BAD_RETURN;

    std::vector<byte_t> stolen_bytes;
    stolen_bytes.reserve(size);

    for(int i = 0; i < size; i++)
        stolen_bytes.insert(stolen_bytes.begin() + i, reinterpret_cast<byte_t*>(src)[i]);
        
    g_DetourArray.insert(std::pair<addr_t, std::vector<byte_t>>(src, stolen_bytes));

    switch(method)
    {
#       if defined(MEM_86)
        case DetourClass::Method0:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_JMP_EAX);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_MOV_EAX)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method1:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_JMP, _MEM_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_JMP)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method2:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_PUSH_EAX, _MEM_RET);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_MOV_EAX)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method3:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_PUSH, _MEM_DWORD, _MEM_RET);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_PUSH)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method4:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_CALL_EAX);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_MOV_EAX)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method5:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_CALL, _MEM_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_CALL)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

#       elif defined(MEM_64)
        case DetourClass::Method0:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_JMP_RAX);
            *(qword_t*)((mem_t)detour_buffer + sizeof(MEM_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method1:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_JMP, _MEM_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_JMP)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method2:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_PUSH_RAX, _MEM_RET);
            *(qword_t*)((mem_t)detour_buffer + sizeof(MEM_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method3:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_PUSH, _MEM_DWORD, _MEM_RET);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_PUSH)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method4:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_CALL_RAX);
            *(qword_t*)((mem_t)detour_buffer + sizeof(MEM_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;

        case DetourClass::Method5:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_CALL, _MEM_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(MEM_CALL)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }break;
#       endif

        default:
        return BAD_RETURN;
        break;
    }
    return 0;
}


addr_t Memory::In::DetourTrampoline(addr_t src, addr_t dst, int size, DetourClass method, addr_t gateway_out)
{
    int detour_size = DetourLength(method);
    if(detour_size == BAD_RETURN || size < detour_size || Protect(src, size, MEM_PROT_XRW) != 0) return (addr_t)BAD_RETURN;

#   if defined(MEM_86)
    byte_t gateway_buffer[] = ASM_GENERATE(_MEM_MOV_EAX, _MEM_DWORD, _MEM_JMP_EAX);
    *(dword_t*)((mem_t)gateway_buffer + sizeof(MEM_MOV_EAX)) = (dword_t)((mem_t)src + size);
#   elif defined(MEM_64)
    byte_t gateway_buffer[] = ASM_GENERATE(_MEM_MOVABS_RAX, _MEM_QWORD, _MEM_JMP_RAX);
    *(qword_t*)((mem_t)gateway_buffer + sizeof(MEM_MOVABS_RAX)) = (qword_t)((mem_t)src + size);
#   endif

    size_t gateway_size = size + sizeof(gateway_buffer);
    addr_t gateway = Allocate(gateway_size, MEM_PROT_XRW);
    if(!gateway || gateway == (addr_t)-1 || gateway == (addr_t)BAD_RETURN) return (addr_t)BAD_RETURN;
    memset(gateway, 0x90, gateway_size);
    memcpy(gateway, src, size);
    memcpy((addr_t)((mem_t)gateway + size), gateway_buffer, sizeof(gateway_buffer));

    if(gateway_out != NULL)
    {
        Protect(gateway_out, gateway_size, MEM_PROT_XRW);
        memcpy(gateway_out, gateway, gateway_size);
    }

    Protect(gateway, gateway_size, MEM_PROT_X | MEM_PROT_R);
    Detour(src, dst, size, method);

    return gateway;   
}
#endif //MEM_INCLUDE_INTERNALS

#endif //MEMORY_CPP
#endif //MEMORY