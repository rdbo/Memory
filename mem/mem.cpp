//Made by rdbo
//https://github.com/rdbo/Memory

#include "mem.hpp"
#if MEM_COMPATIBLE

const mem::byte_t MEM_JMP[]        = ASM_GENERATE(_MEM_JMP);
const mem::byte_t MEM_JMP_RAX[]    = ASM_GENERATE(_MEM_JMP_RAX);
const mem::byte_t MEM_JMP_EAX[]    = ASM_GENERATE(_MEM_JMP_EAX);
const mem::byte_t MEM_CALL[]       = ASM_GENERATE(_MEM_CALL);
const mem::byte_t MEM_CALL_EAX[]   = ASM_GENERATE(_MEM_CALL_EAX);
const mem::byte_t MEM_CALL_RAX[]   = ASM_GENERATE(_MEM_CALL_RAX);
const mem::byte_t MEM_MOVABS_RAX[] = ASM_GENERATE(_MEM_MOVABS_RAX);
const mem::byte_t MEM_MOV_EAX[]    = ASM_GENERATE(_MEM_MOV_EAX);
const mem::byte_t MEM_PUSH[]       = ASM_GENERATE(_MEM_PUSH);
const mem::byte_t MEM_PUSH_RAX[]   = ASM_GENERATE(_MEM_PUSH_RAX);
const mem::byte_t MEM_PUSH_EAX[]   = ASM_GENERATE(_MEM_PUSH_EAX);
const mem::byte_t MEM_RET[]        = ASM_GENERATE(_MEM_RET);
const mem::byte_t MEM_BYTE[]       = ASM_GENERATE(_MEM_BYTE);
const mem::byte_t MEM_WORD[]       = ASM_GENERATE(_MEM_WORD);
const mem::byte_t MEM_DWORD[]      = ASM_GENERATE(_MEM_DWORD);
const mem::byte_t MEM_QWORD[]      = ASM_GENERATE(_MEM_QWORD);
#if defined(MEM_86)
const mem::byte_t MEM_MOV_REGAX[] = ASM_GENERATE(_MEM_MOV_EAX);
#elif defined(MEM_64)
const mem::byte_t MEM_MOV_REGAX[] = ASM_GENERATE(_MEM_MOVABS_RAX);
#endif

std::map<mem::voidptr_t, mem::bytearray_t> g_detour_restore_array;

//mem

mem::string_t mem::parsemask(string_t mask)
{
    for(size_t i = 0; i < mask.length(); i++)
        mask[i] = mask.at(i) == MEM_KNOWN_BYTE || mask.at(i) == (char)toupper(MEM_KNOWN_BYTE) ? MEM_KNOWN_BYTE : MEM_UNKNOWN_BYTE;

    return mask;
}

//mem::ex

mem::pid_t mem::ex::getpid(string_t process_name)
{
	pid_t pid = (pid_t)MEM_BAD_RETURN;
	DIR* pdir = opendir("/proc");
	if (!pdir)
		return pid;

	struct dirent* pdirent;
	while (pid < 0 && (pdirent = readdir(pdir)))
	{
		int id = atoi(pdirent->d_name);
		if (id > 0)
		{
			string_t cmdpath = string_t("/proc/") + pdirent->d_name + "/cmdline";
			std::ifstream cmdfile(cmdpath.c_str());
			string_t cmdline;
			getline(cmdfile, cmdline);
			size_t pos = cmdline.find('\0');
			if (!cmdline.empty())
			{
				if (pos != string_t::npos)
					cmdline = cmdline.substr(0, pos);
				pos = cmdline.rfind('/');
				if (pos != string_t::npos)
					cmdline = cmdline.substr(pos + 1);
				if (process_name.c_str() == cmdline.c_str())
					pid = id;
			}
		}
	}
	closedir(pdir);
	return pid;
}

mem::moduleinfo_t mem::ex::getmoduleinfo(pid_t pid, string_t module_name)
{
    moduleinfo_t modinfo{};
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    char path_buffer[64];
    snprintf(path_buffer, sizeof(path_buffer), "/proc/%i/maps", pid);
    std::ifstream file(path_buffer, std::ios::binary);
    if(!file.is_open()) return modinfo;
    std::stringstream ss;
    ss << file.rdbuf();
    std::size_t base_address_pos = ss.str().rfind('\n', ss.str().find(module_name.c_str(), 0)) + 1;
    std:size_t base_address_end = ss.str().find('-', base_address_pos);
    std::string base_address_str = ss.str().substr(base_address_pos, base_address_end - base_address_pos);

    std::size_t end_address_pos = ss.str().rfind('\n', ss.str().rfind(module_name.c_str()));
    end_address_pos = ss.str().find('-', end_address_pos) + 1;
    std::size_t end_address_end = ss.str().find(' ', end_address_pos);
    std::string end_address_str = ss.str().substr(end_address_pos, end_address_end - end_address_pos);

#   if defined(MEM_86)
    mem::uintptr_t base_address = strtoul(base_address_str.c_str(), NULL, 16);
    mem::uintptr_t end_address = strtoul(end_address_str.c_str(), NULL, 16);
#   elif defined(MEM_64)
    mem::uintptr_t base_address = strtoull(base_address_str.c_str(), NULL, 16);
    mem::uintptr_t end_address = strtoull(end_address_str.c_str(), NULL, 16);
#   endif

    modinfo.name = module_name;
    modinfo.base = base_address;
    modinfo.end = end_address;
    modinfo.size = modinfo.end - modinfo.base;
#   endif

    return modinfo;
}

mem::int_t mem::ex::read(pid_t pid, voidptr_t src, voidptr_t dst, size_t size)
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    struct iovec iosrc;
	struct iovec iodst;
	iodst.iov_base = dst;
	iodst.iov_len = size;
	iosrc.iov_base = src;
	iosrc.iov_len = size;
	return process_vm_readv(pid, &iodst, 1, &iosrc, 1, 0);
#   endif
    return MEM_BAD_RETURN;
}

mem::int_t mem::ex::write(pid_t pid, voidptr_t src, byteptr_t data, size_t size)
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    struct iovec iosrc;
	struct iovec iodst;
	iosrc.iov_base = data;
	iosrc.iov_len = size;
	iodst.iov_base = src;
	iodst.iov_len = size;
	return process_vm_writev(pid, &iosrc, 1, &iodst, 1, 0);
#   endif
    return MEM_BAD_RETURN;
}

mem::int_t mem::ex::set(pid_t pid, voidptr_t src, byte_t byte, size_t size)
{
    byte_t data[size];
    mem::in::set(data, byte, size);
    return write(pid, src, data, size);
}

mem::voidptr_t mem::ex::patternscan(pid_t pid, string_t pattern, string_t mask, voidptr_t base, voidptr_t end)
{
    mask = parsemask(mask);
	size_t scan_size = (uintptr_t)end - (uintptr_t)base;
    if(mask.length() != pattern.length())
    
	for (size_t i = 0; i < scan_size; i++)
	{
		bool found = true;
        byte_t pbyte;
		for (size_t j = 0; j < mask.length(); j++)
		{
            read(pid, (voidptr_t)((uintptr_t)base + i + j), &pbyte, 1);
			found &= mask[j] == MEM_UNKNOWN_BYTE || pattern[j] == pbyte;
		}

		if (found) return (voidptr_t)((uintptr_t)base + i);
	}

	return (mem::voidptr_t)MEM_BAD_RETURN;
}

mem::voidptr_t mem::ex::patternscan(pid_t pid, string_t pattern, string_t mask, voidptr_t base, size_t size)
{
    return patternscan(pid, pattern, mask, base, (voidptr_t)((uintptr_t)base + size));
}

//mem::in

mem::pid_t mem::in::getpid()
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    return (pid_t)::getpid();
#   endif
    return (pid_t)MEM_BAD_RETURN;
}

mem::moduleinfo_t mem::in::getmoduleinfo(string_t module_name)
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    return mem::ex::getmoduleinfo(mem::in::getpid(), module_name);
#   endif
}

mem::void_t mem::in::read (voidptr_t src, voidptr_t dst,  size_t size)
{
    memcpy(dst, src, size);
}

mem::void_t mem::in::write(voidptr_t src, byteptr_t data, size_t size)
{
    memcpy(src, data, size);
}

mem::void_t mem::in::set(voidptr_t src, byte_t byte, size_t size)
{
    memset(src, byte, size);
}

mem::int_t mem::in::protect(voidptr_t src, int_t protection, size_t size)
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    long pagesize = sysconf(_SC_PAGE_SIZE);
	uintptr_t src_page = (uintptr_t)src - ((uintptr_t)src % pagesize);
	return mprotect((voidptr_t)src_page, size, protection);
#   endif
    return (int_t)MEM_BAD_RETURN;
}

mem::voidptr_t mem::in::allocate(int_t protection, size_t size)
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    return mmap(NULL, size, protection, MAP_ANON | MAP_PRIVATE, -1, 0);
#   endif
    return (voidptr_t)MEM_BAD_RETURN;
}

mem::int_t mem::in::detour_length(detour_int method)
{
    switch(method)
    {
        case detour_int::method0: return CALC_ASM_LENGTH(_MEM_DETOUR_METHOD0);
        case detour_int::method1: return CALC_ASM_LENGTH(_MEM_DETOUR_METHOD1);
        case detour_int::method2: return CALC_ASM_LENGTH(_MEM_DETOUR_METHOD2);
        case detour_int::method3: return CALC_ASM_LENGTH(_MEM_DETOUR_METHOD3);
        case detour_int::method4: return CALC_ASM_LENGTH(_MEM_DETOUR_METHOD4);
        case detour_int::method5: return CALC_ASM_LENGTH(_MEM_DETOUR_METHOD5);
    }

    return (mem::int_t)MEM_BAD_RETURN;
}

mem::int_t mem::in::detour(voidptr_t src, voidptr_t dst, detour_int method, int_t size)
{
    int_t detour_size = detour_length(method);
    #if defined(MEM_WIN)
    #elif defined(MEM_LINUX)
    int_t protection = PROT_EXEC | PROT_READ | PROT_WRITE;
    #endif
    if(detour_size == MEM_BAD_RETURN || size < detour_size || protect(src, protection, size) == MEM_BAD_RETURN) return (mem::int_t)MEM_BAD_RETURN;

    byte_t* stolen_bytes = new byte_t[size];
    write(stolen_bytes, (byteptr_t)src, size);
    g_detour_restore_array.insert(std::pair<voidptr_t, bytearray_t>(src, bytearray_t((char*)stolen_bytes)));

    switch(method)
    {
        case detour_int::method0:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD0);
            *(uintptr_t*)((uintptr_t)detour_buffer + sizeof(MEM_MOV_REGAX)) = (uintptr_t)dst;
            write(src, detour_buffer, sizeof(detour_buffer));
            break;
        }

        case detour_int::method1:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD1);
            *(dword_t*)((uintptr_t)detour_buffer + sizeof(MEM_JMP)) = (dword_t)((uintptr_t)dst - (uintptr_t)src - detour_size);
            write(src, detour_buffer, sizeof(detour_buffer));
            break;
        }

        case detour_int::method2:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD2);
            *(uintptr_t*)((uintptr_t)detour_buffer + sizeof(MEM_MOV_REGAX)) = (uintptr_t)dst;
            write(src, detour_buffer, sizeof(detour_buffer));
            break;
        }

        case detour_int::method3:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD3);
            *(dword_t*)((uintptr_t)detour_buffer + sizeof(MEM_PUSH)) = (dword_t)((uintptr_t)dst - (uintptr_t)src - detour_size);
            write(src, detour_buffer, sizeof(detour_buffer));
            break;
        }

        case detour_int::method4:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD4);
            *(uintptr_t*)((uintptr_t)detour_buffer + sizeof(MEM_MOV_REGAX)) = (uintptr_t)dst;
            write(src, detour_buffer, sizeof(detour_buffer));
            break;
        }

        case detour_int::method5:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD5);
            *(dword_t*)((uintptr_t)detour_buffer + sizeof(MEM_CALL)) = (dword_t)((uintptr_t)dst - (uintptr_t)src - detour_size);
            write(src, detour_buffer, sizeof(detour_buffer));
            break;
        }

        default:
        {
            return (mem::int_t)MEM_BAD_RETURN;
            break;
        }
    }

    return !(MEM_BAD_RETURN);
}

mem::voidptr_t mem::in::detour_trampoline(voidptr_t src, voidptr_t dst, detour_int method, int_t size, voidptr_t gateway_out)
{
    int_t detour_size = detour_length(method);
    #if defined(MEM_WIN)
    #elif defined(MEM_LINUX)
    int_t protection = PROT_EXEC | PROT_READ | PROT_WRITE;
    #endif
    if(detour_size == MEM_BAD_RETURN || size < detour_size || protect(src, protection, size) == MEM_BAD_RETURN) return (voidptr_t)MEM_BAD_RETURN;

    byte_t gateway_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD0);
    *(uintptr_t*)((uintptr_t)gateway_buffer + sizeof(MEM_MOV_REGAX)) = (uintptr_t)((uintptr_t)src + size);
    size_t gateway_size = size + sizeof(gateway_buffer);
    voidptr_t gateway = allocate(gateway_size, protection);
    if(!gateway || gateway == (voidptr_t)-1 || gateway == (voidptr_t)MEM_BAD_RETURN) return (voidptr_t)MEM_BAD_RETURN;
    set(gateway, 0x0, gateway_size);
    write(gateway, (byteptr_t)src, size);
    write((voidptr_t)((uintptr_t)gateway + size), gateway_buffer, sizeof(gateway_buffer));

    #if defined(MEM_WIN)
    #elif defined(MEM_LINUX)
    protection = PROT_EXEC | PROT_READ;
    #endif

    protect(gateway, gateway_size, protection);
    detour(src, dst, method, size);
    return gateway;
}

mem::void_t mem::in::detour_restore(voidptr_t src)
{
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    int protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#   endif

    size_t size = g_detour_restore_array[src].length();
    protect(src, protection, size);
    write(src, (byteptr_t)g_detour_restore_array[src].data(), size);
}

mem::voidptr_t mem::in::patternscan(string_t pattern, string_t mask, voidptr_t base, voidptr_t end)
{
    mask = parsemask(mask);
	size_t scan_size = (uintptr_t)end - (uintptr_t)base;
    if(mask.length() != pattern.length())
    
	for (size_t i = 0; i < scan_size; i++)
	{
		bool found = true;
		for (size_t j = 0; j < mask.length(); j++)
		{
			found &= mask[j] == MEM_UNKNOWN_BYTE || pattern[j] == *(byte_t*)((uintptr_t)base + i + j);
		}

		if (found) return (voidptr_t)((uintptr_t)base + i);
	}

	return (mem::voidptr_t)MEM_BAD_RETURN;
}

mem::voidptr_t mem::in::patternscan(string_t pattern, string_t mask, voidptr_t base, size_t size)
{
    return patternscan(pattern, mask, base, (voidptr_t)((uintptr_t)base + size));
}

#endif //MEM_COMPATIBLE