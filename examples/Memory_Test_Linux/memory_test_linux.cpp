#ifndef linux
#define linux
#endif

#include "../../mem/mem.h"
#define PROCESS_NAME "memory_test_linux"
#define DEFAULT_VALUE 100
#define NEW_VALUE 250
#define MULT 2
#if defined(ARCH_X86)
#define HOOK_LENGTH 5
#elif defined(ARCH_X64)
#define HOOK_LENGTH 12
#endif

int buffer = DEFAULT_VALUE;
byte_t pattern[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
cstr_t mask = (cstr_t)"xxxxxxxxxxxxxxx";

void Separator()
{
	std::cout << "========================" << std::endl;
}

bool TestPID(pid_t& pid)
{
    pid = Memory::Ex::GetProcessIdByName(PROCESS_NAME);
    std::cout << "PID: " << pid << std::endl;
    Separator();
    return (bool)pid;
}

bool TestBuffer(pid_t pid)
{
    int read_buffer;
    Memory::Ex::ReadBuffer(pid, (mem_t)&buffer, &read_buffer, sizeof(read_buffer));
    Memory::Ex::WriteBuffer(pid, (mem_t)&buffer, new int(NEW_VALUE), sizeof(NEW_VALUE));

    int ptrace_read_buffer;
    Memory::Ex::Ptrace::ReadBuffer(pid, (mem_t)&buffer, &ptrace_read_buffer, sizeof(ptrace_read_buffer));
    Memory::Ex::Ptrace::WriteBuffer(pid, (mem_t)&buffer, new int(NEW_VALUE * MULT), sizeof(NEW_VALUE * MULT));

    int vm_read_buffer;
    Memory::Ex::VM::ReadBuffer(pid, (mem_t)&buffer, &vm_read_buffer, sizeof(vm_read_buffer));
    Memory::Ex::VM::WriteBuffer(pid, (mem_t)&buffer, new int(NEW_VALUE * MULT * MULT), sizeof(NEW_VALUE * MULT));

    std::cout << "Read Buffer: " << read_buffer << std::endl;
    std::cout << "Ptrace Read Buffer: " << ptrace_read_buffer << std::endl;
    std::cout << "Vm Read Buffer: " << vm_read_buffer << std::endl;;
    std::cout << "Buffer: " << buffer << std::endl;
    Separator();

    return read_buffer == DEFAULT_VALUE && ptrace_read_buffer == NEW_VALUE && vm_read_buffer == NEW_VALUE * MULT && buffer == NEW_VALUE * MULT * MULT;
}

bool TestScan(pid_t pid)
{
    mem_t moduleAddr = Memory::Ex::GetModuleAddress(pid, PROCESS_NAME);
    mem_t endAddr = moduleAddr + ((mem_t)pattern - moduleAddr) + sizeof(pattern) + 0x10;
    mem_t scan = Memory::Ex::PatternScan(pid, (mem_t)pattern - 0x10, (mem_t)pattern + sizeof(pattern) + 0x10, pattern, mask);
    mem_t modScan = Memory::Ex::PatternScan(pid, (mem_t)pattern - 0x10, endAddr, pattern, mask);
    std::cout << "Address: " << std::hex << (mem_t)pattern << std::endl;
    std::cout << "Module Address: " << moduleAddr << std::endl;
    std::cout << "End Address: " << endAddr << std::endl;
    std::cout << "Scan: " << std::hex << scan << std::endl;
    std::cout << "Module Scan: " << std::hex << modScan << std::endl;
    Separator();
    return scan && scan == modScan;
}

bool TestHook(bool check = false)
{
    Separator();
    return check;
}

typedef bool(*TestHook_t)(bool);
TestHook_t oTestHook;

bool hkTestHook(bool check)
{
    std::cout << "Hooked!" << std::endl;
    check = true;
    return oTestHook(check);
}

int main()
{
    pid_t pid;
    oTestHook = (TestHook_t)Memory::In::Hook::TrampolineHook((ptr_t)&TestHook, (ptr_t)&hkTestHook, HOOK_LENGTH);
    bool bTestPid = TestPID(pid);
    bool bTestBuffer = TestBuffer(pid);
    bool bTestScan = TestScan(pid);
    bool bTestHook = TestHook();
    std::cout << "[*] RESULTS" << std::endl;
    std::cout << "Test PID: " << bTestPid << std::endl;
    std::cout << "Test Buffer: " << bTestBuffer << std::endl;
    std::cout << "Test Scan: " << bTestScan << std::endl;
    std::cout << "Test Hook: " << bTestHook << std::endl;
}