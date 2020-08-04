#include "../Memory/mem/mem.hpp"
#define PROCESS_NAME MEM_STR("main")

bool test_pid(mem::string_t process_name, mem::pid_t& pid)
{
    mem::pid_t pid_in = mem::in::get_pid();
    mem::pid_t pid_ex = mem::ex::get_pid(process_name);
    pid = pid_in;

    std::cout << "PID (in):  " << pid_in << std::endl;
    std::cout << "PID (ex):  " << pid_ex << std::endl;

    return pid_in != (mem::pid_t)MEM_BAD_RETURN && pid_in == pid_ex;
}

bool test_process_name(mem::pid_t pid, mem::string_t& process_name)
{
    mem::string_t process_name_in = mem::in::get_process_name();
    mem::string_t process_name_ex = mem::ex::get_process_name(pid);
    process_name = process_name_in;

    std::cout << "Process Name (in): " << process_name_in << std::endl;
    std::cout << "Process Name (ex): " << process_name_ex << std::endl;

    return (
        process_name_in == process_name_ex && 
        process_name_in != ""
    );
}

bool test_process(mem::string_t process_name, mem::process_t& process)
{
    mem::process_t process_in = mem::in::get_process();
    mem::process_t process_ex = mem::ex::get_process(process_name);
    process = process_in;

    std::cout << "Process ID (in): " << process_in.pid << std::endl;
    std::cout << "Process ID (ex): " << process_ex.pid << std::endl;
    std::cout << "Process Name (in): " << process_in.name << std::endl;
    std::cout << "Process Name (ex): " << process_ex.name << std::endl;

    return (
        process_in.is_valid() &&
        process_in == process_ex
    );
}

bool function(bool ret)
{
    asm(
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
    );

    std::cout << "the return is: " << ret << std::endl;
    return ret;
}

typedef bool(* function_t)(bool ret);
function_t o_function;

bool hk_function(bool ret)
{
    std::cout << "the old ret was: " << ret << std::endl;
    ret = true;
    std::cout << "ret set to true" << std::endl;
    return o_function(ret);
}

bool test_hook()
{
    mem::detour_int method = mem::detour_int::method0;
    o_function = (function_t)mem::in::detour_trampoline((mem::voidptr_t)&function, (mem::voidptr_t)&hk_function, mem::in::detour_length(method));
    bool ret = function(false);
    return ret;
}

bool test_module(mem::process_t process)
{
    mem::string_t mod_name = mem::string_t("/" + process.name + "\n");
    mem::module_t mod_in = mem::in::get_module(mod_name);
    mem::module_t mod_ex = mem::ex::get_module(process, mod_name);

    std::cout << "Module Name (in):   " << mod_in.name << std::endl;
    std::cout << "Module Name (ex):   " << mod_ex.name << std::endl;
    std::cout << "Module Path (in):   " << mod_in.path << std::endl;
    std::cout << "Module Path (ex):   " << mod_ex.path << std::endl;
    std::cout << "Module Base (in):   " << mod_in.base << std::endl;
    std::cout << "Module Base (ex):   " << mod_ex.base << std::endl;
    std::cout << "Module Size (in):   " << std::hex << mod_in.size << std::endl;
    std::cout << "Module Size (ex):   " << std::hex << mod_ex.size << std::endl;
    std::cout << "Module End  (in):   " << mod_in.end << std::endl;
    std::cout << "Module End  (ex):   " << mod_ex.end << std::endl;
    std::cout << "Module Handle (in): " << mod_in.handle << std::endl;
    mod_ex.handle = mod_in.handle;

    return (
        mod_in.is_valid() &&
        mod_ex.is_valid() &&
        mod_in == mod_ex
    );
}

void separator()
{
    std::cout << "-------------------" << std::endl;
}

int main()
{
    mem::pid_t pid;
    mem::string_t process_name;
    mem::process_t process;

    std::cout << "test pid" << std::endl;
    bool btest_pid          = test_pid(PROCESS_NAME, pid);
    separator();

    std::cout << "test process name" << std::endl;
    bool btest_process_name = test_process_name(pid, process_name);
    separator();

    std::cout << "test process" << std::endl;
    bool btest_process      = test_process(process_name, process);
    separator();

    std::cout << "test module" << std::endl;
    bool btest_module       = test_module(process);
    separator();

    std::cout << "test hook" << std::endl;
    bool btest_hook         = test_hook();
    separator();

    std::cout << "<< Results >>" << std::endl;
    std::cout << "Test PID:          " << btest_pid << std::endl;
    std::cout << "Test Process Name: " << btest_process_name << std::endl;
    std::cout << "Test Process:      " << btest_process << std::endl;
    std::cout << "Test Module:       " << btest_module << std::endl;
    std::cout << "Test Hook:         " << btest_hook << std::endl;

    return 0;
}