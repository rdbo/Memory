# Memory
Memory Management on Windows/Linux  
https://github.com/rdbo/Memory  

# Usage
Just copy the "mem" folder to your project, then include "mem/mem.hpp" and make sure to compile "mem/mem.cpp".  
Check "docs/documentation.txt" for more guidance  

# LICENSE
Read LICENSE  

# Overview
```
mem::ex::get_pid
mem::ex::get_process
mem::ex::get_process_name
mem::ex::get_module_info
mem::ex::is_process_running
mem::ex::read
mem::ex::write
mem::ex::set
mem::ex::scan
mem::ex::protect
mem::ex::allocate
mem::ex::pattern_scan
mem::ex::load_library

mem::in::get_pid
mem::in::get_process
mem::in::get_process_name
mem::in::get_module_info
mem::in::read
mem::in::write
mem::in::set
mem::in::scan
mem::in::protect
mem::in::allocate
mem::in::detour
mem::in::detour_length
mem::in::detour_trampoline
mem::in::detour_restore
mem::in::pattern_scan
mem::in::load_library
```

# TODO
```
Add support for allocating and protecting memory externally on Linux
Add support for loading libraries externally on Linux
Clean up code
Add a simple documentation
Add some examples
```
