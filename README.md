# Memory
Memory Management on Windows/Linux
# How to use it?
```
To compile on Linux, just run "compile.sh" on a terminal.
Check out the examples folder for assistance
You can use mem.h with either mem.cpp or mem.lib (Windows) / mem.a (Linux) to compile your projects
```
# Overview
## WINDOWS ##
```
Memory::EnumWindowsCallback
Memory::ParseMask

Memory::Ex::GetProcessIdByName
Memory::Ex::GetProcessIdByWindow
Memory::Ex::GetProcessIdByHandle
Memory::Ex::GetWindowHandle
Memory::Ex::GetModuleAddress
Memory::Ex::GetModuleList
Memory::Ex::IsModuleLoaded
Memory::Ex::GetPointer
Memory::Ex::WriteBuffer
Memory::Ex::ReadBuffer
Memory::Ex::GetModuleInfo
Memory::Ex::PatternScan
Memory::Ex::PatternScanModule

Memory::Ex::Nt::GetProcessHandle
Memory::Ex::Nt::GetProcessID
Memory::Ex::Nt::OpenProcessHandle
Memory::Ex::Nt::CloseProcessHandle
Memory::Ex::Nt::WriteBuffer
Memory::Ex::Nt::ReadBuffer

Memory::Ex::Zw::GetProcessHandle
Memory::Ex::Zw::GetProcessID
Memory::Ex::Zw::OpenProcessHandle
Memory::Ex::Zw::CloseProcessHandle
Memory::Ex::Zw::WriteBuffer
Memory::Ex::Zw::ReadBuffer

Memory::Ex::Injection::DLL::LoadLib

Memory::In::ZeroMem
Memory::In::IsBadPointer
Memory::In::GetCurrentProcessID
Memory::In::GetCurrentProcessHandle
Memory::In::GetCurrentWindowHandle
Memory::In::GetModuleAddress
Memory::In::GetPointer
Memory::In::WriteBuffer
Memory::In::ReadBuffer
Memory::In::GetModuleInfo
Memory::In::PatternScan
Memory::In::PatternScanModule
Memory::In::Read
Memory::In::Write

Memory::In::Hook::Restore
Memory::In::Hook::Detour
Memory::In::Hook::TrampolineHook
```
## LINUX ##
```
Memory::Ex::GetProcessIdByName
Memory::Ex::ReadBuffer
Memory::Ex::WriteBuffer
Memory::Ex::VmReadBuffer
Memory::Ex::VmWriteBuffer
Memory::Ex::PtraceReadBuffer
Memory::Ex::PtraceWriteBuffer
Memory::Ex::IsProcessRunning

Memory::In::ZeroMem
Memory::In::IsBadPointer
Memory::In::GetCurrentProcessID
Memory::In::ReadBuffer
Memory::In::WriteBuffer
Memory::In::Read
Memory::In::Write

Memory::In::Hook::Restore
Memory::In::Hook::Detour
Memory::In::Hook::TrampolineHook
```
