//## Include

#pragma once
#ifndef MEMORY
#include "defs.h"

//# Includes

//Any
#include <iostream>
#include <fstream>
#include <map>
#include <vector>

//Windows
#if defined(MEM_WIN)
#include <iostream>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

//Linux

#elif defined(MEM_LINUX)
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#endif

#endif //MEMORY