#pragma once
#include "defines.h"

//Any
#include <iostream>
#include <fstream>
#include <map>

//Windows
#if defined(WIN)
#include <iostream>
#include <vector>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#endif

//Linux

#if defined(LINUX)
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <vector>
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