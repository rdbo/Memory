#Compile for Linux
g++ -c -m32 ./mem/mem.cpp
ar rvs ./lib/x86/mem.a mem.o
rm mem.o
g++ -c -m64 ./mem/mem.cpp
ar rvs ./lib/x64/mem.a mem.o
rm mem.o