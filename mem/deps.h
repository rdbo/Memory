//## Dependencies
#include "defs.h"

//defs
#if defined(MEM_WIN)
typedef struct _UNICODE_STRING;
typedef _UNICODE_STRING UNICODE_STRING, * PUNICODE_STRING, ** PPUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES;
typedef _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID;
typedef _CLIENT_ID CLIENT_ID, *PCLIENT_ID;
typedef NTSTATUS(NTAPI* NtGetNextProcess_t)(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewProcessHandle);
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, const ptr_t Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* ZwGetNextProcess_t)(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewProcessHandle);
typedef NTSTATUS(NTAPI* ZwOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* ZwClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI* ZwReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* ZwWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, const ptr_t Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
#elif defined(MEM_LINUX)
#endif

//decls

#if defined(MEM_WIN)
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};
#elif defined(MEM_LINUX)
#endif