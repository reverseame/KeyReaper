// Compilar con: cl /EHsc /std:c++17 .\cifrar3.cpp Advapi32.lib

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <locale>
#include <codecvt>
#pragma comment(lib, "advapi32.lib") // crypto api

#include "../cryptoapi.h"
using namespace key_scanner;

using namespace std;

namespace fs = filesystem;

#define AES_KEY_SIZE 16
#define IN_CHUNK_SIZE (AES_KEY_SIZE * 10) // a buffer must be a multiple of the key size
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 2) // an output buffer (for encryption) must be twice as big

#include <tlhelp32.h>
int PrintHeapInformation() {
  printf("Getting heap\n");

  DWORD pid = GetCurrentProcessId();
  printf("Self PID: %u\n", pid);

  HEAPLIST32 hl;
  HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
  hl.dwSize = sizeof(HEAPLIST32);

  if ( hHeapSnap == INVALID_HANDLE_VALUE ) {
    printf ("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
    return -1;
  }

  int func_result = 0;
  if( Heap32ListFirst(hHeapSnap, &hl)) {
    do {
      HEAPENTRY32 he;
      ZeroMemory(&he, sizeof(HEAPENTRY32));
      he.dwSize = sizeof(HEAPENTRY32);

      if( Heap32First(&he, pid, hl.th32HeapID )) {
        printf( "\nHeap ID: %zd\n", hl.th32HeapID );
        size_t total_size = 0;
        do {
          total_size += he.dwBlockSize;
          he.dwSize = sizeof(HEAPENTRY32);
        } while( Heap32Next(&he) );
        printf("Size of heap: %zu\n", total_size);
      }
      hl.dwSize = sizeof(HEAPLIST32);
    } while (Heap32ListNext( hHeapSnap, &hl ));
  
  } else { 
    printf ("Cannot list first heap (%d)\n", GetLastError());
  }
   
  CloseHandle(hHeapSnap);
  printf("Self PID: %u\n", pid);
  return func_result;
}

vector<string> retrieveTextFiles(const wstring& folderPath) {
    vector<string> fileNames;
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".txt") {
            fileNames.push_back(entry.path().filename().string());
        }
    }
    return fileNames;
}

vector<string> retrieveEncodedFiles(const string& folderPath) {
    vector<string> fileNames;
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".enc") {
            fileNames.push_back(entry.path().filename().string());
        }
    }
    return fileNames;
}

void PrintKeyData(HCRYPTKEY hKey) {
    uintptr_t* ptr = (uintptr_t*) hKey;
    cryptoapi::HCRYPTKEY* hCryptKey = (cryptoapi::HCRYPTKEY*) hKey;

    printf("HCRYPTKEY:      %p -> %p\n", hCryptKey, ptr);
    printf("CPGenKey:       %p   [%p]\n", hCryptKey->CPGenKey, &(hCryptKey->CPGenKey));
    printf("CPDeriveKey:    %p   [%p]\n", hCryptKey->CPDeriveKey, &(hCryptKey->CPDeriveKey));
    printf("CPDestroyKey:   %p   [%p]\n", hCryptKey->CPDestroyKey, &(hCryptKey->CPDestroyKey));
    printf("CPSetKeyParam:  %p   [%p]\n", hCryptKey->CPSetKeyParam, &(hCryptKey->CPSetKeyParam));
    printf("CPGetKeyParam:  %p   [%p]\n", hCryptKey->CPGetKeyParam, &(hCryptKey->CPGetKeyParam));
    printf("CPExportKey:    %p   [%p]\n", hCryptKey->CPExportKey, &(hCryptKey->CPExportKey));
    printf("CPImportKey:    %p   [%p]\n", hCryptKey->CPImportKey, &(hCryptKey->CPImportKey));
    printf("CPEncrypt:      %p   [%p]\n", hCryptKey->CPEncrypt, &(hCryptKey->CPEncrypt));
    printf("CPDecrypt:      %p   [%p]\n", hCryptKey->CPDecrypt, &(hCryptKey->CPDecrypt));
    printf("CPDuplicateKey: %p   [%p]\n", hCryptKey->CPDuplicateKey, &(hCryptKey->CPDuplicateKey));
    printf("hCryptProv:     %p   [%p]\n", (void*) hCryptKey->hCryptProv, &(hCryptKey->hCryptProv));
    printf("magic:          %p   [%p]\n", hCryptKey->magic, &(hCryptKey->magic));

    UINT_PTR magic_xor = (UINT_PTR) hCryptKey->magic;
    magic_xor = magic_xor ^ MAGIC_CONSTANT;
    cryptoapi::magic_s* ms = (cryptoapi::magic_s*) magic_xor;
    printf("magic xor:      %p -> %p\n", ms, ms->key_data);
    cryptoapi::key_data_s* key_data = (cryptoapi::key_data_s*) ms->key_data;

    printf("\nKEY STRUCTURE [@ %p]\n", (void*) key_data);
    printf("Unknown ptr:    %p\n", key_data->unknown);
    printf("Algorithm:      %08X\n", key_data->alg);
    printf("Flags:          %08X\n", key_data->flags);
    printf("Key size:       %08X\n", key_data->key_size);
    printf("Key ptr:        %p\n", key_data->key_bytes);

    char* key_bytes = (char*) key_data->key_bytes;
    printf("\nKEY [@ %p]\n", key_bytes);
    for (int i = 0; i < 16; i++) {
        
        printf("%02x ",  (*(key_bytes+i)) & 255);
    }; printf("\n");
}

//params: <path> <is decrypt mode> <key>
int main(int argc, char* argv[]) {

    wstring default_path = L"C:\\TEST\\";
    wstring path = default_path;

    const char *alternate_key = "password";
    wchar_t default_key[] = L"clave";
    wchar_t *key_str = default_key;

    //BOOL isDecrypt = FALSE;
    //wstring decrypt = argv[2];
    printf("Encrypt mode\n");
    printf("Self PID: %u\n", GetCurrentProcessId());
    printf("Press a key to start...");
    getchar();

    const size_t alt_len = strlen(alternate_key);
    const size_t len = lstrlenW(key_str);
    const size_t alt_size = alt_len * sizeof(alternate_key[0]);
    const size_t key_size = len * sizeof(key_str[0]); // size in bytes

    if (alt_size > UINT_MAX) {
        printf("Integer overflow when obtaining alt_size. Data is too big?\n"); 
        return -1;
    }
    const DWORD alt_size_dw = (DWORD) alt_size;

    printf("Key: %s\n", alternate_key);
    printf("Key len: %zx, %zd\n", alt_len, alt_len);
    printf("Key size: %zx | %zd\n", key_size, key_size);
    std::wcout << "Input path: " << path << endl;
    printf("----\n");

    DWORD dwStatus = 0;
    BOOL bResult = FALSE;

    // Get the cryptographic context. Necessary for most of the operations of CryptoAPI
    wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    LPCWSTR szContainer = NULL; // name of the vault/container, null when CRYPT_VERIFYCONTEXT;
    DWORD dwProvType = PROV_RSA_AES; // provider type
    DWORD dwFlags = CRYPT_VERIFYCONTEXT; // [in] config flags
    HCRYPTPROV phProv; // [out]
    if (!CryptAcquireContextW(&phProv, szContainer, info, dwProvType, dwFlags)) {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %x\n", dwStatus);
        CryptReleaseContext(phProv, 0);
        system("pause");
        return dwStatus;
    }

    // create a hash object from the CSP (cryptographic service provider)
    HCRYPTHASH hHash;
    if (!CryptCreateHash(phProv, CALG_SHA_256, 0, 0, &hHash)) {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %x\n", dwStatus);
        CryptReleaseContext(phProv, 0);
        system("pause");
        return dwStatus;
    }

    // hashes the key (for greater data entropy) and stores it in the hash object
    if (!CryptHashData(hHash, (BYTE*)alternate_key, alt_size_dw, 0)) {
        DWORD err = GetLastError();
        printf("CryptHashData Failed : %#x\n", err);
        system("pause");
        return (-1);
    }
    printf("[+] CryptHashData Success\n");

    // creates a key suitable for AES-128
    HCRYPTKEY hKey;
    if (!CryptDeriveKey(phProv, CALG_AES_128, hHash, 0, &hKey)) {
        dwStatus = GetLastError();
        printf("CryptDeriveKey failed: %x\n", dwStatus);
        CryptReleaseContext(phProv, 0);
        system("pause");
        return dwStatus;
    }

    printf("[+] CryptDeriveKey Success\n");
    
    // PRINTING ALL STRUCTURE DATA (pointers)
    PrintKeyData(hKey);

    PrintHeapInformation();
    printf("ENCRYPTING...\n");

    // Iterate over input folder
    vector<string> textFiles = retrieveTextFiles(path);
    for (const string& filename : textFiles) {
        
        wstring wFilename(filename.begin(), filename.end()); // Convertir el nombre de archivo a wstring
        wFilename = path + wFilename; // Pasar el path
        const wchar_t* input = wFilename.c_str(); // Variable const wchar_t* para el nombre de archivo de entrada
        wstring wOutputFilename = wFilename; // Crear una copia de wFilename para el nombre de archivo de salida
        wOutputFilename += L".enc"; // Agregar la extensión ".dec" al nombre de archivo de salida

        const wchar_t* output = wOutputFilename.c_str(); // Variable const wchar_t* para el nombre de archivo de salida
        
        // Input file handle
        HANDLE hInpFile = CreateFileW(input, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hInpFile == INVALID_HANDLE_VALUE) {
            printf("Cannot open input file!\n");
            system("pause");
            return (-1);
        }

        // Output file handle
        HANDLE hOutFile = CreateFileW(output, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutFile == INVALID_HANDLE_VALUE) {
            printf("Cannot open output file!\n");
            system("pause");
            return (-1);
        }

        // Buffered read/write
        const size_t chunk_size = OUT_CHUNK_SIZE; // chunk size 
        BYTE *chunk = new BYTE[chunk_size]; // dynamic byte array, as 
        DWORD out_len = 0;
        BOOL isFinal = FALSE;
        DWORD readTotalSize = 0;
        DWORD inputSize = GetFileSize(hInpFile, NULL);

        while (bResult = ReadFile(hInpFile, chunk, IN_CHUNK_SIZE, &out_len, NULL)) {
            if (out_len == 0) {
                break;
            }

            // last chunk (needed by the CryptEncrypt funciton, probably because of padding)
            readTotalSize += out_len;
            if (readTotalSize >= inputSize) {
                isFinal = TRUE;
                //printf("Final chunk set, len: %d = %x\n", out_len, out_len);
            }

            if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
                printf("[-] CryptEncrypt failed: %x\n", GetLastError());
                break;
            }
            
            DWORD written = 0;
            if (!WriteFile(hOutFile, chunk, out_len, &written, NULL)) {
                printf("writing failed!\n");
                break;
            }
            memset(chunk, 0, chunk_size);
        }
        delete[]chunk; chunk = NULL;
        CloseHandle(hInpFile);
        CloseHandle(hOutFile);
        Sleep(1000);
    }

    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(phProv, 0);

    return 0;
}
