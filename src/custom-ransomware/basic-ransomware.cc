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

#include "cryptoapi.h"
#include "key.h"
#include "program_result.h"
using namespace key_scanner;

using namespace std;

namespace fs = filesystem;

#define AES_KEY_SIZE 16
#define IN_CHUNK_SIZE (AES_KEY_SIZE * 10) // a buffer must be a multiple of the key size
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 2) // an output buffer (for encryption) must be twice as big

// Header
void PrintKeyData(HCRYPTKEY hKey);

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

cryptoapi::key_data_s* GetKeyStruct(HCRYPTKEY key) {
    cryptoapi::HCRYPTKEY* hCryptKey = (cryptoapi::HCRYPTKEY*) key;
    UINT_PTR magic_xor = (UINT_PTR) hCryptKey->magic;
    magic_xor = magic_xor ^ MAGIC_CONSTANT;
    cryptoapi::magic_s* ms = (cryptoapi::magic_s*) magic_xor;
    return (cryptoapi::key_data_s*) ms->key_data;
}

void CheckAllBlockSizes(HCRYPTPROV prov) {
    SIZE_T biggest_block_len = 0;
    ALG_ID to_check_algs[] = {CALG_DES, CALG_RC2, CALG_3DES, CALG_3DES_112, CALG_DESX, CALG_AES_128, CALG_AES_192, CALG_AES_256, CALG_AES, CALG_SKIPJACK, CALG_TEK, CALG_CYLINK_MEK};
    HCRYPTKEY key;
    BOOL result;
    DWORD block_size;
    BYTE data[256];
    DWORD data_len;
    cryptoapi::key_data_s* key_data;

    for (ALG_ID alg : to_check_algs) {
        printf("Generating a key with ALG_ID: %04X\n", alg);
        result = CryptGenKey(prov, alg, 0, &key);
        if (result == 0) {
            printf(" [x] Error generating key. Error: %u\n", GetLastError());
            cout << "  \\Last error: " <<  error_handling::GetLastErrorAsString() << endl;
        
        } else {
            key_data = GetKeyStruct(key);
            // PrintKeyData(key);

            printf(" Shadow BLOCK len is %u\n", key_data->block_len);
            if (key_data->block_len != 0) {
                data_len = 256;
                result = CryptGetKeyParam(key, KP_IV, data, &data_len, 0);
                if (result == 0) printf(" [i] Seems that the ALG does not have an IV.\n");
                else printf(" [i] The ALG seems to be using an IV\n");

                data_len = sizeof(DWORD);
                result = CryptGetKeyParam(key, KP_BLOCKLEN, (BYTE*) &block_size, &data_len, 0);

                if (result == 0) printf(" [x] Error retrieving the block length\n");
                else printf("  * BLOCKLEN: %u\n", block_size);

            } else printf(" [i] Probably not using IV\n");
            
            CryptDestroyKey(key);
        } printf("\n");
    }
}

#include "program_result.h"
void TryExportKey(HCRYPTKEY key_handle) {

    // Get the key size
    DWORD blob_size = NULL;
    BOOL success = CryptExportKey(
        key_handle, NULL,
        PLAINTEXTKEYBLOB, 0,
        NULL, &blob_size
    );

    if (!success) {
        cout << "[x] Could not export the key: " << error_handling::GetLastErrorAsString() << endl;
        printf("CRYPT_EXPORTABLE: 0x%x\n", CRYPT_EXPORTABLE);
        return;
    } else {
        printf("Size recovered\n");
    }

    BYTE* buffer = (BYTE*) calloc(sizeof(BYTE), blob_size);

    if (buffer != NULL) {
        DWORD bytes_written = blob_size;
        success = CryptExportKey(
            key_handle, NULL,
            PLAINTEXTKEYBLOB, 0,
            buffer, &bytes_written
        );

        if (!success) {
            cout << "[x] Could not export the key: " << error_handling::GetLastErrorAsString() << endl;
            return;
        } else {
            printf("Key exported\n");

            printf(" KEY DATA:\n");
            for (unsigned int i = 0; i < bytes_written; i++) {
                printf("%02X ", buffer[i]);
            } printf("\n");
        }
        free(buffer);
    }
}

void PrintKeyParameters(HCRYPTKEY key_handle) {
    CrAPIAESKeyWrapper key_wrapper = CrAPIAESKeyWrapper(key_handle);

    printf("IV:            ");
    for (auto byte : key_wrapper.GetIV()) {
        printf(" %02X", byte);
    } printf("\n");

    printf("KP_PADDING:    ");
    for (auto byte : key_wrapper.GetPadding()) {
        printf(" %02X", byte);
    } printf("\n");

    printf("KP_MODE:       ");
    for (auto byte : key_wrapper.GetMode()) {
        printf(" %02X", byte);
    } printf("\n");
}

void GetAllBlockCipherParameters(HCRYPTKEY key) {
    BOOL result;

    const char* parameter_list_str[] = {"KP_ALGID", "KP_BLOCKLEN", "KP_CERTIFICATE", "KP_KEYLEN", "KP_SALT", "KP_PERMISSIONS", "KP_EFFECTIVE_KEYLEN", "KP_IV", "KP_PADDING", "KP_MODE", "KP_MODE_BITS"};
    DWORD parameter_list[] = {KP_ALGID, KP_BLOCKLEN, KP_CERTIFICATE, KP_KEYLEN, KP_SALT, KP_PERMISSIONS, KP_EFFECTIVE_KEYLEN, KP_IV, KP_PADDING, KP_MODE, KP_MODE_BITS};

    BYTE buffer[256];
    DWORD len = 256;

    for (unsigned int i = 0; i < size(parameter_list); i++) {
        ZeroMemory(buffer, 256); len = 256;
        printf("[%u] Getting %s\n", i, parameter_list_str[i]);
        result = CryptGetKeyParam(key, parameter_list[i], buffer, &len, 0);
        if (result == 0) {
            printf("Last error: %u\n", GetLastError());
        } else {
            printf("Parameter length: %u\n", len);
            for (UINT j = 0; j < len; j++) {
                printf("%02X ", buffer[j]);
            } printf("\n");
        }
        // getchar();   
    }
}

BOOL GenerateKeyWithIV(HCRYPTPROV provider) {
    HCRYPTKEY key;
    // IV must be the block length in bits divided by 8,
    //  and the result must be in bytes.
    // AES has a 128 bit block length, therefore:
    //   128b / 8 = 16B of IV
    const BYTE iv[] = { 0x41, 0x42, 0x43, 0x44,
                        0x45, 0x46, 0x47, 0x48,
                        0x49, 0x50, 0x51, 0x52,
                        0x53, 0x54, 0x55, 0x56
                        };
    BOOL result;

    printf("[i] Generating a key\n");
    result = CryptGenKey(
        provider,
        CALG_AES_128,
        0, &key
    );

    if (result == 0) {
        printf("[x] Failed to generate a key\n");
        return false;
    } printf("Key handle: %p\n", (void*) key);

    result = CryptSetKeyParam(key, KP_IV, iv, 0);
    if (result == 0) {
        printf("[x] Failed to set key parameter\n");
    }

    DWORD mode = CRYPT_MODE_CFB;
    result = CryptSetKeyParam(key, KP_MODE, (BYTE*) &mode, 0);
    if (result == 0) {
        printf("[x] Failed to set the mode of operation of the block cipher\n");
    }

    DWORD blocklen = 0; DWORD param_len = sizeof(DWORD);
    result = CryptGetKeyParam(key, KP_BLOCKLEN, (BYTE*) &blocklen, &param_len, 0);
    printf("Blocklen: %u\n", blocklen);
    // GetAllBlockCipherParameters(key);

    PrintKeyData(key);
    printf("[i] Destroying key\n");
    CryptDestroyKey(key);
    return true;
}

void GenerateKeyChunck(HCRYPTPROV provider) {
    HCRYPTKEY key;
    BOOL result;
    BYTE buffer[1024];
    DWORD data_len;


    for (UINT u = 0; u < 10; u++) {
        result = CryptGenKey(provider, CALG_AES_128, CRYPT_EXPORTABLE, &key);
        if (result == 0) printf(" [x] Failed to generate key\n");
        else {
            data_len = 1024;
            result = CryptExportKey(key, NULL, PLAINTEXTKEYBLOB, 0, buffer, &data_len);
            if (result == 0) printf(" [x] Could not export the key\n");
            else {
                cryptoapi::key_data_s* cryptkey = GetKeyStruct(key);
                BYTE* raw_key = (BYTE*) cryptkey->key_bytes;
                printf(" - KEY BYTES: 0x%p\n", raw_key);

                if (cryptkey->key_size != data_len - 12) {
                    printf(" [x] Key size mismatch\n");
                    continue;
                }

                printf(" --- RAW KEY: \n");
                for (UINT w = 0; w < cryptkey->key_size; w++) {
                    printf(" %02X", buffer[w+12]);
                    if (buffer[w+12] != raw_key[w]) {
                        printf("\n [x] Keys mismatch\n");
                        continue;
                    }
                } printf("\n");
                printf("Keys match\n");
            }
        } printf("\n");
    }
    getchar();
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
    printf("Unknown ptr:     %p\n", key_data->unknown);
    printf("Algorithm:       %08X\n", key_data->alg);
    printf("Flags:           %08X\n", key_data->flags);
    printf("Key size:        %08X\n", key_data->key_size);
    printf("Key ptr:         %p\n", key_data->key_bytes);
    printf("Key block len:   %08X\n", key_data->block_len);
    printf("Key cipher mode: %08X\n", key_data->cipher_mode);
    printf("Base IV:         %p\n", key_data->iv);
    
    for (UINT i = 0; i < key_data->block_len; i++) {
        printf("%02X ", key_data->iv[i]);
    } printf("\n");
    PrintKeyParameters(hKey);

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

    // CheckAllBlockSizes(phProv);
    // GenerateKeyWithIV(phProv);
    GenerateKeyChunck(phProv);

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

    TryExportKey(hKey);

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
