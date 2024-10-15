#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")

// From the examples in Microsoft Learn
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

using namespace std;
namespace fs = filesystem;

// CONFIG
wstring path = L"C:\\TEST\\";
const char* key_string = "password";
#define AES_KEY_SIZE 16

#define IN_CHUNK_SIZE (AES_KEY_SIZE * 10)

// GLOBAL
BCRYPT_ALG_HANDLE aes_provider_handle = nullptr;
BCRYPT_ALG_HANDLE sha256_provider_handle = nullptr;
BCRYPT_HASH_HANDLE hash_handle = nullptr;
BCRYPT_KEY_HANDLE key_handle = nullptr;

vector<string> RetrieveTextFiles(const wstring& folderPath) {
    vector<string> file_names;
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".txt") {
            file_names.push_back(entry.path().filename().string());
        }
    }
    return file_names;
}

bool SetupCryptography() {
  NTSTATUS result;
  /** =================
   * OBTAIN PROVIDERS
   *  1. Get AES provider
   *  2. Get SHA256 provider
   * =====
   */

  printf(" [i] Opening providers\n");
  result = BCryptOpenAlgorithmProvider(
    &aes_provider_handle, BCRYPT_AES_ALGORITHM,
    MS_PRIMITIVE_PROVIDER,
    NULL // no flags
  );

  result |= BCryptOpenAlgorithmProvider(
    &sha256_provider_handle, BCRYPT_SHA256_ALGORITHM,
    MS_PRIMITIVE_PROVIDER, NULL
  );

  if (!NT_SUCCESS(result)) {
    printf(" [x] Failed to obtain a provider\n"); return false; }

  /** =================
     * HASH THE PASSWORD
     * =====
     */
  DWORD hash_object_size = 0, hash_data_size = 0, data_size = 0;
  PBYTE hash_object_ptr = nullptr;
  PBYTE hash_ptr = nullptr;

  // Get the size of the hash object 
  printf(" [i] Hashing password\n");
  result = BCryptGetProperty(
    sha256_provider_handle,
    BCRYPT_OBJECT_LENGTH,
    (PBYTE) &hash_object_size,
    sizeof(DWORD),
    &data_size, 
    0 // no flags
  );
  if (!NT_SUCCESS(result)) { printf(" [x] Failed to get object length property\n"); return false; }

  hash_object_ptr = (PBYTE) HeapAlloc(GetProcessHeap(), 0, hash_object_size);
  if (hash_object_ptr == NULL) { printf(" [x] Failed to allocate space for hash object\n"); return false; }

  result = BCryptGetProperty(
    sha256_provider_handle,
    BCRYPT_HASH_LENGTH,
    (PBYTE) &hash_data_size,
    sizeof(DWORD),
    &data_size,
    0 // no flags
  );
  if (!NT_SUCCESS(result)) { printf(" [x] Failed to get hash length\n"); return false; }

  hash_ptr = (PBYTE) HeapAlloc(GetProcessHeap(), 0, hash_data_size);
  if (hash_ptr == NULL) { printf(" [x] Failed to allocate space for hash lenght\n"); return false; }

  result = BCryptCreateHash(
    sha256_provider_handle,
    &hash_handle,
    hash_object_ptr,
    hash_object_size,
    NULL, // secret (not used)
    0, // size of secret
    0 // no flags
  );
  if (!NT_SUCCESS(result)) { printf(" [x] Failed to create hashing system\n"); return false; }

  result = BCryptHashData(
    hash_handle,
    (PBYTE) key_string,
    (DWORD) strlen(key_string),
    0 // no flags
  );
  if (!NT_SUCCESS(result)) { printf(" [x] Failed to has data\n"); return false; }

  result = BCryptFinishHash(
    hash_handle,
    hash_ptr,
    hash_data_size,
    0
  );
  if (!NT_SUCCESS(result)) { printf(" [x] Failed to end hashing\n"); return false; }

  if (AES_KEY_SIZE > hash_data_size) {
    printf(" [x] Desired key size exceeds hash size, therefore it is not possible to derive a key from it. Please use a smaller key size (current size: %u)\n", AES_KEY_SIZE);
    return false;
  }

  printf(" [i] Generating symmetric key\n");
  result = BCryptGenerateSymmetricKey(
    aes_provider_handle,
    &key_handle,
    NULL, // null when key is derived (in our case, calculated through a hash)
    0, // size of the object set to auto
    hash_ptr, // key material
    AES_KEY_SIZE, // size of previous
    0 // no flags
  );
  if (!NT_SUCCESS(result)) { printf("Failed to generate a symmetric key from the hash\n"); return false; }

  return true;
}

void CleanUp() {
  printf(" [i] Cleaning up (w/o error checks)\n");
  BCryptCloseAlgorithmProvider(aes_provider_handle, 0);
  BCryptCloseAlgorithmProvider(sha256_provider_handle, 0);
}

bool CipherFiles() {
  NTSTATUS result;

  printf(" [i] Enumerating text files\n");
  vector<string> text_files = RetrieveTextFiles(path);
  printf("  * Found %u text files\n", text_files.size());

  printf(" [i] Ciphering text files in folder\n");
  SIZE_T file_count = 1;
  for (const string& filename : text_files) {
    printf(" Progress: %u/%u\t\t\r", file_count++, text_files.size());

    wstring wide_input_filename(filename.begin(), filename.end()); // Convertir el nombre de archivo a wstring
    wide_input_filename = path + wide_input_filename; // Pasar el path
    const wchar_t* input = wide_input_filename.c_str(); // Variable const wchar_t* para el nombre de archivo de entrada
    wstring wide_output_filename = wide_input_filename; // Crear una copia de wide_input_filename para el nombre de archivo de salida
    wide_output_filename += L".enc"; // Agregar la extensión ".dec" al nombre de archivo de salida

    const wchar_t* output = wide_output_filename.c_str(); // Variable const wchar_t* para el nombre de archivo de salida
    
    // Input file handle
    HANDLE input_file_handle = CreateFileW(input, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (input_file_handle == INVALID_HANDLE_VALUE) {
      printf("Cannot open input file!\n");
      system("pause");
      return false;
    }

    // Output file handle
    HANDLE hOutFile = CreateFileW(output, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE) {
      printf("Cannot open output file!\n");
      system("pause");
      return false;
    }

    // Buffered read/write
    BYTE* input_chunk = new BYTE[IN_CHUNK_SIZE]; // dynamic byte array
    DWORD in_bytes_read = 0;
    BYTE* output_chunk = nullptr;
    DWORD out_chunk_size = 0;
    BOOL is_final = FALSE;
    DWORD total_bytes_read = 0;
    DWORD input_size = GetFileSize(input_file_handle, NULL);

    while (ReadFile(input_file_handle, input_chunk, IN_CHUNK_SIZE, &in_bytes_read, NULL)) {
      if (in_bytes_read == 0) {
        break;
      }

      // last chunk (needed by the CryptEncrypt funciton, probably because of padding)
      total_bytes_read += in_bytes_read;
      if (total_bytes_read >= input_size) {
        is_final = TRUE;
        //printf("Final chunk set, len: %d = %x\n", out_len, out_len);
      }

      /* Check the necessary output buffer size */
      out_chunk_size = 0;
      result = BCryptEncrypt(
        key_handle,
        input_chunk, in_bytes_read,
        NULL, NULL, 0,  // padding & IV
        NULL, 0, // output null to get the size
        &out_chunk_size,  // This will receive the required output size
        is_final ? BCRYPT_BLOCK_PADDING : 0
      );

      // Allocate space for the output buffer
      output_chunk = new BYTE[out_chunk_size];

      DWORD bytes_written = 0;
      result = BCryptEncrypt(
        key_handle, 
        input_chunk, in_bytes_read, // input data
        NULL, NULL, 0, // padding, IV
        output_chunk, out_chunk_size, // output data
        &bytes_written,
        is_final ? BCRYPT_BLOCK_PADDING : 0 // Use block padding for the final chunk
      );

      if (!NT_SUCCESS(result)) {
        printf("[-] BCryptEncrypt result: %X\n", result);
        break;
      }
      
      DWORD written_to_file = 0;
      if (!WriteFile(hOutFile, output_chunk, bytes_written, &written_to_file, NULL)) {
        printf("writing failed!\n");
        break;
      }
      memset(input_chunk, 0, IN_CHUNK_SIZE);
      delete[]output_chunk; output_chunk = nullptr;
    }
    delete[]input_chunk; input_chunk = nullptr;
    CloseHandle(input_file_handle);
    CloseHandle(hOutFile);
    Sleep(1000);
  }
  printf("\n");
  return true;
}

int main() {
  
  if (SetupCryptography()) {
    CipherFiles();
  } else {
    printf("Failed to initialize key\n");
  }

  CleanUp();
}