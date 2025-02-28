#include <memory>
#include <windows.h>
#include <winternl.h>
#include <functional>
#include <algorithm>
#include <iostream>

#include "key.h"
#include "scanners.h"
#include "process_capturer.h"
#include "cryptoapi.h"
#include "injection/interproc_coms.h"

using namespace std;
using ProcessCapturer = process_manipulation::ProcessCapturer;
using HeapInformation = process_manipulation::HeapInformation;


namespace key_scanner {

void ScannerBuilder::AddCryptoAPIScan() {
  do_crapi_structure_scan_ = true;
}

void ScannerBuilder::AddRoundKeyScan() {
  do_round_key_scan_ = true;
}

ScannerVector ScannerBuilder::GetScanners() {

  unique_ptr<vector<unique_ptr<ScanStrategy>>> strategies = make_unique<vector<unique_ptr<ScanStrategy>>>();

  if (do_round_key_scan_) {
    RoundKeyScan s = RoundKeyScan();
    strategies->push_back(make_unique<RoundKeyScan>(s));
  }

  if (do_crapi_structure_scan_) {
    CryptoAPIScan s = CryptoAPIScan();
    strategies->push_back(make_unique<CryptoAPIScan>(s));
  }

  return ScannerVector(move(strategies));
}

HMODULE CryptoAPIScan::cryptoapi_base_address = NULL;
vector<uintptr_t> CryptoAPIScan::cryptoapi_functions = vector<uintptr_t>();
bool CryptoAPIScan::cryptoapi_functions_initialized = false;

void CryptoAPIScan::InitializeCryptoAPI() {
  if (!cryptoapi_functions_initialized) {
    // reset the contents in case there was any remainder from previous executions
    cryptoapi_functions.clear();

    // if it was not already initialized
    if (cryptoapi_base_address == NULL) {
      cryptoapi_base_address = LoadLibraryA("rsaenh.dll");
    } else {
      printf(" Could not initialize rsaenh.dll");
    }

    if (cryptoapi_base_address != NULL) {
      // Assume all initialized correctly and wait for the error
      cryptoapi_functions_initialized = true;

      for (string func_name : cryptoapi::cryptoapi_function_names) {
        FARPROC func_address = GetProcAddress(cryptoapi_base_address, func_name.c_str());

        if (func_address != NULL) {
          // Cast and add it to the list with all the functions
          cryptoapi_functions.push_back(reinterpret_cast<uintptr_t>(func_address));

        } else {
          cout << " Could not initialize a function pointer to " << func_name << endl;
          cout << error_handling::GetLastErrorAsString() << endl;
          cryptoapi_functions_initialized = false;
          break;
        }
      }
    }
  }
}

unordered_set<HCRYPTKEY> CryptoAPIScan::GetHCRYPTKEYs(unsigned char *input_buffer, process_manipulation::HeapInformation heap_info) {
  auto found_hcryptkeys = unordered_set<HCRYPTKEY>();

  InitializeCryptoAPI();
  if (cryptoapi_functions_initialized) {

    printf(" rsaenh.dll 0x%p\n", (void*) cryptoapi_base_address);

    vector<BYTE> byte_pattern = GetCryptoAPIFunctions();
    auto searcher = boyer_moore_horspool_searcher(byte_pattern.data(), byte_pattern.data() + byte_pattern.size());

    size_t match_count = 0;
    unsigned char* search_start = input_buffer;
    unsigned char* search_result;

    // While there are matches left
    while ((search_result = search(search_start, input_buffer + heap_info.GetSize(), searcher)) != input_buffer + heap_info.GetSize()) {
      uintptr_t position = search_result - input_buffer;
      match_count++;
      printf(" [%zu] HCRYPTKEY structure found at offset [0x%p]\n", match_count, (void*) (position + heap_info.GetBaseAddress()));

      HCRYPTKEY key = heap_info.GetBaseAddress() + position;
      found_hcryptkeys.insert(key);

      search_start = search_result + byte_pattern.size();
      printf(" --\n");
    }

    if (match_count == 0) {
      printf("Pattern not found\n");
    } else printf("A total of %zu matches were found.\n", match_count);

  } else {
    printf("Could not load initialize necessary CryptoAPI functions\n");
  }

  return found_hcryptkeys;
}

vector<BYTE> CryptoAPIScan::GetCryptoAPIFunctions() {
  if (!cryptoapi_functions_initialized) return vector<BYTE>();

  uintptr_t pos = 0;
  size_t pattern_size = cryptoapi_functions.size() * sizeof(void*);
  vector<BYTE> byte_pattern = vector<BYTE>(pattern_size);
  for (auto& offset : cryptoapi_functions) {
    memcpy(byte_pattern.data() + pos, &offset, sizeof(void*));
    pos += sizeof(void*);
  }

  return byte_pattern;
}

// KEY MANUAL EXTRACTION TEST
typedef NTSTATUS (NTAPI *PFN_NTDEVICEIOCONTROLFILE)(
  HANDLE FileHandle,
  HANDLE Event,
  PIO_APC_ROUTINE ApcRoutine,
  PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG IoControlCode,
  PVOID InputBuffer,
  ULONG InputBufferLength,
  PVOID OutputBuffer,
  ULONG OutputBufferLength
);

void GetPrivateRSAPair(unsigned char* input_buffer, HeapInformation heap_info) {
/*
  1. Search for "RSA2" and copy the bytes
  2. Perform the same call as the CryptoAPI 
  */
 HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (!hNtdll) {
    printf("Failed to get handle to ntdll.dll\n");
    return;
  }

  // Get the address of NtDeviceIoControlFile
  PFN_NTDEVICEIOCONTROLFILE NtDeviceIoControlFile =
    (PFN_NTDEVICEIOCONTROLFILE)GetProcAddress(hNtdll, "NtDeviceIoControlFile");
  if (!NtDeviceIoControlFile) {
    printf("Failed to get address of NtDeviceIoControlFile\n");
    return;
  }
  BYTE rsa2_pattern[] = { 
    'R', 'S', 'A', '2'
  };
  DWORD pattern_size = 4;
  DWORD rsa2_size = 0x2BC;
  auto rsa2_searcher = boyer_moore_horspool_searcher(rsa2_pattern, rsa2_pattern + pattern_size);
  
  size_t matches = 0;
  unsigned char* search_start = input_buffer;
  unsigned char* search_result;
  while((search_result = search(search_start, input_buffer + heap_info.GetSize(), rsa2_searcher)) != input_buffer + heap_info.GetSize()) {
    matches++;
    uintptr_t position = search_result - input_buffer;
    printf("[%zu] RSA2 shadow found [0x%p]\n", matches, (void*) position);
    ProcessCapturer::PrintMemory(search_result, rsa2_size, 0);

    search_start = search_result + pattern_size;
    getchar();
  }
  if (matches == 0) printf("No matches found\n");

  HANDLE hSourceProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, 7892);
  if (!hSourceProcess) {
    printf("Failed to open source process: %lu\n", GetLastError());
    return;
  }

  HANDLE hTargetProcess = GetCurrentProcess(); // Duplicate into the current process
  HANDLE hDuplicatedHandle;

  if (DuplicateHandle(
    hSourceProcess,      // Source process
    (HANDLE) 0x12C,  // Handle to duplicate
    hTargetProcess,      // Target process
    &hDuplicatedHandle,  // New handle
    0,                   // Access rights (0 = same as source)
    FALSE,               // Not inheritable
    DUPLICATE_SAME_ACCESS)) { // Same access rights
    printf("Successfully duplicated handle\n");
  } else {
    printf("Failed to duplicate handle: %lu\n", GetLastError());
  }

  CloseHandle(hSourceProcess);

  IO_STATUS_BLOCK status_block;
  NTSTATUS res = NtDeviceIoControlFile(
    hDuplicatedHandle,
    0,
    0,
    0,
    &status_block,
    0x390012,
    search_result,
    rsa2_size,
    search_result,
    rsa2_size
  );
  printf("0x%X\n", res);
  ProcessCapturer::PrintMemory(search_result, rsa2_size, 0);
  getchar();
}

void InjectExtractKeys(unordered_set<HCRYPTKEY> key_handles) {
  for (auto key : key_handles) {
    custom_ipc::SendKeyHandleToMailSlot(key);
  }
}

unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> CryptoAPIScan::Scan(unsigned char *input_buffer, HeapInformation heap_info, ProcessCapturer& capturer) const {
  unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> found_keys = unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>();

  // TEST
  /*{
    auto key_handles = GetHCRYPTKEYs(input_buffer, heap_info);
    InjectExtractKeys(key_handles);
  }*/

  InitializeCryptoAPI();
  if (cryptoapi_functions_initialized) {

    printf(" rsaenh.dll 0x%p\n", (void*) cryptoapi_base_address);

    // Copy the pattern to a buffer
    vector<BYTE> byte_pattern = GetCryptoAPIFunctions();
    auto searcher = boyer_moore_horspool_searcher(byte_pattern.data(), byte_pattern.data() + byte_pattern.size());
    // GetPrivateRSAPair(input_buffer, heap_info);

    size_t match_count = 0;
    unsigned char* search_start = input_buffer;
    unsigned char* search_result;

    // While there are matches left
    while ((search_result = search(search_start, input_buffer + heap_info.GetSize(), searcher)) != input_buffer + heap_info.GetSize()) {
      uintptr_t position = search_result - input_buffer;
      match_count++;
      printf(" [%zu] HCRYPTKEY structure found at offset [0x%p]\n", match_count, (void*) (position + heap_info.GetBaseAddress()));
      // ProcessCapturer::PrintMemory(search_result, 64, heap_info.base_address + position); // print the HCRYPTKEY structure

      HCRYPTKEY key_handle = heap_info.GetBaseAddress() + position;

      // XOR with the magic constant
      SIZE_T data_read = 0;
      auto buffer = vector<BYTE>();
      auto raw_key = vector<BYTE>();

      cryptoapi::HCRYPTKEY* h_crypt_key = reinterpret_cast<cryptoapi::HCRYPTKEY*>(search_result);
      ULONG_PTR unk_struct = (ULONG_PTR) (h_crypt_key->magic) ^ MAGIC_CONSTANT; // virtual address

      cryptoapi::magic_s* magic_struct_ptr = NULL;

      if (!heap_info.RebaseAddress(&unk_struct, (ULONG_PTR) input_buffer)) {
        printf(" Magic struct address [0x%p] is outside of the heap dump, trying a manual copy\n", (void*) unk_struct);
        buffer.resize(sizeof(cryptoapi::magic_s), 0);

        error_handling::ProgramResult res = capturer.GetMemoryChunk((BYTE*) unk_struct, sizeof(cryptoapi::magic_s), buffer.data(), &data_read);
        if (res.IsOk() && data_read == sizeof(cryptoapi::magic_s)) {
          magic_struct_ptr = (cryptoapi::magic_s*) buffer.data();
        
        } else {
          cerr << " [x] Error while copying the data: " << res.GetResultInformation() << endl;
          search_start = search_result + byte_pattern.size();
          continue;
        }
      } else {
        magic_struct_ptr = (cryptoapi::magic_s*) unk_struct;
      }

      ULONG_PTR ptr = (ULONG_PTR) magic_struct_ptr->key_data;
      // ProcessCapturer::PrintMemory((unsigned char*) magic_struct_ptr, 16);

      cryptoapi::key_data_s* key_data_struct = NULL;
      if (!heap_info.RebaseAddress(&ptr, (ULONG_PTR) input_buffer)) {
        printf(" Key data [0x%p] is out of this heap, trying a manual copy\n", magic_struct_ptr->key_data);
        buffer.resize(sizeof(cryptoapi::key_data_s), 0);

        error_handling::ProgramResult res = capturer.GetMemoryChunk((BYTE*) ptr, sizeof(cryptoapi::key_data_s), buffer.data(), &data_read);
        if (res.IsOk() && data_read == sizeof(cryptoapi::key_data_s)) {
          key_data_struct = (cryptoapi::key_data_s*) buffer.data();
        } else {
          cerr << " [x] Error while copying the data: " << res.GetResultInformation() << endl;
          search_start = search_result + byte_pattern.size();
          continue;
        }

      } else {
        key_data_struct = (cryptoapi::key_data_s*) ptr;
      }

      ptr = (ULONG_PTR) key_data_struct->key_bytes;
      printf("   * Key found at 0x%p\n", (void*) ptr);

      if (!heap_info.RebaseAddress(&ptr, (ULONG_PTR) input_buffer)) {
        printf(" Key [0x%p] is out of this heap, trying a manual copy\n", (void*) ptr);
        raw_key.resize(key_data_struct->key_size, '\0');

        error_handling::ProgramResult res = capturer.GetMemoryChunk((BYTE*) key_data_struct->key_bytes, key_data_struct->key_size, raw_key.data(), &data_read);
        if (res.IsOk() && data_read == key_data_struct->key_size) {
          ptr = (ULONG_PTR) raw_key.data();
        } else {
          cerr << " [x] Error while copying the data: " << res.GetResultInformation() << endl;
          search_start = search_result + byte_pattern.size();
          continue;
        }
      }

      // TODO: move this check above
      DWORD alg = key_data_struct->alg;
      // TODO: check which other CryptoAPI-supported algorithms have a private pair
      if ( alg == CALG_RSA_KEYX || alg == CALG_RSA_SIGN ) { // If asymmetric
        printf(" [i] Detected an asymmetric key\n");
        vector<BYTE> key_blob;
        auto res = capturer.GetKeyBlobFromRemote(key_handle, PUBLICKEYBLOB, key_blob);
        
        // Copy and update the size
        cryptoapi::key_data_s updated_key_data = *key_data_struct;
        updated_key_data.key_size = key_blob.size();

        if (res.IsOk()) {
          ProcessCapturer::PrintMemory(key_blob.data(), key_blob.size());
          found_keys.insert(
            make_shared<CryptoAPIKey>(
              CryptoAPIKey(&updated_key_data, key_blob.data(), key_handle)
            )
          );
        } else cerr << res.GetResultInformation() << endl;

        res = capturer.GetKeyBlobFromRemote(key_handle, PRIVATEKEYBLOB, key_blob);
        updated_key_data.key_size = key_blob.size();
        if (res.IsOk()) {
          found_keys.insert(
            make_shared<CryptoAPIKey>(
              CryptoAPIKey(&updated_key_data, key_blob.data(), key_handle)
            )
          );
        } else cerr << res.GetResultInformation() << endl;

      } else { // symmetric algorithms
        ProcessCapturer::PrintMemory((unsigned char*) ptr, 16, (ULONG_PTR) key_data_struct->key_bytes);
        found_keys.insert(
          make_shared<CryptoAPIKey>(
            CryptoAPIKey(key_data_struct, (unsigned char*) ptr, key_handle)
          )
        );
      }

      search_start = search_result + byte_pattern.size();
      printf(" --\n");
    }

    if (match_count == 0) {
      printf("Pattern not found\n");
    } else printf("A total of %zu matches were found.\n", match_count);

  } else {
    printf("Could not load initialize necessary CryptoAPI functions\n");
  }

  return found_keys;
}

std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> RoundKeyScan::Scan(unsigned char *buffer, HeapInformation heap_info, ProcessCapturer& capturer) const {
  return std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>();
}

ScannerVector::ScannerVector(std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> scanners) {
  scanners_ = std::move(scanners);
}

} // namespace key_scanner
