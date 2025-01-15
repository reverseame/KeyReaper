#include <memory>
#include <windows.h>
#include <functional>
#include <algorithm>
#include <iostream>

#include "key.h"
#include "scanners.h"
#include "process_capturer.h"
#include "cryptoapi.h"

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
std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> CryptoAPIScan::Scan(unsigned char *input_buffer, HeapInformation heap_info, DWORD pid) const {
  std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> found_keys = std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>();

  InitializeCryptoAPI();
  if (cryptoapi_functions_initialized) {

    printf(" rsaenh.dll 0x%p\n", (void*) cryptoapi_base_address);

    /* [OLD] PRECOMPUTED OFFSETS
    vector<uintptr_t> local_offsets = cryptoapi::cryptoapi_offsets;
    for (auto &offset : local_offsets) {
      offset += (uintptr_t) cryptoapi_base_address;
    }*/

    // Copy the pattern to a buffer
    uintptr_t pos = 0;
    size_t pattern_size = cryptoapi_functions.size() * sizeof(void*);
    vector<BYTE> byte_pattern = vector<BYTE>(pattern_size);
    for (auto& offset : cryptoapi_functions) {
      memcpy(byte_pattern.data() + pos, &offset, sizeof(void*));
      pos += sizeof(void*);
    }

    /*
    for (unsigned int i = 0; i < pos; i++) {
      printf("%02hhX ", byte_pattern[i]);
      if (i % 16 == 15) { printf("\n"); }
    } printf("\n");
    */

    auto searcher = boyer_moore_horspool_searcher(byte_pattern.data(), byte_pattern.data() + pattern_size);

    size_t match_count = 0;
    unsigned char* search_start = input_buffer;
    unsigned char* search_result;

    ProcessCapturer mem_copier = ProcessCapturer(pid); // until I get a proper copy of the top chunk

    // While there are matches left
    while ((search_result = search(search_start, input_buffer + heap_info.GetSize(), searcher)) != input_buffer + heap_info.GetSize()) {
      uintptr_t position = search_result - input_buffer;
      match_count++;
      printf(" HCRYPTKEY structure found at offset [0x%p]\n", (void*) (position + heap_info.GetBaseAddress()));
      // ProcessCapturer::PrintMemory(search_result, 64, heap_info.base_address + position); // print the HCRYPTKEY structure

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

        error_handling::ProgramResult res = mem_copier.GetMemoryChunk((BYTE*) unk_struct, sizeof(cryptoapi::magic_s), buffer.data(), &data_read);
        if (res.IsOk() && data_read == sizeof(cryptoapi::magic_s)) {
          magic_struct_ptr = (cryptoapi::magic_s*) buffer.data();
        
        } else {
          printf(" A LA MIERDA\n");
          search_start = search_result + pattern_size;
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

        error_handling::ProgramResult res = mem_copier.GetMemoryChunk((BYTE*) ptr, sizeof(cryptoapi::key_data_s), buffer.data(), &data_read);
        if (res.IsOk() && data_read == sizeof(cryptoapi::key_data_s)) {
          key_data_struct = (cryptoapi::key_data_s*) buffer.data();
        } else {
          printf(" A LA MIERDA 2\n");
          search_start = search_result + pattern_size;
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

        error_handling::ProgramResult res = mem_copier.GetMemoryChunk((BYTE*) key_data_struct->key_bytes, key_data_struct->key_size, raw_key.data(), &data_read);
        if (res.IsOk() && data_read == key_data_struct->key_size) {
          ptr = (ULONG_PTR) raw_key.data();
        } else {
          printf(" A LA MIERDA 3\n");
          search_start = search_result + pattern_size;
          continue;
        }
      }

      ProcessCapturer::PrintMemory((unsigned char*) ptr, 16, (ULONG_PTR) key_data_struct->key_bytes);
      found_keys.insert(
        std::make_shared<CryptoAPIKey>(
          CryptoAPIKey(key_data_struct, (unsigned char*) ptr)
        )
      );

      search_start = search_result + pattern_size;
      printf(" --\n");
    }

    if (match_count == 0) {
      printf("Pattern not found\n");
    }

  } else {
    printf("Could not load initialize necessary CryptoAPI functions\n");
  }

  return found_keys;
}

std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> RoundKeyScan::Scan(unsigned char *buffer, HeapInformation heap_info, DWORD _pid) const {
  return std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>();
}

ScannerVector::ScannerVector(std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> scanners) {
  scanners_ = std::move(scanners);
}

} // namespace key_scanner
