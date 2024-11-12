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
std::unordered_set<Key, Key::KeyHashFunction> CryptoAPIScan::Scan(unsigned char *input_buffer, HeapInformation heap_info) const {

  unordered_set<Key, Key::KeyHashFunction> found_keys = unordered_set<Key, Key::KeyHashFunction>();

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
    unsigned char* byte_pattern = (unsigned char*) malloc(pattern_size);
    for (auto& offset : cryptoapi_functions) {
      memcpy(byte_pattern + pos, &offset, sizeof(void*));
      pos += sizeof(void*);
    }

    /*
    for (unsigned int i = 0; i < pos; i++) {
      printf("%02hhX ", byte_pattern[i]);
      if (i % 16 == 15) { printf("\n"); }
    } printf("\n");
    */

    auto searcher = boyer_moore_horspool_searcher(byte_pattern, byte_pattern + pattern_size);

    size_t match_count = 0;
    unsigned char* search_start = input_buffer;
    unsigned char* search_result;

    // While there are matches left
    while ((search_result = search(search_start, input_buffer + heap_info.GetSize(), searcher)) != input_buffer + heap_info.GetSize()) {
      uintptr_t position = search_result - input_buffer;
      match_count++;
      printf(" HCRYPTKEY structure found at [%p]\n", search_result);
      // ProcessCapturer::PrintMemory(search_result, 64, heap_info.base_address + position); // print the HCRYPTKEY structure

      // XOR with the magic constant
      cryptoapi::HCRYPTKEY* h_crypt_key = reinterpret_cast<cryptoapi::HCRYPTKEY*>(search_result);
      ULONG_PTR unk_struct = (ULONG_PTR) (h_crypt_key->magic) ^ MAGIC_CONSTANT; // virtual address

      if (heap_info.RebaseAddress(&unk_struct, (ULONG_PTR) input_buffer)) {
        cryptoapi::magic_s* magic_struct_ptr = (cryptoapi::magic_s*) unk_struct;
        ULONG_PTR ptr = (ULONG_PTR) magic_struct_ptr->key_data;
        // ProcessCapturer::PrintMemory((unsigned char*) magic_struct_ptr, 16);
        if (heap_info.RebaseAddress(&ptr, (ULONG_PTR) input_buffer)) {
          cryptoapi::key_data_s* key_data_struct = (cryptoapi::key_data_s*) ptr;
          ptr = (ULONG_PTR) key_data_struct->key_bytes;
          printf("   * Key found at 0x%p\n", (void*) ptr);

          if (heap_info.RebaseAddress(&ptr, (ULONG_PTR) input_buffer)) {
            Key key = Key(key_data_struct, (unsigned char*) ptr);
            found_keys.insert(key);
            // ProcessCapturer::PrintMemory((unsigned char*) (ptr), 16, ptr + heap_info.base_address - (ULONG_PTR) input_buffer);

          } else {
            printf(" Key [0x%p] is out of this heap\n", (void*) ptr);
            printf("  > ALG_ID: %X\n", key_data_struct->alg);
          }
        } else {
          printf(" Key data [0x%p] is out of this heap\n", magic_struct_ptr->key_data);
        }
      } else {
        printf(" Magic struct address [0x%p] is out of this heap\n", (void*) unk_struct);
      }

      search_start = search_result + pattern_size;
      printf(" --\n");
    }

    if (match_count == 0) {
      printf("Pattern not found\n");
    }

    free(byte_pattern);

  } else {
    printf("Could not load initialize necessary CryptoAPI functions\n");
  }

  return found_keys;
}

std::unordered_set<Key, Key::KeyHashFunction> RoundKeyScan::Scan(unsigned char *buffer, HeapInformation heap_info) const {
  return std::unordered_set<Key, Key::KeyHashFunction>();
}

ScannerVector::ScannerVector(std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> scanners) {
  scanners_ = std::move(scanners);
}

} // namespace key_scanner