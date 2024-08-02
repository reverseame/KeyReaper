#include <memory>
#include <Windows.h>
#include <functional>
#include <algorithm>

#include "key.h"
#include "scanners.h"
#include "process_capturer.h"
#include "cryptoapi.h"

using namespace std;
using ProcessCapturer = process_manipulation::ProcessCapturer;
using HeapInformation = process_manipulation::HeapInformation;


namespace key_scanner {

void StrategyBuilder::AddStructureScan() {
  do_structure_scan_ = true;
}

void StrategyBuilder::AddRoundKeyScan() {
  do_round_key_scan_ = true;
}

unique_ptr<vector<unique_ptr<ScanStrategy>>> StrategyBuilder::GetScanners() {

  unique_ptr<vector<unique_ptr<ScanStrategy>>> strategies = make_unique<vector<unique_ptr<ScanStrategy>>>();

  if (do_round_key_scan_) {
    RoundKeyScan s = RoundKeyScan();
    strategies->push_back(make_unique<RoundKeyScan>(s));
  }

  if (do_structure_scan_) {
    StructureScan s = StructureScan();
    strategies->push_back(make_unique<StructureScan>(s));
  }

  return strategies;
}

static HMODULE cryptoapi_base_address = NULL;
std::unordered_set<Key, Key::KeyHashFunction> StructureScan::Scan(unsigned char *input_buffer, HeapInformation heap_info) const {

  unordered_set<Key, Key::KeyHashFunction> found_keys = unordered_set<Key, Key::KeyHashFunction>();
  
  if (cryptoapi_base_address == NULL) { // if it was not initialized
    cryptoapi_base_address = LoadLibraryA("rsaenh.dll");
  }
  
  if (cryptoapi_base_address != NULL) {

    printf("rsaenh.dll 0x%p\n", (void*) cryptoapi_base_address);

    // Precomputed offsets vs GetProcAddress
    //FARPROC cgk_address = GetProcAddress(cryptoapi_base_address, "CryptGenKey");
    vector<uintptr_t> local_offsets = cryptoapi::cryptoapi_offsets;
    for (auto &offset : local_offsets) {
      offset += (uintptr_t) cryptoapi_base_address;
    }

    uintptr_t pos = 0;
    size_t pattern_size = local_offsets.size() * sizeof(void*);
    unsigned char* byte_pattern = (unsigned char*) malloc(pattern_size);
    for (auto& offset : local_offsets) {
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
    //unsigned char* search_result = search(input_buffer, input_buffer + buffer_size, searcher);

    size_t match_count = 0;
    unsigned char* search_start = input_buffer;
    unsigned char* search_result;

    while ((search_result = search(search_start, input_buffer + heap_info.size, searcher)) != input_buffer + heap_info.size) {
      uintptr_t position = search_result - input_buffer;
      //printf("Pattern found at position: d%td\n", position);
      printf(" Search result: [%p]\n", search_result);
      ProcessCapturer::PrintMemory(search_result, 64, heap_info.base_address + position);

      match_count++;
      // TODO follow structure pointers to key
      cryptoapi::HCRYPTKEY* h_crypt_key = reinterpret_cast<cryptoapi::HCRYPTKEY*>(search_result);
      if ( heap_info.IsAddressInHeap(h_crypt_key->magic) ) {
        printf("Address out of this heap\n");

      } else {
        ULONG_PTR heap_offset = (ULONG_PTR) (h_crypt_key->magic) ^ MAGIC_CONSTANT; // virtual address
        heap_offset -= (ULONG_PTR) heap_info.base_address; // offset in relation to the buffer
        cryptoapi::magic_s* magic_struct_ptr = (cryptoapi::magic_s*) ((ULONG_PTR) heap_offset + (ULONG_PTR) input_buffer); // Why does it fail with the structure
        // ProcessCapturer::PrintMemory((unsigned char*) magic_struct_ptr, 16);

        heap_offset = ((ULONG_PTR) magic_struct_ptr->key_data) - heap_info.base_address;
        cryptoapi::key_data_s* key_data = (cryptoapi::key_data_s*) (heap_offset + (ULONG_PTR) input_buffer);
        // ProcessCapturer::PrintMemory((unsigned char*) key_data, 32, heap_info.base_address + heap_offset);

        heap_offset = ((ULONG_PTR) key_data->key_bytes - (ULONG_PTR) heap_info.base_address);
        Key key = Key(key_data, (unsigned char*) ((ULONG_PTR) input_buffer + heap_offset));
        printf("     Key found at 0x%p\n", key_data->key_bytes);

        ProcessCapturer::PrintMemory((unsigned char*) ((ULONG_PTR) input_buffer + heap_offset), 16, heap_info.base_address + heap_offset);
        found_keys.insert(key);
      }

      search_start = search_result + pattern_size;
    }

    if (match_count == 0) {
      printf("Pattern not found\n");
    }

    free(byte_pattern);

  } else {
    printf("Could not load rsaenh.dll\n");
  }
  return found_keys;
}

std::unordered_set<Key, Key::KeyHashFunction> RoundKeyScan::Scan(unsigned char *buffer, HeapInformation heap_info) const {
  return std::unordered_set<Key, Key::KeyHashFunction>();
}

} // namespace key_scanner