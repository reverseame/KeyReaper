#include <memory>
#include <Windows.h>
#include <functional>
#include <algorithm>

#include "key.h"
#include "scanners.h"

using namespace std;

namespace key_scanner {

#define CPGENKEY_ADDRESS 0x000050C0u
#define CPDERIVEKEY_ADDRESS 0x0001AD90u
#define CPDESTROYKEY_ADDRESS 0x000086C0u
#define CPSETKEYPARAM_ADDRESS 0x0001C770u
#define CPGETKEYPARAM_ADDRESS 0x000098C0u
#define CPEXPORTKEY_ADDRESS 0x00004C40u
#define CPIMPORTKEY_ADDRESS 0x00006290u
#define CPENCRYPT_ADDRESS 0x00019880u
#define CPDECRYPT_ADDRESS 0x0000A500u
#define CPDUPLICATEKEY_ADDRESS 0x0001B5C0u

const vector<unsigned int> cryptoapi_offsets = {
  CPGENKEY_ADDRESS, CPDERIVEKEY_ADDRESS, CPDESTROYKEY_ADDRESS, 
  CPSETKEYPARAM_ADDRESS, CPGETKEYPARAM_ADDRESS, CPEXPORTKEY_ADDRESS,
  CPIMPORTKEY_ADDRESS, CPENCRYPT_ADDRESS, CPDECRYPT_ADDRESS,
  CPDUPLICATEKEY_ADDRESS
};

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
std::unordered_set<Key, Key::KeyHashFunction> StructureScan::Scan(unsigned char *input_buffer, size_t buffer_size) const {

  unordered_set<Key, Key::KeyHashFunction> found_keys = unordered_set<Key, Key::KeyHashFunction>();
  
  if (cryptoapi_base_address == NULL) { // if it was not initialized
    cryptoapi_base_address = LoadLibraryA("rsaenh.dll");
  }
  
  if (cryptoapi_base_address != NULL) {

    printf("rsaenh.dll 0x%08X\n", (void*) cryptoapi_base_address);

    //FARPROC cgk_address = GetProcAddress(cryptoapi_base_address, "CryptGenKey");
    vector<unsigned int> local_offsets = cryptoapi_offsets;
    for (auto &offset : local_offsets) {
      offset += (unsigned int) cryptoapi_base_address;
    }

    unsigned int pos = 0;
    unsigned char* byte_pattern = (unsigned char*) malloc(local_offsets.size() * sizeof(void*));
    for (auto& offset : local_offsets) {
      if (sizeof(void*) == 4) { // 32 bit
        ULONG32 reversed = _byteswap_ulong(offset);
        memcpy(byte_pattern + pos, &offset, sizeof(ULONG32)); // TODO: check why the search is not working
        pos += 4;
      } else if (sizeof(void*) == 8) { // 64 bit
        ULONG64 reversed = _byteswap_uint64(offset);
        memcpy(byte_pattern + pos, &reversed, sizeof(ULONG64));
        pos += 8;
      } else {
        printf("Fatal error\n");
      }
    }

    /*
    for (unsigned int i = 0; i < pos; i++) {
      printf("%02hhX ", byte_pattern[i]);
      if (i % 16 == 15) { printf("\n"); }
    } printf("\n");*/

    auto searcher = boyer_moore_horspool_searcher(byte_pattern, byte_pattern + 4);
    unsigned char* search_result = search(input_buffer, input_buffer + buffer_size, searcher);
    printf("Finished scan: %p\n", search_result);

    if (search_result != input_buffer + buffer_size) {
        printf("Pattern found at position: 0x%p\n", (search_result - input_buffer));
    } else {
        printf("Pattern not found\n");
    }

    free(byte_pattern);

  } else {
    printf("Could not load rsaenh.dll\n");
  }
  return found_keys;
}

std::unordered_set<Key, Key::KeyHashFunction> RoundKeyScan::Scan(unsigned char *buffer, size_t buffer_size) const {
  return std::unordered_set<Key, Key::KeyHashFunction>();
}

} // namespace key_scanner