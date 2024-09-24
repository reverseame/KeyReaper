#ifndef CUSTOM_CRYPTOAPI_H
#define CUSTOM_CRYPTOAPI_H

#include <Windows.h>
#include <vector>
#include <string>

namespace key_scanner {
namespace cryptoapi {

#if _WIN64
#define MAGIC_CONSTANT 0xE35A172CD96214A0
#elif _WIN32
#define MAGIC_CONSTANT 0xE35A172C
#endif

const std::vector<std::string> cryptoapi_function_names = {
  "CPGenKey", "CPDeriveKey", "CPDestroyKey",
  "CPSetKeyParam", "CPGetKeyParam", "CPExportKey",
  "CPImportKey", "CPEncrypt", "CPDecrypt",
  "CPDuplicateKey"
};

struct key_data_s {
  void *unknown; // XOR-ed
  ALG_ID alg;
  uint32_t flags;
  uint32_t key_size;
  void* key_bytes;
};

struct magic_s {
  key_data_s *key_data;
};

struct HCRYPTKEY {
  void* CPGenKey;
  void* CPDeriveKey;
  void* CPDestroyKey;
  void* CPSetKeyParam;
  void* CPGetKeyParam;
  void* CPExportKey;
  void* CPImportKey;
  void* CPEncrypt;
  void* CPDecrypt;
  void* CPDuplicateKey;
  HCRYPTPROV hCryptProv;
  magic_s *magic; // XOR-ed
};

} // namespace cryptoapi
} // namespace key_scanner

#endif // CUSTOM_CRYPTOAPI_H