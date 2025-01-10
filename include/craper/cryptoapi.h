#ifndef CUSTOM_CRYPTOAPI_H
#define CUSTOM_CRYPTOAPI_H

#include <windows.h>
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
  void *unknown;     // +0x00
  ALG_ID alg;        // +0x04
  uint32_t flags;    // +0x08
  uint32_t key_size; // +0x0C
  void* key_bytes;   // +0x10
  BYTE unk1[0x10];
  BYTE iv[0x10];     // +0x24
  BYTE unk2[0x34];
  DWORD cipher_mode; // +0x68
  BYTE unk3[0x14];
  DWORD block_len;   // +0x80
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