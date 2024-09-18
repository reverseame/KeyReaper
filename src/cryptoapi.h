#ifndef CUSTOM_CRYPTOAPI_H
#define CUSTOM_CRYPTOAPI_H

#include <Windows.h>
#include <vector>
#include <string>

namespace key_scanner {
namespace cryptoapi {

#if _WIN64
#define CPGENKEY_OFFSET 0x1140u
#define CPDERIVEKEY_OFFSET 0x18F80u
#define CPDESTROYKEY_OFFSET 0x48A0u
#define CPSETKEYPARAM_OFFSET 0x1AAC0u
#define CPGETKEYPARAM_OFFSET 0x5100u
#define CPEXPORTKEY_OFFSET 0x4AA0u
#define CPIMPORTKEY_OFFSET 0x1590u
#define CPENCRYPT_OFFSET 0x161B0u
#define CPDECRYPT_OFFSET 0x16100u
#define CPDUPLICATEKEY_OFFSET 0x197F0u
#elif _WIN32
#define CPGENKEY_OFFSET 0x000050C0u
#define CPDERIVEKEY_OFFSET 0x0001AD90u
#define CPDESTROYKEY_OFFSET 0x000086C0u
#define CPSETKEYPARAM_OFFSET 0x0001C770u
#define CPGETKEYPARAM_OFFSET 0x000098C0u
#define CPEXPORTKEY_OFFSET 0x00004C40u
#define CPIMPORTKEY_OFFSET 0x00006290u
#define CPENCRYPT_OFFSET 0x00019880u
#define CPDECRYPT_OFFSET 0x0000A500u
#define CPDUPLICATEKEY_OFFSET 0x0001B5C0u
#endif

#if _WIN64
#define MAGIC_CONSTANT 0xE35A172CD96214A0
#elif _WIN32
#define MAGIC_CONSTANT 0xE35A172C
#endif

const std::vector<uintptr_t> cryptoapi_offsets = {
  CPGENKEY_OFFSET, CPDERIVEKEY_OFFSET, CPDESTROYKEY_OFFSET, 
  CPSETKEYPARAM_OFFSET, CPGETKEYPARAM_OFFSET, CPEXPORTKEY_OFFSET,
  CPIMPORTKEY_OFFSET, CPENCRYPT_OFFSET, CPDECRYPT_OFFSET,
  CPDUPLICATEKEY_OFFSET
};

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