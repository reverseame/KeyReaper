#ifndef CUSTOM_CRYPTOAPI_H
#define CUSTOM_CRYPTOAPI_H

#include <windows.h>
#include <vector>
#include <string>

namespace cryptoapi {

#if _WIN64
#define RSAENH_CONSTANT 0xE35A172CD96214A0 
#define DSSENH_CONSTANT 0xA2491D83D96214A0
#elif _WIN32 
#define RSAENH_CONSTANT 0xE35A172C
#define DSSENH_CONSTANT 0xA2491D83
#endif

enum CryptoAPIProvider {
  kRsaEnh, kDssEnh
};

const std::vector<std::string> cryptoapi_function_names = {
  "CPGenKey", "CPDeriveKey", "CPDestroyKey",
  "CPSetKeyParam", "CPGetKeyParam", "CPExportKey",
  "CPImportKey", "CPEncrypt", "CPDecrypt",
  "CPDuplicateKey"
};

struct RSAENH_CRYPTKEY {
  void *unknown;     // +0x00
  ALG_ID alg;        // +0x04 | +0x08
  uint32_t flags;    // +0x08 | +0x0C
  uint32_t key_size; // +0x0C | +0x10
  void* key_bytes;   // +0x10 | +0x18 (padding)
  void* unk_ptr1;    // alignment for 32 and 64-bit
  BYTE unk1[0x0C];
  BYTE iv[0x10];     // +0x24 | +0x34
  BYTE unk2[0x34];
  DWORD cipher_mode; // +0x68 | +0x78
  uint32_t unk_align;
  void* unk_ptr2;
  BYTE unk3[0x0C];
  DWORD block_len;   // +0x80 | +0x94
};

struct unk_struct {
  RSAENH_CRYPTKEY* key_data; //rsaenh
  void* unk2;
	uint32_t unk3;
	ALG_ID alg;  // dssenh
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
  unk_struct *magic; // XOR-ed
};

/**
 * This function performs the necessary indirections
 *  to get the pointer to the RSAENH_CRYPTKEY struct from
 *  the HCRYPTKEY struct.
 * DON'T use it on a dump, as it does not calculate
 *  the offsets.
 */
cryptoapi::RSAENH_CRYPTKEY* GetKeyStructRsaEnh(::HCRYPTKEY key);

/**
 * This function sets the exportable bit of an HCRYPTKEY
 *  to be able to export it with CryptExportKey even if
 *  it was not generated with the CRYPT_EXPORTABLE flag set.
 * Will work with any type of key, but bare in mind that 
 *  private pairs check other things too.
 * DO NOT use it on a dump, as it does not calculate
 *  the offsets.
 */
void ForceExportBitRsaEnh(::HCRYPTKEY key);

} // namespace cryptoapi

#endif // CUSTOM_CRYPTOAPI_H
