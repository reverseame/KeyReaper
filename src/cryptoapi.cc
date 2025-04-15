#include <cryptoapi.h>
#include <wincrypt.h>

namespace key_scanner {
namespace cryptoapi {

cryptoapi::key_data_s* GetKeyStruct(::HCRYPTKEY key) {
  cryptoapi::HCRYPTKEY* hCryptKey = (cryptoapi::HCRYPTKEY*) key;
  UINT_PTR magic_xor = (UINT_PTR) hCryptKey->magic;
  magic_xor = magic_xor ^ MAGIC_CONSTANT;
  cryptoapi::magic_s* ms = (cryptoapi::magic_s*) magic_xor;
  return (cryptoapi::key_data_s*) ms->key_data;
}

void ForceExportBit(::HCRYPTKEY key) {
  cryptoapi::key_data_s* key_data = GetKeyStruct(key);
  key_data->flags |= 
    CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
}

} // namespace cryptoapi
} // namespace key_scanner