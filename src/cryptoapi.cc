#include <cryptoapi.h>
#include <wincrypt.h>

namespace cryptoapi {

cryptoapi::RSAENH_CRYPTKEY* GetKeyStructRsaEnh(::HCRYPTKEY key) {
  cryptoapi::HCRYPTKEY* hCryptKey = (cryptoapi::HCRYPTKEY*) key;
  UINT_PTR magic_xor = (UINT_PTR) hCryptKey->magic;
  magic_xor = magic_xor ^ RSAENH_CONSTANT;
  cryptoapi::unk_struct* ms = (cryptoapi::unk_struct*) magic_xor;
  return (cryptoapi::RSAENH_CRYPTKEY*) ms->key_data;
}

void ForceExportBitRsaEnh(::HCRYPTKEY key) {
  cryptoapi::RSAENH_CRYPTKEY* key_data = GetKeyStructRsaEnh(key);
  key_data->flags |= 
    CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;
}

} // namespace cryptoapi