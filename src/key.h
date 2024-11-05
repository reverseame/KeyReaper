#ifndef KEY_H
#define KEY_H

#include <string>
#include <unordered_map>
#include <cstddef>
#include <memory>
#include <vector>
#include <windows.h>
#include <wincrypt.h>
#include "cryptoapi.h"

namespace key_scanner {

// FROM MS-LEARN
// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/jj650836(v=vs.85)
#define PLAINTEXTKEYBLOB_MAX_SIZE_BYTES 16
struct CRAPI_PLAINTEXTKEYBLOB {
  CRAPI_PLAINTEXTKEYBLOB(DWORD key_size, ALG_ID algo, const BYTE* key_bytes) {
        hdr.bType = PLAINTEXTKEYBLOB;
        hdr.bVersion = CUR_BLOB_VERSION;
        hdr.reserved = 0;
        hdr.aiKeyAlg = algo;

        ZeroMemory(rgbKeyData, PLAINTEXTKEYBLOB_MAX_SIZE_BYTES); // bytes
        if (key_size > PLAINTEXTKEYBLOB_MAX_SIZE_BYTES) {
          printf(" [x] Key size too big. Copying until maximum (max allowed: %u)\n", PLAINTEXTKEYBLOB_MAX_SIZE_BYTES);
          dwKeySize = PLAINTEXTKEYBLOB_MAX_SIZE_BYTES;
        } else {
          dwKeySize = key_size;
        }
        
        std::memcpy(rgbKeyData, key_bytes, static_cast<size_t>(dwKeySize));
      }
  CRAPI_PLAINTEXTKEYBLOB() : dwKeySize(0) {}

  bool isOk() {
    if (size() == 0) return false;
    return true;
  }

  DWORD size() {
    if (dwKeySize == 0) return 0;
    return dwKeySize + sizeof(BLOBHEADER) + sizeof(DWORD);
  }

  BYTE* key_bytes() {
    return rgbKeyData;
  }

  BLOBHEADER hdr;
  DWORD dwKeySize;
  BYTE rgbKeyData[PLAINTEXTKEYBLOB_MAX_SIZE_BYTES];
};

size_t const kError = 0;
enum class CipherAlgorithm { kError, kUnknown, kAES, kRSA, kRC4, kDES, kSalsa20 };

const std::unordered_map<CipherAlgorithm, std::string> cipher_to_string = {
    { CipherAlgorithm::kError, "Error" },
    { CipherAlgorithm::kUnknown, "Unknown" },
    { CipherAlgorithm::kAES, "AES" },
    { CipherAlgorithm::kRSA, "RSA" },
    { CipherAlgorithm::kRC4, "RC4" },
    { CipherAlgorithm::kDES, "DES" },
    { CipherAlgorithm::kSalsa20, "Salsa20" },
};

class KeyType {
 public:
  KeyType(size_t key_size, CipherAlgorithm algorithm) : 
      key_size_(key_size), algorithm_(algorithm) {};
  
  size_t GetSize() const;
  CipherAlgorithm GetAlgorithm() const;
  std::string GetAlgorithmAsString() const;

 private:
  size_t key_size_;
  CipherAlgorithm algorithm_;
};

class Key {
 public:
  Key(size_t key_size, CipherAlgorithm algorithm, unsigned char* key);
  Key(cryptoapi::key_data_s* key_data, unsigned char* key);
  Key(const Key& other) :
      cipher_type_(other.cipher_type_),
      key_(other.key_ ? std::make_unique<std::vector<unsigned char>>(*other.key_) : nullptr) {}; 
  Key& operator=(const Key& other) = default;

  size_t GetSize() const;
  std::string GetAlgorithm() const;
  std::string GetCipherType() const;
  std::vector<unsigned char> GetKey() const;
  std::string GetKeyAsString() const;

  bool operator==(const Key& other) const;

  struct KeyHashFunction {
    size_t operator()(const Key& key) const;
  };

 private:
  KeyType cipher_type_;
  std::unique_ptr<std::vector<unsigned char>> key_;
};

} // namespace key_scanner

#endif  // KEY_H
