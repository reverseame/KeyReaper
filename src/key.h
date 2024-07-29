#ifndef KEY_H
#define KEY_H

#include <cstddef>
#include <memory>
#include <vector>
#include "cryptoapi.h"

namespace key_scanner {

enum class KeySize : size_t { kError = 0, k128 = 16, k256 = 32 };
enum class CipherAlgorithm { kError, kAES, kRSA };

class KeyType {
 public:
  KeyType(KeySize key_size, CipherAlgorithm algorithm) : 
      key_size_(key_size), algorithm_(algorithm) {};
  
  size_t GetSize() const;
  CipherAlgorithm GetAlgorithm() const;

 private:
  KeySize key_size_;
  CipherAlgorithm algorithm_;
};

class Key {
 public:
  Key(KeySize key_size, CipherAlgorithm algorithm, unsigned char* key);
  Key(cryptoapi::key_data_s* key_data, unsigned char* key);
  Key(const Key& other) :
      cipher_type_(other.cipher_type_),
      key_(other.key_ ? std::make_unique<std::vector<unsigned char>>(*other.key_) : nullptr) {}; 
  Key& operator=(const Key& other) = default;

  size_t GetSize() const;
  std::vector<unsigned char> GetKey() const;

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
