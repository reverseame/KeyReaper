#ifndef KEY_H
#define KEY_H

#include <string>
#include <cstddef>
#include <memory>
#include <vector>
#include "cryptoapi.h"

namespace key_scanner {

size_t const kError = 0;
enum class CipherAlgorithm { kError, kUnknown, kAES, kRSA, kRC4 };

class KeyType {
 public:
  KeyType(size_t key_size, CipherAlgorithm algorithm, std::string algorithm_str) : 
      key_size_(key_size), algorithm_(algorithm),
      algorithm_str_(algorithm_str) {};
  
  size_t GetSize() const;
  CipherAlgorithm GetAlgorithm() const;
  std::string GetAlgorithmAsString() const;

 private:
  size_t key_size_;
  CipherAlgorithm algorithm_;
  std::string algorithm_str_;
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
  std::string GetType() const;
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
