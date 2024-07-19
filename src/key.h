#ifndef KEY_H
#define KEY_H

#include <cstddef>
namespace key_scanner {

enum class KeySize : size_t { kError = 0, k128 = 16, k256 = 32 };
enum class CipherAlgorithm { kError, kAES, kRSA };

class KeyType {
 public:
  KeyType(KeySize key_size, CipherAlgorithm algorithm) : 
      key_size_(key_size), algorithm_(algorithm) {};
  
  [[nodiscard]] size_t GetSize() const;
  [[nodiscard]] CipherAlgorithm GetAlgorithm() const;

 private:
  KeySize key_size_;
  CipherAlgorithm algorithm_;
};

class Key {
 public:
  Key(KeySize key_size, CipherAlgorithm algorithm);
  ~Key();

  [[nodiscard]] size_t GetSize() const;
  [[nodiscard]] unsigned char* GetKey() const;

  bool operator==(const Key& other) const;

  struct KeyHashFunction {
    size_t operator()(const Key& key) const;
  };

 private:
  KeyType cipher_type_;
  unsigned char* key_;
};

} // namespace key_scanner

#endif
