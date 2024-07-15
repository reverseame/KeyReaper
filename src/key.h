#ifndef KEY_H
#define KEY_H

enum class KeySize { k128, k256 };
enum class CipherAlgorithm { kAes, kRsa };

namespace key_scanner {
class KeyType {
 private:
  KeySize key_size_;
  CipherAlgorithm algorithm_;
};

class Key {
 private:
  KeyType cipher_type_;
  unsigned char* key_;
};

} // namespace key_scanner

#endif
