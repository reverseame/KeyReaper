#include "key.h"
#include <new>
#include <iostream>

using namespace std;

namespace key_scanner {
Key::Key(KeySize key_size, CipherAlgorithm algorithm, unsigned char* key) : cipher_type_(key_size, algorithm), key_() {
  
  try {
    key_ = make_unique<vector<unsigned char>>(vector<unsigned char>(key, key + cipher_type_.GetSize()));
    // cipher_type_ = KeyType(key_size, algorithm); // in initialization list
  
  } catch (const std::bad_alloc& e) {
    cout << "Key allocation failed: " << e.what() << endl;
    cipher_type_ = KeyType(KeySize::kError, CipherAlgorithm::kError);
    key_ = nullptr;
  }
}

Key::Key(cryptoapi::key_data_s *key_data, unsigned char* key) : 
    cipher_type_(KeySize::kError, CipherAlgorithm::kError), key_() {

  switch (key_data->alg) {
  case CALG_AES_128:
    // Flag information can be found here: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey
    printf(" Detected Windows CryptoAPI - AES 128 algorithm\n");
    cipher_type_ = KeyType(KeySize::k128, CipherAlgorithm::kAES);
    key_ = make_unique<vector<unsigned char>>(vector<unsigned char>(key, key + key_data->key_size));
    // TODO: key
    break;

  case CALG_AES_256:
    cipher_type_ = KeyType(KeySize::k256, CipherAlgorithm::kAES);
    // TODO: key
    break;
  
  default:
    // specified in the constructor initialization list
    // cipher_type_ = KeyType(KeySize::kError, CipherAlgorithm::kError);
    key = nullptr;
    break;
  }
}

size_t Key::GetSize() const {
  return cipher_type_.GetSize();
}

vector<unsigned char> Key::GetKey() const {
  if (cipher_type_.GetAlgorithm() == CipherAlgorithm::kError) return vector<unsigned char>();

  return *key_; // return a copy
}

bool Key::operator==(const Key &other) const {

  if (this->GetSize() != other.GetSize()) return false;

  return (this->GetKey() == other.GetKey());

}

std::size_t KeyType::GetSize() const {
  return static_cast<std::size_t>(key_size_);
}

CipherAlgorithm KeyType::GetAlgorithm() const {
  return algorithm_;
}

size_t Key::KeyHashFunction::operator()(const Key &key) const {
  const vector<unsigned char> key_data = key.GetKey();

  size_t hash = std::hash<unsigned char>()(key_data[0]);
  for (size_t i = 1; key_data.size(); i++) {
    hash = hash ^ std::hash<unsigned char>()(key_data[i]);
  }
  return hash;
}

} // namespace key_scanner