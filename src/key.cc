#include "key.h"
#include <new>
#include <iostream>

using namespace std;

namespace key_scanner {
Key::Key(KeySize key_size, CipherAlgorithm algorithm) : cipher_type_(key_size, algorithm) {
  
  try {
    key_ = new unsigned char[cipher_type_.GetSize()];
    cipher_type_ = KeyType(key_size, algorithm);
  
  } catch (const std::bad_alloc& e) {
    cout << "Key allocation failed" << endl;
    key_ = nullptr;
    cipher_type_ = KeyType(KeySize::kError, CipherAlgorithm::kError);
  }
}

Key::~Key() {
  if (cipher_type_.GetAlgorithm() != CipherAlgorithm::kError) {
    delete[] key_;
  }
}

size_t Key::GetSize() const {
  return cipher_type_.GetSize();
}

unsigned char *Key::GetKey() const {
  return key_;
}

bool Key::operator==(const Key &other) const {
  size_t this_size = this->GetSize();
    size_t other_size = other.GetSize();

    if (this_size != other_size) return false;

    unsigned char* key1 = this->GetKey();
    unsigned char* key2 = other.GetKey();

    for (size_t i = 0; i < this_size; i++) {
      if (key1[i] != key2[i]) {
        return false;
      }
    }
    return true;
}

std::size_t KeyType::GetSize() const {
  return static_cast<std::size_t>(key_size_);
}

CipherAlgorithm KeyType::GetAlgorithm() const {
  return algorithm_;
}

size_t Key::KeyHashFunction::operator()(const Key &key) const
{
  unsigned char* key_data = key.GetKey();

  size_t hash = std::hash<unsigned char>()(key_data[0]);
  for (size_t i = 1; key.GetSize(); i++) {
    hash = hash ^ std::hash<unsigned char>()(key_data[i]);
  }
  return hash;
}

} // namespace key_scanner