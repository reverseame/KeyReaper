#include "key.h"
#include <new>
#include <iostream>
#include <wincrypt.h>
#include <string>

#include <locale>
#include <codecvt>

#pragma comment(lib, "Crypt32.lib") // crypto api

using namespace std;

namespace key_scanner {
Key::Key(size_t key_size, CipherAlgorithm algorithm, unsigned char* key) : cipher_type_(key_size, algorithm, ""), key_() {
  
  try {
    key_ = make_unique<vector<unsigned char>>(vector<unsigned char>(key, key + cipher_type_.GetSize()));
    // cipher_type_ = KeyType(key_size, algorithm); // in initialization list
  
  } catch (const std::bad_alloc& e) {
    cout << "Key allocation failed: " << e.what() << endl;
    cipher_type_ = KeyType(kError, CipherAlgorithm::kError, "Error");
    key_ = nullptr;
  }
}

Key::Key(cryptoapi::key_data_s *key_data, unsigned char* key) : 
    cipher_type_(kError, CipherAlgorithm::kError, "Unknown"), key_() {

  switch (key_data->alg) {
  case CALG_AES_128:
    // Flag information can be found here: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey
    printf(" Detected Windows CryptoAPI - AES 128 algorithm\n");
    cipher_type_ = KeyType(key_data->key_size, CipherAlgorithm::kAES, "AES");
    break;

  case CALG_AES_256:
    printf(" Detected Windows CryptoAPI - AES 256 algorithm\n");
    cipher_type_ = KeyType(key_data->key_size, CipherAlgorithm::kAES, "AES");
    break;
  
  case CALG_RC4:
    printf(" Detected Windows CryptoAPI - RC4 algorithm\n");
    cipher_type_ = KeyType(key_data->key_size, CipherAlgorithm::kRC4, "RC4");
    break;
  default:
    // specified in the constructor initialization list
    // cipher_type_ = KeyType(KeySize::kError, CipherAlgorithm::kError);
    printf(" Detected Windows CryptoAPI - Key data copied.\n");
    printf("  > ALG_ID: %X", key_data->alg);
    
    const CRYPT_OID_INFO* poid_info = CryptFindOIDInfo(CRYPT_OID_INFO_ALGID_KEY, &(key_data->alg), 0);
    if (poid_info != NULL) {
      wcout << " (" << poid_info->pwszName << ")" << endl;
      // std::wstring ws = poid_info->pwszName;
      using convert_type = std::codecvt_utf8<wchar_t>;
      std::wstring_convert<convert_type, wchar_t> converter;
      
      // string s = WideCharToMultiByte(
        //CP_UTF8, WC_COMPOSITECHECK,
        //poid_info->pwszName, -1, NULL, );
      cipher_type_ = KeyType(key_data->key_size, CipherAlgorithm::kUnknown, converter.to_bytes( poid_info->pwszName ));

    } else {
      cipher_type_ = KeyType(key_data->key_size, CipherAlgorithm::kUnknown, "Unkown");
      printf("\n");
    }
    
    break;
  }

  key_ = make_unique<vector<unsigned char>>(vector<unsigned char>(key, key + key_data->key_size));
}

size_t Key::GetSize() const {
  return cipher_type_.GetSize();
}

std::string Key::GetType() const {
  string algo = cipher_type_.GetAlgorithmAsString();
  string key_size = to_string(cipher_type_.GetSize() * 8);

  return algo + " " + key_size;
}

vector<unsigned char> Key::GetKey() const {
  if (cipher_type_.GetAlgorithm() == CipherAlgorithm::kError) 
    return vector<unsigned char>();
  
  return *key_; // return a copy
}

bool Key::operator==(const Key &other) const {

  if (this->GetSize() != other.GetSize()) 
    return false;

  return (this->GetKey() == other.GetKey());

}

std::size_t KeyType::GetSize() const {
  return static_cast<std::size_t>(key_size_);
}

CipherAlgorithm KeyType::GetAlgorithm() const {
  return algorithm_;
}

std::string KeyType::GetAlgorithmAsString() const {
  return algorithm_str_;
}


size_t Key::KeyHashFunction::operator()(const Key &key) const {
  const vector<unsigned char> key_data = key.GetKey();
  if (key_data.empty()) {
    return 0;
  }

  size_t hash = std::hash<unsigned char>()(key_data[0]);
  for (size_t i = 1; i < key_data.size(); ++i) {
    hash = hash ^ std::hash<unsigned char>()(key_data[i]);
  }
  return hash;
}

} // namespace key_scanner