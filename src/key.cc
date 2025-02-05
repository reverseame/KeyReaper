#include "key.h"
#include <new>
#include <iostream>
#include <fstream>
#include <wincrypt.h>
#include <string>
#include <format>

#pragma comment(lib, "Crypt32.lib") // crypto api

using namespace std;
using namespace error_handling;

namespace key_scanner {
Key::Key(DWORD key_size, CipherAlgorithm algorithm, unsigned char* key) : cipher_type_(key_size, algorithm), key_() {
  
  try {
    key_ = make_unique<vector<unsigned char>>(vector<unsigned char>(key, key + cipher_type_.GetSize()));
    // cipher_type_ = KeyType(key_size, algorithm); // in initialization list
  
  } catch (const std::bad_alloc& e) {
    cout << "Key allocation failed: " << e.what() << endl;
    cipher_type_ = KeyType(kError, CipherAlgorithm::kError);
    key_ = nullptr;
  }
}

std::string Key::GetCipherType() const {
  string algo = cipher_type_.GetAlgorithmAsString();
  string key_size = to_string(cipher_type_.GetSize() * 8);

  return algo + " " + key_size;
}

vector<unsigned char> Key::GetKey() const {
  if (cipher_type_.GetAlgorithm() == CipherAlgorithm::kError) 
    return vector<unsigned char>();
  
  return *key_; // return a copy
}

string Key::GetKeyAsString() const {
  string key_string = string();

  for (BYTE byte : GetKey()) {
    // printf("%2X\n", byte);
    key_string.append(format("{:02X}", byte));
  }

  return key_string;
}

error_handling::ProgramResult Key::ExportKeyAsBinary(std::string out_file) { 
  ofstream file(out_file, std::ios::binary | std::ios::out);
  if (!file.is_open()) {
    return ErrorResult("Failed to open file: " + out_file);
  }

  // Write to the file
  file.write(reinterpret_cast<const char*>(GetKey().data()), GetSize());
  if (!file.good()) {
    return ErrorResult("Error writing to file: " + out_file);
  }

  file.close();
  return OkResult("Successfully exported key blob to " + out_file);
}

bool Key::operator==(const Key& other) const {
  if (this->GetAlgorithm() != other.GetAlgorithm()) return false;
  if (this->GetSize() != other.GetSize()) return false;

  return (this->GetKey() == other.GetKey());
}

DWORD KeyType::GetSize() const {
  return key_size_;
}

CipherAlgorithm KeyType::GetAlgorithm() const {
  return algorithm_;
}

std::string KeyType::GetAlgorithmAsString() const {
  auto algo = cipher_to_string.find(algorithm_);
  if (algo != cipher_to_string.end()) {
    return algo->second;
  } else {
    return "Unknown algorithm";
  }
}


size_t Key::KeyHashFunction::operator()(const std::shared_ptr<Key>& key) const {
  const std::vector<unsigned char> key_data = key->GetKey();
  if (key_data.empty()) {
    return 0;
  }

  size_t hash = std::hash<unsigned char>()(key_data[0]);
  for (size_t i = 1; i < key_data.size(); ++i) {
    hash = hash ^ std::hash<unsigned char>()(key_data[i]);
  }

  return hash;
}

bool Key::KeyHashFunction::operator()(const std::shared_ptr<Key>& lhs, const std::shared_ptr<Key>& rhs) const {
  if (!lhs || !rhs) return !lhs && !rhs; // Handle null pointers
  return *lhs == *rhs;
}


vector<BYTE> CrAPIKeyWrapper::GetParameter(DWORD parameter) {
  vector<BYTE> data_bytes;
  DWORD data_size = 0;

  // Get the size of the parameter
  if (!CryptGetKeyParam(
    key_handle_,
    parameter,
    NULL,
    &data_size, 0
  )) {
    return vector<BYTE>();
  }

  // Get the parameter itself
  data_bytes.resize(data_size);
  if (!CryptGetKeyParam(
    key_handle_,
    parameter,
    data_bytes.data(),
    &data_size, 0
  )) {
    return vector<BYTE>();
  }

  return data_bytes;
}

const WCHAR* GetCipherNameFromAlgID(ALG_ID alg) {
  const CRYPT_OID_INFO* poid_info = CryptFindOIDInfo(CRYPT_OID_INFO_ALGID_KEY, &(alg), 0);
  if (poid_info != NULL) {
    return poid_info->pwszName;
  } else return L"";
}

CryptoAPIKey::CryptoAPIKey(cryptoapi::key_data_s* key_data, unsigned char* key) {
  alg_id_ = key_data->alg;
  
  // Flag information can be found here: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey
  switch (alg_id_) {
  case CALG_AES_128:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kAES));
    break;

  case CALG_AES_192:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kAES));
    break;

  case CALG_AES_256:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kAES));
    break;

  case CALG_DES:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kDES));
    break;

  case CALG_3DES:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::k3DES));
    break;

  case CALG_3DES_112:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::k3DES));
    break;

  case CALG_RC2:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kRC2));
    break;
  
  case CALG_RC4:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kRC4));
    break;

  case CALG_RSA_KEYX:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kRSA));
    break;

  case CALG_RSA_SIGN:
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kRSA));
    break;

  default:
    printf("  [!] Algorithm not registered. ALG_ID: %X", alg_id_);
    SetCipherType(KeyType(key_data->key_size, CipherAlgorithm::kUnknown));
    wcout << GetCipherNameFromAlgID(alg_id_) << endl;
    break;
  }

  key_ = make_unique<vector<unsigned char>>(vector<unsigned char>(key, key + key_data->key_size));
}

bool CryptoAPIKey::IsSymmetricAlgorithm() {
  return ((GetALG_ID() & ALG_CLASS_DATA_ENCRYPT) == ALG_CLASS_DATA_ENCRYPT);
}

bool CryptoAPIKey::IsAsymmetricAlgorithm() {
  return ((GetALG_ID() & ALG_CLASS_KEY_EXCHANGE) == ALG_CLASS_KEY_EXCHANGE) ||
         ((GetALG_ID() & ALG_CLASS_SIGNATURE) == ALG_CLASS_SIGNATURE);
}

error_handling::ProgramResult CryptoAPIKey::ExportKeyAsBinary(std::string out_file) {
  if (IsSymmetricAlgorithm()) {
    printf(" [!] Symmetric algorithm detected. Exporting the key as PLAINTEXTKEYBLOB\n");
    return ExportAsBinaryGeneric(PLAINTEXTKEYBLOB, out_file + ".bin");
  
  } else if (IsAsymmetricAlgorithm()) {
    printf(" [!] An asymmetric key was detected. Since it's unkown whether it is the private or public pair, it will be exported in both formats\n");
    ProgramResult pr = ExportAsBinaryGeneric(PUBLICKEYBLOB, out_file + ".PUBK");
    if (pr.IsErr()) return pr;
    pr = ExportAsBinaryGeneric(PRIVATEKEYBLOB, out_file + ".PRIVK");
    if (pr.IsErr()) return pr;
    return OkResult("Both keys successfully exported");
  
  } else {
    return ErrorResult("Key type not recognized as symmetric or assymetric");
  }
}

ProgramResult CryptoAPIKey::ExportAsBinaryGeneric(BYTE blob_type, string out_file) {
  BLOBHEADER header;
  header.bType = blob_type;
  header.bVersion = CUR_BLOB_VERSION;
  header.reserved = 0;
  header.aiKeyAlg = alg_id_;

  DWORD dest_size = sizeof(BLOBHEADER) + GetSize();

  auto key_bytes = std::unique_ptr<BYTE[]>(new (std::nothrow) BYTE[dest_size]);
  if (!key_bytes)
    return ErrorResult("Could not allocate memory for the key");

  if (memcpy_s(key_bytes.get(), dest_size, &header, sizeof(BLOBHEADER)) != 0) {
    return ErrorResult("Error copying the BLOBHEADER into the allocated space");
  }
  if (memcpy_s(key_bytes.get() + sizeof(BLOBHEADER), dest_size - sizeof(BLOBHEADER), GetKey().data(), GetSize()) != 0) {
    return ErrorResult("Error copying the key data into the allocated space");
  }

  ofstream file(out_file, std::ios::binary | std::ios::out);
  if (!file.is_open()) {
    return ErrorResult("Failed to open file: " + out_file);
  }

  // Write to the file
  file.write(reinterpret_cast<const char *>(key_bytes.get()), dest_size);
  if (!file.good()) {
    return ErrorResult("Error writing to file: " + out_file);
  }

  file.close();
  return OkResult("Successfully exported key blob to " + out_file);
}

} // namespace key_scanner