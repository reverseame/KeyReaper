#ifndef KEY_H
#define KEY_H

#include <nlohmann/json.hpp>

#include <string>
#include <unordered_map>
#include <cstddef>
#include <memory>
#include <vector>
#include <optional>
#include <windows.h>
#include <wincrypt.h>
#include "cryptoapi.h"

#include "program_result.h"

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

  /**
   * Returns the size of the whole structure
   */
  DWORD size() {
    if (dwKeySize == 0) return 0;
    return dwKeySize + sizeof(BLOBHEADER) + sizeof(DWORD);
  }

  DWORD key_size() {
    return dwKeySize;
  }

  BYTE* key_bytes() {
    return rgbKeyData;
  }

  BLOBHEADER hdr;
  DWORD dwKeySize;
  BYTE rgbKeyData[PLAINTEXTKEYBLOB_MAX_SIZE_BYTES];
};

size_t const kError = 0;
enum class CipherAlgorithm { kError, kUnknown, kAES, kRSA, kRC2, kRC4, kDES, k3DES, kSalsa20 };

const std::unordered_map<CipherAlgorithm, std::string> cipher_to_string = {
  { CipherAlgorithm::kError, "Error" },
  { CipherAlgorithm::kUnknown, "Unknown" },
  { CipherAlgorithm::kAES, "AES" },
  { CipherAlgorithm::kRSA, "RSA" },
  { CipherAlgorithm::kRC2, "RC2" },
  { CipherAlgorithm::kRC4, "RC4" },
  { CipherAlgorithm::kDES, "DES" },
  { CipherAlgorithm::k3DES, "3DES" },
  { CipherAlgorithm::kRSA, "RSA" },
};

const WCHAR* GetCipherNameFromAlgID(ALG_ID alg);

class KeyType {
 public:
  KeyType(DWORD key_size, CipherAlgorithm algorithm) :
      key_size_(key_size), algorithm_(algorithm) {};
  
  DWORD GetSize() const;
  CipherAlgorithm GetAlgorithm() const;
  std::string GetAlgorithmAsString() const;

 private:
  DWORD key_size_;
  CipherAlgorithm algorithm_;
};

class Key {
 public:
  Key() : cipher_type_(kError, CipherAlgorithm::kError), key_() {};
  Key(DWORD key_size, CipherAlgorithm algorithm, unsigned char* key);
  Key(const Key& other) :
      cipher_type_(other.cipher_type_),
      key_(other.key_ ? std::make_unique<std::vector<unsigned char>>(*other.key_) : nullptr) {}; 
  Key& operator=(const Key& other) = default;

  DWORD GetSize() const { return cipher_type_.GetSize(); };
  std::string GetAlgorithm() const { return cipher_type_.GetAlgorithmAsString(); };
  std::string GetCipherType() const;
  virtual std::vector<unsigned char> GetKey() const;
  virtual std::string GetKeyAsString() const;

  virtual error_handling::ProgramResult ExportKeyAsBinary(std::string out_file);
  virtual nlohmann::json GetKeyAsJSON() const;

  bool operator==(const Key& other) const;

  struct KeyHashFunction {
    size_t operator()(const std::shared_ptr<Key>& key) const;
    bool operator()(const std::shared_ptr<Key>& lhs, const std::shared_ptr<Key>& rhs) const;
  };

 protected:
  void SetCipherType(KeyType type) { cipher_type_ = type; };
  KeyType cipher_type_;
  std::unique_ptr<std::vector<unsigned char>> key_;
};

class CryptoAPIKey : public Key {
 public:
  CryptoAPIKey(ALG_ID alg, DWORD key_size, unsigned char* key, HCRYPTKEY oringial_handle);
  CryptoAPIKey(cryptoapi::RSAENH_CRYPTKEY* key_data, unsigned char* key, HCRYPTKEY oringial_handle);
  ALG_ID GetALG_ID() const;
  HCRYPTKEY GetOriginalHandle() const;
  bool IsSymmetricAlgorithm();
  bool IsAsymmetricAlgorithm();

  error_handling::ProgramResult ExportKeyAsBinary(std::string out_file) override;
  nlohmann::json GetKeyAsJSON() const override;

  bool operator==(const CryptoAPIKey& other) const;

 private:
  ALG_ID alg_id_;
  HCRYPTKEY original_handle_;
  error_handling::ProgramResult ExportAsBinaryGeneric(BYTE blob_type, std::string out_file);
};

class CrAPIKeyWrapper {
 public:
  CrAPIKeyWrapper(HCRYPTKEY key_handle) : key_handle_(key_handle), algorithm_(0) {};
  std::vector<BYTE> GetSalt() {
    if (!salt_.has_value()) 
      salt_ = GetParameter(KP_SALT);
    return salt_.value();
  };

  ALG_ID GetAlgorithm() {
    if (algorithm_ == 0) {
      algorithm_ = *reinterpret_cast<ALG_ID*>(GetParameter(KP_ALGID).data());
    }
    return algorithm_;
  };

 protected:
  std::vector<BYTE> GetParameter(DWORD parameter);

 private:
  HCRYPTKEY key_handle_;
  std::optional<std::vector<BYTE>> salt_;
  ALG_ID algorithm_;
};

class CrAPIAESKeyWrapper : public CrAPIKeyWrapper {
 public:
  CrAPIAESKeyWrapper(HCRYPTKEY key_handle) : CrAPIKeyWrapper(key_handle) {};
  std::vector<BYTE> GetIV() {
    if (!initialization_vector_.has_value()) 
      initialization_vector_ = GetParameter(KP_IV);
    return initialization_vector_.value();
  };
  std::vector<BYTE> GetPadding() {
    if (!padding_.has_value()) 
      padding_ = GetParameter(KP_PADDING);
    return padding_.value();
  };
  std::vector<BYTE> GetMode() {
    if (!mode_.has_value()) 
      mode_ = GetParameter(KP_MODE);
    return mode_.value();
  };

 private:
  std::optional<std::vector<BYTE>> initialization_vector_;
  std::optional<std::vector<BYTE>> padding_;
  std::optional<std::vector<BYTE>> mode_;
};

} // namespace key_scanner

#endif  // KEY_H
