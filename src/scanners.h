#include "key.h"
#include "process_capturer.h"
#include <vector>
#include <memory>
#include <unordered_set>

namespace key_scanner {

// abstract
class ScanStrategy {
 public:
  virtual ~ScanStrategy() = default;
  virtual std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const = 0;
};

class StructureScan : public ScanStrategy {
 public:
  StructureScan() = default;
  std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const override;
};

class RoundKeyScan : public ScanStrategy {
 public:
  RoundKeyScan() = default;
  std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const override;
};

class StrategyBuilder {
 public:
  StrategyBuilder() = default;

  void AddStructureScan();
  void AddRoundKeyScan();

  std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> GetScanners();

 private:
  bool do_structure_scan_ = false;
  bool do_round_key_scan_ = false;
};

namespace cryptoapi {

#define CPGENKEY_ADDRESS 0x000050C0u
#define CPDERIVEKEY_ADDRESS 0x0001AD90u
#define CPDESTROYKEY_ADDRESS 0x000086C0u
#define CPSETKEYPARAM_ADDRESS 0x0001C770u
#define CPGETKEYPARAM_ADDRESS 0x000098C0u
#define CPEXPORTKEY_ADDRESS 0x00004C40u
#define CPIMPORTKEY_ADDRESS 0x00006290u
#define CPENCRYPT_ADDRESS 0x00019880u
#define CPDECRYPT_ADDRESS 0x0000A500u
#define CPDUPLICATEKEY_ADDRESS 0x0001B5C0u

#define MAGIC_CONSTANT 0xE35A172C

const std::vector<unsigned int> cryptoapi_offsets = {
  CPGENKEY_ADDRESS, CPDERIVEKEY_ADDRESS, CPDESTROYKEY_ADDRESS, 
  CPSETKEYPARAM_ADDRESS, CPGETKEYPARAM_ADDRESS, CPEXPORTKEY_ADDRESS,
  CPIMPORTKEY_ADDRESS, CPENCRYPT_ADDRESS, CPDECRYPT_ADDRESS,
  CPDUPLICATEKEY_ADDRESS
};

struct key_data_s {
  void *unknown; // XOR-ed
  ALG_ID alg;
  uint32_t flags;
  uint32_t key_size;
  void* key_bytes;
};

struct magic_s {
  key_data_s *key_data;
};

struct HCRYPTKEY {
  void* CPGenKey;
  void* CPDeriveKey;
  void* CPDestroyKey;
  void* CPSetKeyParam;
  void* CPGetKeyParam;
  void* CPExportKey;
  void* CPImportKey;
  void* CPEncrypt;
  void* CPDecrypt;
  void* CPDuplicateKey;
  HCRYPTPROV hCryptProv;
  magic_s *magic; // XOR-ed
};

} // namespace cryptoapi
} // namespace key_scanner