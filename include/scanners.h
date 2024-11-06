#ifndef KEY_SCANNERS_H
#define KEY_SCANNERS_H

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

class CryptoAPIScan : public ScanStrategy {
 public:
  CryptoAPIScan() = default;
  std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const override;

  static void InitializeCryptoAPI();

 private:
  static bool cryptoapi_functions_initialized;
  static std::vector<uintptr_t> cryptoapi_functions;
  static HMODULE cryptoapi_base_address;
};

class RoundKeyScan : public ScanStrategy {
 public:
  RoundKeyScan() = default;
  std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const override;
};

class ScannerBuilder {
 public:
  ScannerBuilder() = default;

  void AddCryptoAPIScan();
  void AddRoundKeyScan();

  std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> GetScanners();

 private:
  bool do_structure_scan_ = false;
  bool do_round_key_scan_ = false;
};

} // namespace key_scanner

#endif