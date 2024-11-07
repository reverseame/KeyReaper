#ifndef KEY_SCANNERS_H
#define KEY_SCANNERS_H

#include "key.h"
#include "process_capturer.h"
#include <vector>
#include <memory>
#include <unordered_set>
#include <iostream>

namespace key_scanner {

// abstract
class ScanStrategy {
 public:
  virtual ~ScanStrategy() = default;
  virtual std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const = 0;

  // iostream output
  virtual void print(std::ostream& os) const { os << "Unnamed scanner"; };
  friend std::ostream& operator<<(std::ostream& os, const ScanStrategy& scanner) { scanner.print(os); return os; };
};

class CryptoAPIScan : public ScanStrategy {
 public:
  CryptoAPIScan() = default;
  std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const override;

  static void InitializeCryptoAPI();
  void print(std::ostream& os) const override { os << "CryptoAPI Key Scanner"; };

 private:
  static bool cryptoapi_functions_initialized;
  static std::vector<uintptr_t> cryptoapi_functions;
  static HMODULE cryptoapi_base_address;
};

class RoundKeyScan : public ScanStrategy {
 public:
  RoundKeyScan() = default;
  std::unordered_set<key_scanner::Key, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapInformation heap_info) const override;

  void print(std::ostream& os) const override { os << "AES Round Key Scanner"; };
};

class ScannerVector {
 public:
  explicit ScannerVector(std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> strategies);

  // To allow iterators
  auto begin() { return scanners_->begin(); }
  auto end() { return scanners_->end(); }
  auto begin() const { return scanners_->begin(); }
  auto end() const { return scanners_->end(); }

 private:
  std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> scanners_;
};

class ScannerBuilder {
 public:
  ScannerBuilder() = default;

  void AddCryptoAPIScan();
  void AddRoundKeyScan();

  ScannerVector GetScanners();

 private:
  bool do_structure_scan_ = false;
  bool do_round_key_scan_ = false;
};

} // namespace key_scanner

#endif