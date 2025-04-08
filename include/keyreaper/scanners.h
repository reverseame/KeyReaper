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
  virtual std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapSegment heap_info, process_manipulation::ProcessCapturer& capturer) const = 0;

  // iostream output
  virtual std::string GetName() const { return "Unnamed scanner"; };

 protected:
  void SetPid(DWORD pid) { pid_ = pid; };
  DWORD pid_;
};

class CryptoAPIScan : public ScanStrategy {
 public:
  CryptoAPIScan() = default;
  std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapSegment heap_info, process_manipulation::ProcessCapturer& capturer) const override;

  static void InitializeCryptoAPI();
  static std::vector<BYTE> GetCryptoAPIFunctions();
  static std::unordered_set<HCRYPTKEY> GetHCRYPTKEYs(unsigned char* input_buffer, process_manipulation::HeapSegment heap_info);
  std::string GetName() const override { return "CryptoAPI Key Scanner"; };

 private:
  static bool cryptoapi_functions_initialized;
  static std::vector<uintptr_t> cryptoapi_functions;
  static HMODULE cryptoapi_base_address;
};

class RoundKeyScan : public ScanStrategy {
 public:
  RoundKeyScan() = default;
  std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> Scan(unsigned char* input_buffer, process_manipulation::HeapSegment heap_info, process_manipulation::ProcessCapturer& capturer) const override;

  std::string GetName() const override { return "AES Round Key Scanner"; };
};

class ScannerVector {
 public:
  explicit ScannerVector(std::unique_ptr<std::vector<std::unique_ptr<ScanStrategy>>> scanners);
  explicit ScannerVector() : scanners_(std::make_unique<std::vector<std::unique_ptr<ScanStrategy>>>()) {};

  // To allow iterators
  auto& front() { return scanners_->front(); }
  auto begin() { return scanners_->begin(); }
  auto end() { return scanners_->end(); }
  auto begin() const { return scanners_->begin(); }
  auto end() const { return scanners_->end(); }
  size_t size() const { return scanners_->size(); }
  void clear() { scanners_->clear(); }
  void push_back(std::unique_ptr<ScanStrategy> scanner) { scanners_->push_back(std::move(scanner)); }

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
  bool do_crapi_structure_scan_ = false;
  bool do_round_key_scan_ = false;
};

} // namespace key_scanner

#endif