#include "key.h"
#include <vector>
#include <memory>
#include <unordered_set>

namespace key_scanner {

// abstract
class ScanStrategy {
 public:
  virtual ~ScanStrategy() = default;
  virtual std::unordered_set<Key, Key::KeyHashFunction> Scan(unsigned char* buffer, size_t buffer_size) const = 0;
};

class StructureScan : public ScanStrategy {
 public:
  StructureScan() = default;
  std::unordered_set<Key, Key::KeyHashFunction> Scan(unsigned char* buffer, size_t buffer_size) const override;
};

class RoundKeyScan : public ScanStrategy {
 public:
  RoundKeyScan() = default;
  std::unordered_set<Key, Key::KeyHashFunction> Scan(unsigned char* buffer, size_t buffer_size) const override;
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
} // namespace key_scanner