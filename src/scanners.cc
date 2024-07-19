#include <memory>

#include "key.h"
#include "scanners.h"

using namespace std;

namespace key_scanner {

void StrategyBuilder::AddStructureScan() {
  do_structure_scan_ = true;
}

void StrategyBuilder::AddRoundKeyScan() {
  do_round_key_scan_ = true;
}

unique_ptr<vector<unique_ptr<ScanStrategy>>> StrategyBuilder::GetScanners() {

  unique_ptr<vector<unique_ptr<ScanStrategy>>> strategies = make_unique<vector<unique_ptr<ScanStrategy>>>();

  if (do_round_key_scan_) {
    RoundKeyScan s = RoundKeyScan();
    strategies->push_back(make_unique<RoundKeyScan>(s));
  }

  if (do_structure_scan_) {
    StructureScan s = StructureScan();
    strategies->push_back(make_unique<StructureScan>(s));
  }

  return strategies;
}

std::unordered_set<Key, Key::KeyHashFunction> StructureScan::Scan(unsigned char *buffer, size_t buffer_size) const {
  return std::unordered_set<Key, Key::KeyHashFunction>();
}

std::unordered_set<Key, Key::KeyHashFunction> RoundKeyScan::Scan(unsigned char *buffer, size_t buffer_size) const {
  return std::unordered_set<Key, Key::KeyHashFunction>();
}

} // namespace key_scanner