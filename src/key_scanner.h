#ifndef KEYSCANNER_H
#define KEYSCANNER_H

#include <Windows.h>
#include <unordered_set>

#include "key.h"
#include "process_capturer.h"

namespace key_scanner {

class KeyScanner {

 public:

  // Constructors and destructor
  KeyScanner(int pid, unsigned int stride, std::vector<ScanStrategy> strategies, OnDestroyAction on_destroy = OnDestroyAction::kPauseProcess);
  ~KeyScanner();

  // Proxy methods for handling the process
  error_handling::ProgramResult KillProcess(UINT exit_code = 0);
  error_handling::ProgramResult PauseProcess(bool force_pause = false);
  error_handling::ProgramResult ResumeProcess(bool force_resume = false);

  // Query
  std::unordered_set<Key> GetKeys();

 private:
  void AddKeys(std::unordered_set<Key> keys);

  process_manipulation::ProcessCapturer capturer_;
  std::vector<ScanStrategy> strategies_;
  std::unordered_set<Key> keys_;
  OnDestroyAction on_destroy_;
  unsigned int stride_;
  DWORD pid_;
};

// abstract
class ScanStrategy {
  virtual ~ScanStrategy() = default;
  virtual std::unordered_set<Key> Scan(unsigned char* buffer, size_t buffer_size) const = 0;
};

class StructureScan : ScanStrategy {
  std::unordered_set<Key> Scan(unsigned char* buffer, size_t buffer_size) const override;
};

class RoundKeyScan : ScanStrategy {
  std::unordered_set<Key> Scan(unsigned char* buffer, size_t buffer_size) const override;
};

enum class OnDestroyAction {
  kKillProcess,
  kResumeProcess,
  kPauseProcess,
};

} // namespace key_scanner

#endif
