#ifndef KEYSCANNER_H
#define KEYSCANNER_H

#include <Windows.h>
#include <unordered_set>

#include "key.h"
#include "process_capturer.h"
#include "scanners.h"

namespace key_scanner {

enum class OnDestroyAction {
  kKillProcess,
  kPauseProcess,
  kResumeProcess,
};

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
  std::unordered_set<Key, Key::KeyHashFunction> DoScan();

 private:
  void AddKeys(std::unordered_set<Key, Key::KeyHashFunction> keys);

  process_manipulation::ProcessCapturer capturer_;
  std::vector<ScanStrategy> strategies_;
  std::unordered_set<Key, Key::KeyHashFunction> keys_;
  OnDestroyAction on_destroy_;
  unsigned int stride_;
  DWORD pid_;
};

} // namespace key_scanner

#endif
