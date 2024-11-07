#ifndef KEYSCANNER_H
#define KEYSCANNER_H

#include <windows.h>
#include <unordered_set>
#include <memory>

#include "key.h"
#include "process_capturer.h"
#include "scanners.h"
#include "program_result.h"

namespace key_scanner {

enum class OnDestroyAction {
  kKillProcess,
  kPauseProcess,
  kResumeProcess,
  kDoNothing,
};

enum class PauseStrategy {
  NtPauseProcess,
  AllThreadPause,
};

class ScannerFacade {

 public:
  // Constructors and destructor
  ScannerFacade(int pid, ScannerVector strategies, OnDestroyAction on_destroy = OnDestroyAction::kPauseProcess);
  ~ScannerFacade();

  // Proxy methods for handling the process
  error_handling::ProgramResult KillProcess(UINT exit_code = 0);
  error_handling::ProgramResult PauseProcess(PauseStrategy strategy, bool force_pause = false);
  error_handling::ProgramResult ResumeProcess(bool force_resume = false);

  // Query
  bool IsProcessAlive() const;
  std::unordered_set<Key, Key::KeyHashFunction> DoScan();
  std::unordered_set<Key, Key::KeyHashFunction> GetKeys();  
  error_handling::ProgramResult ExportKeysToJSON(std::string output_json);

 private:
  void AddKeys(std::unordered_set<Key, Key::KeyHashFunction> keys);

  process_manipulation::ProcessCapturer capturer_;
  ScannerVector scanners_;
  std::unordered_set<Key, Key::KeyHashFunction> keys_;
  OnDestroyAction on_destroy_;
  DWORD pid_;
};

} // namespace key_scanner

#endif
