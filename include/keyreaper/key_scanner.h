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
  error_handling::ProgramResult PauseProcess(PauseStrategy strategy, std::vector<DWORD> excluded_tids = std::vector<DWORD>(), bool force_pause = false);
  error_handling::ProgramResult ResumeProcess(bool force_resume = false);

  // Query
  bool IsProcessAlive() const;
  std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> DoScan(bool extended_search_enabled);
  std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> GetKeys();  
  error_handling::ProgramResult ExportKeysToJSON(std::string output_json);
  error_handling::ProgramResult ExportKeysToBinary();

  // Strategies
  void AddScanners(ScannerVector scanners);

  bool StressTest(UINT runs, UINT expected_num_of_keys);

 private:
  void AddKeys(std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> keys);

  process_manipulation::ProcessCapturer capturer_;
  ScannerVector scanners_;
  std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> keys_;
  OnDestroyAction on_destroy_;
  DWORD pid_;
};

} // namespace key_scanner

#endif
