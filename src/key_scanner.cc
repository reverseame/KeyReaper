#include "key_scanner.h"
#include <iostream>

using namespace std;

namespace key_scanner {

// Proxy method
error_handling::ProgramResult KeyScanner::KillProcess(UINT exit_code) {
  return capturer_.KillProcess(exit_code);
}

// Proxy method
error_handling::ProgramResult KeyScanner::PauseProcess(bool force_pause) {
    return capturer_.PauseProcess(force_pause);
}

// Proxy method
error_handling::ProgramResult KeyScanner::ResumeProcess(bool force_resume) {
    return capturer_.ResumeProcess(force_resume);
}

std::unordered_set<Key> KeyScanner::GetKeys() {
    return keys_;
}

void KeyScanner::AddKeys(std::unordered_set<Key> keys) {
  keys_.merge(keys);
}

KeyScanner::KeyScanner(int pid, unsigned int stride, std::vector<ScanStrategy> strategies, OnDestroyAction on_destroy) 
    : pid_(pid), stride_(stride), strategies_(strategies), capturer_(pid), on_destroy_(on_destroy) { 
}

KeyScanner::~KeyScanner() {

  error_handling::ProgramResult pr = 
    (on_destroy_ == OnDestroyAction::kKillProcess) ? capturer_.KillProcess() :
    (on_destroy_ == OnDestroyAction::kPauseProcess) ? capturer_.PauseProcess() :
    (on_destroy_ == OnDestroyAction::kResumeProcess) ? capturer_.ResumeProcess() :
    error_handling::ProgramResult::ProgramResult(error_handling::ProgramResult::ResultType::kError, "Invalid destroy option");

  cout << pr.GetResultInformation() << endl;
}

} // namespace key_scanner
