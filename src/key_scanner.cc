#include "key_scanner.h"
#include <iostream>

// JSON
#include <nlohmann/json.hpp>
#include <fstream>

using namespace std;
using namespace error_handling;
using namespace process_manipulation;

namespace key_scanner {

// Proxy method
ProgramResult ScannerFacade::KillProcess(UINT exit_code) {
  return capturer_.KillProcess(exit_code);
}

// Proxy method
ProgramResult ScannerFacade::PauseProcess(PauseStrategy strategy, bool force_pause) {
  switch (strategy) {
  case PauseStrategy::AllThreadPause:
    return capturer_.PauseProcess(force_pause);
  
  case PauseStrategy::NtPauseProcess:
    return capturer_.PauseProcessNt(force_pause);
  
  default:
    return ErrorResult("Invalid pause strategy");
  }
}

// Proxy method
ProgramResult ScannerFacade::ResumeProcess(bool force_resume) {
    return capturer_.ResumeProcess(force_resume);
}

bool ScannerFacade::IsProcessAlive() const {
  return capturer_.IsProcessAlive();
}

std::unordered_set<Key, Key::KeyHashFunction> ScannerFacade::DoScan() {

  // Main functionality
  // Capture memory and pass it to the analyzers

  vector<HeapInformation> heaps;
  ProgramResult r = capturer_.EnumerateHeaps(&heaps);
  cout << r.GetResultInformation() << endl;
  if (!r.IsOk()) {
    cout << GetLastErrorAsString() << endl;
  }

  printf("[i] Key count: %u\n\n", keys_.size());

  for (const auto& scanner : scanners_) {
    //scanner->Scan();
    cout << scanner << endl;
  }

  return keys_;
}

std::unordered_set<Key, Key::KeyHashFunction> ScannerFacade::GetKeys() {
  return keys_;
}

ProgramResult ScannerFacade::ExportKeysToJSON(string output_json) {
  if (keys_.empty()) return ErrorResult("No keys were recovered");

  cout << "[i] Exporting keys to " << output_json << ".json" << endl;
  nlohmann::json json_data;
  for (auto &key : keys_) {
    json_data[key.GetKeyAsString()] = { {"algorithm", key.GetAlgorithm()}, {"size", key.GetSize()} };
  }

  ofstream file(output_json);
  file << json_data.dump(2);  // Pretty print
  file.close();

  return OkResult("Exported keys to: " + output_json);
}

void ScannerFacade::AddKeys(std::unordered_set<Key, Key::KeyHashFunction> keys) {
  keys_.merge(keys);
}

ScannerFacade::ScannerFacade(int pid, ScannerVector strategies, OnDestroyAction on_destroy) 
    : pid_(pid), scanners_(move(strategies)), on_destroy_(on_destroy), capturer_(ProcessCapturer(pid)), keys_() {
  
}

ScannerFacade::~ScannerFacade() {
  if (on_destroy_ != OnDestroyAction::kDoNothing) {
    ProgramResult pr =
        (on_destroy_ == OnDestroyAction::kKillProcess) ? capturer_.KillProcess() : (on_destroy_ == OnDestroyAction::kPauseProcess)  ? capturer_.PauseProcess()
                                                                                 : (on_destroy_ == OnDestroyAction::kResumeProcess) ? capturer_.ResumeProcess()
                                                                                                                                    : ErrorResult("Invalid destroy option");

    cout << pr.GetResultInformation() << endl;
  }
}

} // namespace key_scanner
