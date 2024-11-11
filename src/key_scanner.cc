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
  if (scanners_.size() == 0) {
    printf(" [x] No scanner selected\n");
    return keys_;
  }
  // Main functionality
  // Capture memory and pass it to the analyzers

  vector<HeapInformation> heaps;
  ProgramResult r = capturer_.EnumerateHeaps(&heaps);
  cout << r.GetResultInformation() << endl;
  if (!r.IsOk()) {
    cout << GetLastErrorAsString() << endl;
    return keys_;
  }

  printf("[i] Prev key count: %u\n\n", keys_.size());

  unsigned int scanner_count = 1, heap_counter = 1, total_scanners = scanners_.size();
  for(HeapInformation heap : heaps) {
    printf("============\nHeap: %d/%zd [@%p | %p]\n", heap_counter++, heaps.size(), (void*) heap.GetBaseAddress(), (void*) heap.GetLastAddress());
    unsigned char* buffer = NULL;
    ProgramResult result = capturer_.CopyHeapData(heap, &buffer);
    cout << "Copy result: " <<  result.GetResultInformation() << endl;

    if (result.IsErr()) {
      free(buffer);
      continue;
    }

    cout << "Number of scanners: " << scanners_.size() << endl;
    for (const auto& scanner : scanners_) {
      cout << " [" << scanner_count << "/" << total_scanners << "] Scanning with: " << scanner->GetName() << endl;
      AddKeys(scanner->Scan(buffer, heap));
    }
  }

  printf("\n=======================\n");
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

void ScannerFacade::AddScanners(ScannerVector scanners) {
  scanners_.merge(move(scanners));
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
