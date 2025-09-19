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
ProgramResult ScannerFacade::PauseProcess(PauseStrategy strategy, vector<DWORD> excluded_tids, bool force_pause) {
  switch (strategy) {
    case PauseStrategy::AllThreadPause:
      return capturer_.PauseProcess(excluded_tids, force_pause);

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

std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> ScannerFacade::DoScan(bool extended_search_enabled) {
  printf(" [i] Starting scan\n");
  if (scanners_.size() == 0) {
    printf(" [x] No scanner selected\n");
    return keys_;
  }
  // Main functionality
  // Capture memory and pass it to the analyzers

  vector<HeapSegment> heaps;
  ProgramResult r = capturer_.EnumerateHeaps(heaps, extended_search_enabled);
  cout << r.GetResultInformation() << endl;
  if (!r.IsOk()) {
    cout << GetLastErrorAsString() << endl;
    return keys_;
  }

  printf("[i] Prev key count: %zu\n\n", keys_.size());

  size_t scanner_count = 1, heap_counter = 1, total_scanners = scanners_.size();
  for(HeapSegment heap : heaps) {
    printf("============\nHeap: %zu/%zu [@%p | %p]\n", heap_counter++, heaps.size(), (void*) heap.GetBaseAddress(), (void*) heap.GetLastAddress());

    auto buffer = vector<BYTE>();
    ProgramResult result = capturer_.CopyHeapData(heap, &buffer);
    cout << "Copy result: " <<  result.GetResultInformation() << endl;

    if (result.IsErr()) continue;

    cout << "Number of scanners: " << scanners_.size() << endl;
    for (const auto& scanner : scanners_) {
      cout << " [" << scanner_count << "/" << total_scanners << "] Scanning with: " << scanner->GetName() << endl;
      AddKeys(scanner->Scan(buffer.data(), heap, capturer_));
    }
  }

  printf("\n=======================\n");
  return keys_;
}

std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> ScannerFacade::GetKeys() {
  return keys_;
}

ProgramResult ScannerFacade::ExportKeysToJSON(string output_json) {
  if (keys_.empty()) return ErrorResult("No keys were recovered");

  cout << "[i] Exporting keys to " << output_json << endl;
  nlohmann::json json_data;
  for (auto &key : keys_) {
    json_data += key->GetKeyAsJSON();
  }

  ofstream file(output_json);
  file << json_data.dump(2);  // Pretty print
  file.close();

  return OkResult("Exported keys to: " + output_json);
}

ProgramResult ScannerFacade::ExportKeysToBinary() {
  ProgramResult result = OkResult("All keys were successfully exported");
  
  size_t i = 0;
  size_t failed_exports = 0;
  for (const auto& key : keys_) {
    ProgramResult pr = key->ExportKeyAsBinary("key" + to_string(i++));
    if (pr.IsErr()) {
      cout << pr.GetResultInformation() << std::endl;
      failed_exports += 1;
    }
  }

  if (failed_exports > 0) result = ErrorResult(to_string(failed_exports) + " out of " + to_string(keys_.size()) + "keys failed to export");
  return result;
}

void ScannerFacade::AddScanners(ScannerVector scanners) {
  unsigned int i = 0;
  for (auto& scanner : scanners) {
    scanners_.push_back(move(scanner));
  }
  scanners.clear();
}

bool ScannerFacade::StressTest(UINT runs, UINT expected_num_of_keys) {
  LARGE_INTEGER start, end, frequency;
  QueryPerformanceFrequency(&frequency);

  auto& scanner = scanners_.front(); // use only the first scanner
  cout << "Scanner: " << scanner->GetName() << endl;

  double total_scan_time = 0, total_copy_time = 0, extended_heap_time = 0, milliseconds;
  size_t scanner_count = 1, heap_counter = 1, total_scanners = scanners_.size(), total_heap_size = 0;

  // STANDARD HEAP SCAN
  for(UINT u = 0; u < runs; u++) {
    printf("[%u/%u] HEAP ENUM & COPY (SHORT)\n", u+1, runs);
    auto buffer = vector<BYTE>();
    QueryPerformanceCounter(&start);

    // Enumerate the heaps
    vector<HeapSegment> heaps;
    capturer_.EnumerateHeaps(heaps);

    // Scan the heaps
    for (auto heap : heaps) {
      capturer_.CopyHeapData(heap, &buffer);
    }

    QueryPerformanceCounter(&end);
    milliseconds = static_cast<double>(end.QuadPart - start.QuadPart) / frequency.QuadPart * 1000.0;
    total_copy_time += milliseconds;
  }

  // EXTENDED SEARCH TEST
  for (UINT u = 0; u < runs;  u++) {
    printf("[%u/%u] HEAP ENUM & COPY (EXTENDED)\n", u+1, runs);
    QueryPerformanceCounter(&start); // crono start

    // Enumerate the heaps
    auto heaps_extended = vector<HeapSegment>();
    capturer_.EnumerateHeaps(heaps_extended, true);
    
    // Copy the heaps
    auto buffer = vector<BYTE>();
    for (auto heap_data : heaps_extended) {
      capturer_.CopyHeapData(heap_data, &buffer);
    }

    QueryPerformanceCounter(&end); // crono end
    milliseconds = static_cast<double>(end.QuadPart - start.QuadPart) / frequency.QuadPart * 1000.0;
    extended_heap_time += milliseconds;


    // SCAN TEST
    keys_.clear(); // clear the keys found to avoid the set insertions to slow down
    QueryPerformanceCounter(&start);
    for (auto heap : heaps_extended) {
      auto found_keys = scanner->Scan(buffer.data(), heap, capturer_);
      AddKeys(found_keys);
    }
    QueryPerformanceCounter(&end);

    milliseconds = static_cast<double>(end.QuadPart - start.QuadPart) / frequency.QuadPart * 1000.0;
    // cout << "Scan millis: " << milliseconds << std::endl;
    total_scan_time += milliseconds;
  }

  auto heaps = vector<HeapSegment>();
  capturer_.EnumerateHeaps(heaps, true);
  for (auto heap : heaps) {
    // HEAP SIZE
    total_heap_size += heap.GetSize();
    // NORMAL SCAN
    auto buffer = vector<BYTE>();
    capturer_.CopyHeapData(heap, &buffer);
    auto keys = scanner->Scan(buffer.data(), heap, capturer_);
    AddKeys(keys);
  }

  // NUMBER OF KEYS
  if (keys_.size() != expected_num_of_keys) {
    cout << " [!] Mismatched number of keys." << endl;
    cout << "    * Expected: " << expected_num_of_keys << endl;
    cout << "    * Actual:   " << keys_.size() << endl;
  }

  printf("\n. RESULTS ================\n");
  printf("|  > Copy average: %.2f\n", total_copy_time / runs);
  printf("|  > Scan average: %.2f\n", total_scan_time / runs);
  printf(". ________________________\n");
  printf("Writing results to file...\n");

  string filename = "results.csv";

  ofstream file(filename, ios::app);
  if (!file.is_open()) {
    cerr << "Failed to open file: " << filename << endl;
    return false;
  }

  // Write the header if there's not
  // if (is_empty) {
  // file << "Algorithm,Runs,Keys found,Keys expected,Extended Time Average(ms),Copy Time Average(ms),Scan Time Average(ms),Buffer Size (bytes)" << std::endl;
  // }
  // NOT WORKING??? TODO: fix

  file
  << scanner->GetName()
  << "," << runs
  << "," << keys_.size()
  << "," << expected_num_of_keys
  << "," << std::fixed << std::setprecision(2) << extended_heap_time / runs
  << "," << std::fixed << std::setprecision(2) << total_copy_time / runs
  << "," << std::fixed << std::setprecision(2) << total_scan_time / runs
  << "," << total_heap_size
  << std::endl;  

  file.close();
  return true;
}

void ScannerFacade::AddKeys(std::unordered_set<std::shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> keys) {
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
