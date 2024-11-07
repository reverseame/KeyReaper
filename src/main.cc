// Compilar con: cl /EHsc /std:c++17 .\main.cc User32.lib
#define NOMINMAX  // To avoid macro collision (windows and argparse)
#include <windows.h>

#include <intsafe.h>
#include <string>
#include <iostream>
#include <vector>
#include <stdlib.h>
#include <functional>

#include <argparse/argparse.hpp>

#include "process_capturer.h"
#include "program_result.h"
#include "scanners.h"
#include "key_scanner.h"

using namespace process_manipulation;
using namespace key_scanner;
using namespace error_handling;
using namespace std;

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program("CRAPER");

  program.add_argument("pid")
  .scan<'u', UINT>()
  .help("PID of the target process");

  program.add_argument("-a", "--action")
  .choices("pause", "ntpause", "resume", "kill")
  .nargs(1)
  .help("The action to perform on all the process threads. If not specified, it will not do any. This action will be performed prior to the extraction of the keys");

  program.add_argument("-o", "--output")
  .nargs(1)
  .help("Output file for the keys JSON. If not specified, no file is exported");

  program.add_argument("-s", "--scanners")
  .choices("crapi", "roundkey")
  .nargs(argparse::nargs_pattern::at_least_one)
  .required()
  .remaining()
  .help("Type of key scan to be performed");

  try {
    program.parse_args(argc, argv);
  }
  catch (const exception& err) {
    cerr << err.what() << endl;
    cerr << program;
    exit(1);
  }

  auto pid = program.get<UINT>("pid");
  cout << "[i] Capturing PID: " << pid << endl;

  auto scanners = program.get<vector<string>>("--scanners");
  if (scanners.empty()) {
    printf(" [x] No scanner selected\n");
    exit(2);
  }

  auto sb = ScannerBuilder();
  for (auto scanner_name : scanners) {
    if (scanner_name == "craper") sb.AddCryptoAPIScan();
    else if (scanner_name == "roundkey") sb.AddRoundKeyScan();
  }

  auto scanner = ScannerFacade(pid, sb.GetScanners(), OnDestroyAction::kDoNothing);
  if (!scanner.IsProcessAlive()) {
    printf("[x] Process is not alive");
    exit(1);
  }
  
  if (program.is_used("--action")) {
    auto action = program.get<string>("--action");
    ProgramResult pr = 
      (action == "resume") ? scanner.ResumeProcess(true) :
      (action == "ntpause") ? scanner.PauseProcess(PauseStrategy::NtPauseProcess) :
      (action == "pause") ? scanner.PauseProcess(PauseStrategy::AllThreadPause) :
      (action == "kill") ? scanner.KillProcess() :
      ErrorResult("Invalid option");
  
    cout << pr.GetResultInformation() << endl;
  } else {
    // else: perform no action over the process threads (only extract keys)
    printf(" [i] No action selected, proceeding to scan");
  }

  scanner.DoScan();

  if (program.is_used("--output")) {
    scanner.ExportKeysToJSON(program.get<string>("--output"));
  }

  return 0;

  vector<HeapInformation> heaps;
  //ProgramResult r = cp.EnumerateHeaps(&heaps);
  //cout << r.GetResultInformation() << endl;
  //if (!r.IsOk()) {
  //  cout << GetLastErrorAsString() << endl;
  //}

  unordered_set<Key, Key::KeyHashFunction> keys;
  unsigned int heap_counter = 1;
  for(HeapInformation heap : heaps) {
    printf("============\nHeap: %d/%zd [@%p | %p]\n", heap_counter++, heaps.size(), (void*) heap.GetBaseAddress(), (void*) heap.GetLastAddress());
    unsigned char* buffer = NULL;
    //ProgramResult pr2 = cp.CopyHeapData(heap, &buffer);
    //cout << "Copy result: " <<  pr2.GetResultInformation() << endl;
    //if (pr2.IsErr()) continue;

    //ProcessCapturer::PrintMemory(buffer, 64, heap.base_address);
  
    CryptoAPIScan scanner = CryptoAPIScan::CryptoAPIScan();
    keys.merge( scanner.Scan(buffer, heap) ); // add keys

    free(buffer); buffer = NULL;
  }

  printf("\n=======================\n");
  printf("All found keys: \n");

  unsigned int i = 1;
  for (auto &key : keys) {
    
    cout << " Key [" << i++ << "/" << keys.size() << "]: " << endl;
    cout << "  * Type: " << key.GetAlgorithm() << endl << "  * Size: " << key.GetSize() << " bytes" << endl << endl;
    ProcessCapturer::PrintMemory(&key.GetKey()[0], key.GetSize());

    printf("---\n\n");
  }

  return 0;
}
