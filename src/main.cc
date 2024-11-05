// Compilar con: cl /EHsc /std:c++17 .\main.cc User32.lib
#include <windows.h>

#include <intsafe.h>
#include <string>
#include <iostream>
#include <vector>
#include <stdlib.h>
#include <functional>

#include "process_capturer.h"
#include "program_result.h"
#include "scanners.h"

using namespace process_manipulation;
using namespace key_scanner;
using namespace error_handling;
using namespace std;

#include <nlohmann/json.hpp>
#include <fstream>
void ExportKeysToJSON(unordered_set<Key, Key::KeyHashFunction> keys, string output_json) {
  cout << "[i] Exporting keys to " << output_json << ".json" << endl;
  nlohmann::json json_data;
  for (auto &key : keys) {
    json_data[key.GetKeyAsString()] = { {"algorithm", key.GetAlgorithm()}, {"size", key.GetSize()} };
  }

  ofstream file(output_json + ".json");
  file << json_data.dump(2);  // Pretty print
  file.close();
}

#include <strsafe.h> // PrintLastError

void PrintLastError(LPCTSTR lpszFunction)  { 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    cout << "[x] Argument number mismatch" << endl;
    cout << "    1) PID of the process" << endl;
    cout << "    2) Action to perform [resume, pause, kill]" << endl;
    return -1;
  }

  // Not meant to be used in the final version
  int int_pid = atoi(argv[1]);
  DWORD pid;
  bool err = IntToDWord(int_pid, &pid);

  if (err) {
    cout << "Could not convert pid to DWORD: " << err << endl;
    return -1;
  }
  cout << "[i] Capturing PID: " << pid << endl;

  ProcessCapturer cp = ProcessCapturer(pid);

  char option = argv[2][0];
  ProgramResult pr = 
      (option == 'r') ? cp.ResumeProcess(true) : 
      (option == 'p') ? cp.PauseProcessNt() : 
      (option == 'k') ? cp.KillProcess() : 
      ErrorResult("Invalid option");
  
  cout << pr.GetResultInformation() << endl;

  vector<HeapInformation> heaps;
  ProgramResult r = cp.EnumerateHeaps(&heaps);
  cout << r.GetResultInformation() << endl;
  if (!r.IsOk()) {
    PrintLastError(TEXT("GETHEAP"));
  }

  unordered_set<Key, Key::KeyHashFunction> keys;
  unsigned int heap_counter = 1;
  for(HeapInformation heap : heaps) {
    printf("============\nHeap: %d/%zd [@%p | %p]\n", heap_counter++, heaps.size(), (void*) heap.GetBaseAddress(), (void*) heap.GetLastAddress());
    unsigned char* buffer = NULL;
    ProgramResult pr2 = cp.CopyHeapData(heap, &buffer);
    cout << "Copy result: " <<  pr2.GetResultInformation() << endl;
    if (pr2.IsErr()) continue;

    //ProcessCapturer::PrintMemory(buffer, 64, heap.base_address);
  
    CryptoAPIScan scanner = CryptoAPIScan::CryptoAPIScan();
    keys.merge( scanner.Scan(buffer, heap) ); // add keys

    free(buffer); buffer = NULL;
  }

  printf("\n=======================\n");
  printf("All found keys: \n");

  ExportKeysToJSON(keys, "keys");

  unsigned int i = 1;
  for (auto &key : keys) {
    
    cout << " Key [" << i++ << "/" << keys.size() << "]: " << endl;
    cout << "  * Type: " << key.GetAlgorithm() << endl << "  * Size: " << key.GetSize() << " bytes" << endl << endl;
    ProcessCapturer::PrintMemory(&key.GetKey()[0], key.GetSize());

    printf("---\n\n");
  }

  return 0;
}
