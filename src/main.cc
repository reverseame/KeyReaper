// Compilar con: cl /EHsc /std:c++17 .\main.cc User32.lib
#include <Windows.h>

#include <Intsafe.h>
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
      (option == 'p') ? cp.PauseProcess(true) : 
      (option == 'k') ? cp.KillProcess() : 
      ErrorResult("Invalid option");
  
  cout << pr.GetResultInformation() << endl;

  vector<HeapInformation> heaps;
  ProgramResult r = cp.GetProcessHeaps(&heaps);
  cout << r.GetResultInformation() << endl;
  if (!r.IsOk()) {
    PrintLastError(TEXT("GETHEAP"));
  }

  unordered_set<Key, Key::KeyHashFunction> keys;
  unsigned int heap_counter = 1;
  for(const HeapInformation& heap : heaps) {
    printf("============\nid: %d/%zd [@%p | %p]\n", heap_counter++, heaps.size(), (void*) heap.base_address, (void*) heap.final_address);
    unsigned char* buffer = NULL;
    SIZE_T size;
    ProgramResult pr2 = cp.CopyProcessHeap(heaps[0], &buffer, &size);
    cout << "V2 heap copy result: " <<  pr2.GetResultInformation() << endl;
    //ProcessCapturer::PrintMemory(buffer, 64, heap.base_address);

    StructureScan scanner = StructureScan::StructureScan();
    keys.merge( scanner.Scan(buffer, heap) );

    free(buffer); buffer = NULL;
  }

  printf("\n=======================\n");
  printf("All found keys: \n");
  for (auto &key : keys) {
    ProcessCapturer::PrintMemory(&key.GetKey()[0], key.GetSize());
  }

  return 0;
}
