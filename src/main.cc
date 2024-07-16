// Compilar con: cl /EHsc /std:c++17 .\main.cc User32.lib
#include <Windows.h>

#include <Intsafe.h>
#include <string>
#include <iostream>

#include "process_capturer.h"
#include "program_result.h"

using namespace process_manipulation;
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

  //LPCTSTR message = "Hello, Windows API!";
  //LPCTSTR caption = "test";
  //MessageBox(NULL, message, caption, MB_OK);

  ProcessCapturer cp = ProcessCapturer(pid);

  char option = argv[2][0];
  ProgramResult pr = 
      (option == 'r') ? cp.ResumeProcess(true) : 
      (option == 'p') ? cp.PauseProcess(true) : 
      (option == 'k') ? cp.KillProcess() : 
      ProgramResult::ProgramResult(ProgramResult::ResultType::kError, "Invalid option");
  
  cout << pr.GetResultInformation() << endl;

  return 0;
}
