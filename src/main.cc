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
