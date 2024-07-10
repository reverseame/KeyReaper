// Compilar con: cl /EHsc /std:c++17 .\main.cc User32.lib
#include <Windows.h>
#include <iostream>
#include <Intsafe.h>

#include "process_capturer.h"
#include "program_result.h"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    cout << "[x] Argument number mismatch" << endl;
    cout << "    1) PID of the process" << endl;
    return -1;
  }

  // Not meant to be used in the final version
  int int_pid = atoi(argv[1]);
  DWORD pid;
  bool err = IntToDWord(int_pid, &pid);

  if (err) {
    cout << "Could not convert pid to DWORD: " << err<< endl;
    return -1;
  }
  cout << "[i] Capturing PID: " << pid << endl;

  //LPCTSTR message = "Hello, Windows API!";
  //LPCTSTR caption = "test";
  //MessageBox(NULL, message, caption, MB_OK);

  ProcessCapturer cp = ProcessCapturer(pid);

  if (cp.IsRunning()) {
    cout << "Running" << endl;
  } else {
    printf("Not running\n");
  }
  ProgramResult pr = cp.PauseProcess();
    
  if (pr.IsOk()) {
    cout << "Process successfully paused" << endl;
  } else {
    cout << "Could not pause process" << endl;
  }
  cout << pr.GetResultInformation() << endl;

  return 0;
}
