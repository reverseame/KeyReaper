#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <Windows.h>

#include "program_result.h"

typedef DWORD (WINAPI *ThreadSuspendFunction)(HANDLE hThread);

class ProcessCapturer {
 private:
  DWORD pid_;
  ThreadSuspendFunction suspendThreadPtr_;
  bool suspended_;

 public:

  ProcessCapturer(int pid);

  ProgramResult PauseProcess();

  ProgramResult ResumeProcess();

  ProgramResult KillProcess();

  DWORD GetPid();

  bool IsSuspended();

  ProgramResult GetMemoryChunk(int start, int size, char* buffer);

 private:
  void SetSuspendPtr(int ThreadSuspendFunction);

};

#endif
