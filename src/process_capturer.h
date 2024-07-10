#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <Windows.h>

#include "program_result.h"

typedef DWORD (WINAPI *ThreadSuspendFunction)(HANDLE hThread);

class ProcessCapturer {

 public:
  // Constructors
  ProcessCapturer(int pid);

  // Process manipulation interface
  ProgramResult PauseProcess();
  ProgramResult ResumeProcess();
  ProgramResult KillProcess();

  // Query
  DWORD GetPid();
  bool IsSuspended();
  bool IsProcessAlive();

  // Memory stealing
  ProgramResult GetMemoryChunk(int start, int size, char* buffer);

 private:
 // TODO: review
  void SetSuspendPtr(int ThreadSuspendFunction);

  DWORD pid_;
  ThreadSuspendFunction suspendThreadPtr_;
  bool suspended_;

};

#endif
