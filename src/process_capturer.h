#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <Windows.h>

#include "program_result.h"
using namespace error_handling;

typedef DWORD (WINAPI *ThreadSuspendFunction)(HANDLE hThread);

namespace process_manipulation {

class ProcessCapturer {
 public:
  // Constructors
  ProcessCapturer(int pid);

  // Process manipulation interface
  ProgramResult PauseProcess(bool force_pause = false);
  ProgramResult ResumeProcess(bool force_resume = false);
  ProgramResult KillProcess(UINT exit_code = 0);

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

} // namespace process_manipulation

#endif
