#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <Windows.h>

#include "program_result.h"

typedef DWORD (WINAPI *ThreadSuspendFunction)(HANDLE hThread);

namespace process_manipulation {

class ProcessCapturer {
 public:
  // Constructors
  ProcessCapturer(int pid);

  // Process manipulation interface
  error_handling::ProgramResult PauseProcess(bool force_pause = false);
  error_handling::ProgramResult ResumeProcess(bool force_resume = false);
  error_handling::ProgramResult KillProcess(UINT exit_code = 0);

  // Query
  DWORD GetPid();
  bool IsSuspended();
  bool IsProcessAlive();

  // Memory stealing
  error_handling::ProgramResult GetMemoryChunk(int start, int size, unsigned char* buffer);
  error_handling::ProgramResult GetHeap(unsigned char* buffer);

 private:
 // TODO: review
  void SetSuspendPtr(int ThreadSuspendFunction);

  DWORD pid_;
  ThreadSuspendFunction suspendThreadPtr_;
  int suspended_;

};

} // namespace process_manipulation

#endif
