#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <Windows.h>
#include <vector>

#include "program_result.h"

typedef DWORD (WINAPI *ThreadSuspendFunction)(HANDLE hThread);

namespace process_manipulation {

struct HeapInformation {
  ULONG_PTR id;
  ULONG_PTR base_address;
  ULONG_PTR final_address;
  SIZE_T size;
};

class ProcessCapturer {
 public:
  // Constructors
  ProcessCapturer(int pid);

  // Process manipulation interface
  error_handling::ProgramResult PauseProcess(bool force_pause = false);
  error_handling::ProgramResult ResumeProcess(bool force_resume = false);
  error_handling::ProgramResult KillProcess(UINT exit_code = 0);

  // Memory stealing
  error_handling::ProgramResult GetMemoryChunk(LPCVOID start, SIZE_T size, BYTE* buffer, SIZE_T* bytes_read);
  error_handling::ProgramResult GetProcessHeaps(std::vector<HeapInformation>* heaps);
  error_handling::ProgramResult CopyProcessHeap(HeapInformation heap_to_copy, unsigned char** buffer, SIZE_T* size);

  void static PrintMemory(unsigned char* buffer, SIZE_T num_of_bytes, ULONG_PTR start_address = 0x0);

  // Query
  DWORD GetPid() const;
  bool IsSuspended();
  bool IsProcessAlive();

 private:
 // TODO: review
  void SetSuspendPtr(int ThreadSuspendFunction);

  DWORD pid_;
  ThreadSuspendFunction suspendThreadPtr_;
  int suspended_;

};

} // namespace process_manipulation

#endif
