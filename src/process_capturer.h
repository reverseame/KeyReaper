#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <Windows.h>
#include <vector>
#include <tlhelp32.h>

#include "program_result.h"

typedef DWORD (WINAPI *ThreadSuspendFunction)(HANDLE hThread);

namespace process_manipulation {

class HeapInformation {
 public:
  HeapInformation(HEAPENTRY32 he) : 
      id(he.th32HeapID), base_address(he.dwAddress), final_address(NULL), size(0){};

  inline bool IsAddressInHeap(LPVOID pointer) {
    return (ULONG_PTR) pointer <= (ULONG_PTR) final_address && (ULONG_PTR) pointer >= (ULONG_PTR) base_address;
  };

  inline bool RebaseAddress(ULONG_PTR* pointer, ULONG_PTR new_base_address) {
    if (!IsAddressInHeap((void*) *pointer)) {
      
      printf(" > Pointer: %p\n", (void*) *pointer);
      printf(" > Final:   %p\n", (void*) final_address);
      printf(" > Base:    %p\n", (void*) base_address);
      
      return false;
    
    } else {
      *pointer -= this->base_address;
      *pointer += new_base_address;
      return true;
    }
  }

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

  // Privileges
  error_handling::ProgramResult ObtainSeDebug();
  bool IsPrivileged();

  void static PrintMemory(unsigned char* buffer, SIZE_T num_of_bytes, ULONG_PTR starting_visual_address = 0x0);

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
  bool is_privileged_;

};

} // namespace process_manipulation

#endif
