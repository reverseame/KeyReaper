#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <Windows.h>
#include <vector>
#include <tlhelp32.h>

#include "program_result.h"

typedef DWORD (WINAPI *ThreadSuspendFunction)(HANDLE hThread);

namespace nt_suspend {
// https://ntopcode.wordpress.com/2018/01/16/anatomy-of-the-thread-suspension-mechanism-in-windows-windows-internals/
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

typedef NTSTATUS(NTAPI *pNtSuspendProcess)(
  HANDLE ProcessHandle
); // Undocumented NTDLL function
}

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
  /**
   * Retreives a list of the threads of the process associated
   * with the object through a snapshot.
   * 
   * @param TID_list  [out] A vector for storing the Thread ID of the
   *                  process' threads
   */
  error_handling::ProgramResult EnumerateThreads(std::vector<DWORD>* TID_list);

  /**
   * Pauses the process associated with the object by 
   * pausing all of its threads.
   * 
   * @param force_pause Forces the program to pause even if 
   *        it was already suspended before, or something else
   *        resumed it. Internally, it increases the pause count 
   *        of the threads by one, so there is no drawback to
   *        this option.
   */
  error_handling::ProgramResult PauseProcess(bool force_pause = false);

  /**
   * Pauses the process associated with the object by using an
   * undocumented API function called NtPauseProcess.
   * 
   * @param force_pause Forces the program to pause even if 
   *        it was already suspended before, or something else
   *        resumed it. Internally, it increases the pause count 
   *        of the threads by one, so there is no drawback to
   *        this option.
   */
  error_handling::ProgramResult PauseProcessNt(bool force_pause = false);

  /**
   * Resumes the process associated with the object by resuming
   * all of its threads.
   * 
   * @param force_resume Forces the program to resume even if
   *        it is internally registered as running, in case an
   *        external agent paused it. Internally, it reduces
   *        all process' threads pause count to zero, so if the
   *        process was already running, it won't have any 
   *        side effect.
   */
  error_handling::ProgramResult ResumeProcess(bool force_resume = false);

  /**
   * Terminates the process associated with the object.
   * 
   * @param exit_code For specifying the exit code for the termination
   *                  of the process. It defaults to zero. 
   */
  error_handling::ProgramResult KillProcess(UINT exit_code = 0);

  /**
   * Pauses a thread given its TID (Thread ID).
   * Does not check if the thread belongs to the captured process or not.
   */
  error_handling::ProgramResult PauseSingleThread(DWORD th32ThreadID);

  /**
   * Resumes a thread given its TID by reducing the pause count to zero.
   * Does not check if the thread belongs to the captured process or not.
   */
  error_handling::ProgramResult ResumeSingleThread(DWORD th32ThreadID);

  /**
   * Terminates the execution of a thread given its TID.
   * Does not check if the thread belongs to the captured process or not.
   */
  error_handling::ProgramResult KillSingleThread(DWORD th32ThreadID, DWORD exit_code = 0);


  // Memory stealing methods

  /**
   * This function serves as an interface to Windows API call `ReadProcessMemory`,
   * which allows to read the memory space of the captured process given, and
   * copy the data into a buffer.
   * 
   * Bare in mind that if the address range is not valid, the function will fail.
   * 
   * @param start Address to start copying data from
   * @param size Number of bytes to copy
   * @param buffer Buffer to copy the data to. Ensure it is big enough
   * @param bytes_read Output variable, will hold the number of bytes read 
   */
  error_handling::ProgramResult GetMemoryChunk(LPCVOID start, SIZE_T size, BYTE* buffer, SIZE_T* bytes_read);

  /**
   * Retrieves the information of all the heaps of the process. It is necessary
   * to have elevated privileges to perform this action.
   */
  error_handling::ProgramResult GetProcessHeaps(std::vector<HeapInformation>* heaps);

  /**
   * From the information about the heap, copies the whole heap to a buffer.
   * Although the pointer must be user supplied, note that the memory allocation 
   * is done by this function, and the release must be done by the user.
   * 
   * A few things to note about the function
   *  * It will initialize the memory region with zeroes
   *  * It skips the LF32_FREE blocks, since they may produce invalid addresses
   *  * If the block cannot be copied or is marked as free will be filled with 0xFF
   * 
   * ## Arguments
   *  * [in] HeapInformation heap. This is obtained through the GetProcessHeaps function
   *  * [out] unsigned char** buffer. This is where the function will place the allocated buffer with the heap data.
   *  * [out] SIZE_T size. Number of bytes written
   */
  error_handling::ProgramResult CopyProcessHeap(HeapInformation heap_to_copy, unsigned char** buffer, SIZE_T* size);

  // Privileges
  error_handling::ProgramResult ObtainSeDebug();
  bool IsPrivileged();

  void static PrintMemory(unsigned char* buffer, SIZE_T num_of_bytes, ULONG_PTR starting_visual_address = 0x0);

  // Query
  DWORD GetPid() const;

  /** When a process is suspended by the program, an internal variable keeps track of it.
   *  PauseProcess function sets it and ResumeProcess unsets it.
   *  Pausing a specific thread does not affect it.
   * 
   * This function may be used to recover this information
   */
  bool IsSuspended();

  /**
   * Determines if the process ended or is alive (not killed), independently of
   * the internal status (paused or running)
  */
  bool IsProcessAlive();

 private:
 // TODO: review
  void SetSuspendPtr(int ThreadSuspendFunction);

  /**
   * Function for initializing dynamically imported functions, such as `NtSuspendProcess`.
   */
  error_handling::ProgramResult InitializeExports();

  static nt_suspend::pNtSuspendProcess fNtPauseProcess;
  DWORD pid_;
  ThreadSuspendFunction suspendThreadPtr_;
  int suspended_;
  bool is_privileged_;
};

} // namespace process_manipulation

#endif
