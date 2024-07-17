#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "Kernel32.lib")

#include "process_capturer.h"
using ProgramResult = error_handling::ProgramResult;
using ResultType = ProgramResult::ResultType;

namespace process_manipulation {

ProcessCapturer::ProcessCapturer(int pid) 
    : pid_(pid), suspended_(false) {
  
  // TODO: check if the process is wow64.
  //       would work in 32 bit?

}

ProgramResult ProcessCapturer::PauseProcess(bool force_pause) {

  if (!IsProcessAlive()) {
    return ProgramResult(ResultType::kError, PROC_NOT_ALIVE_ERR_MSG);
  }

  if (!force_pause && IsSuspended()) {
    return ProgramResult(ResultType::kError, PROC_SUSP_ERR_MSG);
  }

  printf("[i] Creating process snapshot\n");
  HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (thread_snapshot == INVALID_HANDLE_VALUE) {
    return ProgramResult(ResultType::kError, THREAD_SNAP_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = ProgramResult(ResultType::kOk, 
                                            "All process' threads paused");

  THREADENTRY32 thread_entry; 
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(thread_snapshot, &thread_entry);
  if (!copied) {
    func_result = ProgramResult(ResultType::kError, THREAD_SNAP_FIRST_ERR_MSG);

  } else if (GetLastError() == ERROR_NO_MORE_FILES) {
    func_result = ProgramResult(ResultType::kError, 
                                THREAD_SNAP_NO_INFO_ERR_MSG);

  } else {
    int n_threads = 0;
    do {
      if (thread_entry.th32OwnerProcessID == pid_) {
        printf(" [%i]\r", ++n_threads);

        HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, 
                                          thread_entry.th32ThreadID);
        if (thread_handle == NULL) {
          func_result = ProgramResult(ResultType::kError, 
                                      THREAD_OPEN_ERR_MSG);
          break;
        }
              
        DWORD suspension_count = SuspendThread(thread_handle);
        if (suspension_count == (DWORD) - 1) {
          // TODO include exact number in error text with a formatter
          func_result = ProgramResult(ResultType::kError, 
                                      THEAD_MAX_SUS_COUNT_ERR_MSG);
          break;
        }
        printf("[%i] Suspend count: %i\n", n_threads, suspension_count + 1);

        // Not considering the result of the close handle function,
        // since its result won't affect the outcome our program
        CloseHandle(thread_handle);
      }
    } while (Thread32Next(thread_snapshot, &thread_entry));
  }

  if (func_result.IsOk()) {
    suspended_ = true;
  }

  // We should always close the handle
  CloseHandle(thread_snapshot);
  return func_result;
}

/**
 * Resumes the process associated with the object
*/
ProgramResult ProcessCapturer::ResumeProcess(bool force_resume) {
  printf("Resuming process\n");

  if (!IsProcessAlive()) {
    return ProgramResult(ResultType::kError, PROC_NOT_ALIVE_ERR_MSG);
  }

  if (!force_resume && !IsSuspended()) {
    return ProgramResult(ResultType::kError, PROC_STILL_RUN_ERR_MSG);
  }

  printf("[i] Creating process snapshot\n");
  HANDLE handle_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (handle_thread_snap == INVALID_HANDLE_VALUE) {
    return ProgramResult(ResultType::kError, THREAD_SNAP_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = ProgramResult(ResultType::kOk, 
                                            "All process' threads resumed");

  THREADENTRY32 thread_entry;
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(handle_thread_snap, &thread_entry);
  if (!copied) {
    func_result = ProgramResult(ResultType::kError, THREAD_SNAP_FIRST_ERR_MSG);

  } else if (GetLastError() == ERROR_NO_MORE_FILES) {
    func_result = ProgramResult(ResultType::kError, THREAD_SNAP_NO_INFO_ERR_MSG);

  } else {
    int n_threads = 0;
    do {
      if (thread_entry.th32OwnerProcessID == pid_) {
        printf("[%i] Reducing to zero the number of pauses\n", ++n_threads);

        HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
        if (thread_handle == NULL) {
          func_result = ProgramResult(ResultType::kError, THREAD_OPEN_ERR_MSG);
          break;
        }

        // Reduce the suspension count to zero
        DWORD suspension_count;
        do {
          suspension_count = ResumeThread(thread_handle) - 1; // ResumeThread returns the PREVIOUS pause count
          if (suspension_count == (DWORD) - 1) {
            // TODO include exact number in error text with a formatter
            func_result = ProgramResult(ResultType::kError, THREAD_RESUME_ERR_MSG);
            break;
          }
        } while (suspension_count > 0);
        
        // Not considering the result of the close handle function,
        // since its result won't affect the outcome our program
        CloseHandle(thread_handle);
      }
    } while (Thread32Next(handle_thread_snap, &thread_entry));
  }

  if (func_result.IsOk()) {
    suspended_ = false;
  }

  CloseHandle(handle_thread_snap);
  return func_result;
}

ProgramResult ProcessCapturer::KillProcess(UINT exit_code) {

  ProgramResult func_result = ProgramResult(ResultType::kOk, "Process terminated");

  if (!IsProcessAlive()) {
    func_result = ProgramResult(ResultType::kError, PROC_NOT_ALIVE_ERR_MSG);

  } else {
    HANDLE proc_handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid_);
    if (proc_handle == NULL) {
      func_result = ProgramResult(ResultType::kError, PROC_OPEN_ERR_MSG);

    } else {
      bool success = TerminateProcess(proc_handle, exit_code);
      if (!success) {
        func_result = ProgramResult(ResultType::kError, "Could not terminate the process");
      }
    }

    CloseHandle(proc_handle);
  }

  return func_result;
}

void ProcessCapturer::SetSuspendPtr(int ThreadSuspendFunction) {
  // TODO - implement ProcessCapturer::setSuspendPtr
  throw "Not yet implemented";
}

/**
 * Determines if the process exists / is alive (not killed), independently of
 * the status (paused or running)
*/
bool ProcessCapturer::IsProcessAlive() {
  bool active = false;
  HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION , FALSE, pid_);

  if (process_handle != NULL) {
    DWORD exit_code;
    bool result = GetExitCodeProcess(process_handle, &exit_code);
    if (result != 0 && exit_code == STILL_ACTIVE) {
      active = true;
    }
  }

  CloseHandle(process_handle);
  return active;
}

ProgramResult ProcessCapturer::GetMemoryChunk(int start, int size, unsigned char* buffer) {
  // TODO - implement ProcessCapturer::getMemoryChunk
  throw "Not yet implemented";
}

/**
 * Retrieves the information of all the heaps of the process. It is necessary
 * to have elevated privileges to perform this action.
*/
ProgramResult ProcessCapturer::GetProcessHeaps(std::vector<HeapInformation>* heaps) {
  printf("Getting heap\n");

  HEAPLIST32 hl;
  HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid_);
  hl.dwSize = sizeof(HEAPLIST32);

  if ( hHeapSnap == INVALID_HANDLE_VALUE ) {
    printf ("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
    return ProgramResult(ResultType::kError, "Could not open handle to snapshot");
  }

  ProgramResult func_result = ProgramResult(ResultType::kOk, "Heap captured successfully");

  if( Heap32ListFirst(hHeapSnap, &hl)) {
    do {
      HEAPENTRY32 he;
      ZeroMemory(&he, sizeof(HEAPENTRY32));
      he.dwSize = sizeof(HEAPENTRY32);

      if( Heap32First(&he, pid_, hl.th32HeapID )) {

        HeapInformation heap_data;
        heap_data.id = hl.th32HeapID;
        heap_data.base_address = he.dwAddress;

        unsigned int total_size = 0;
        do {
          total_size += he.dwBlockSize;
          he.dwSize = sizeof(HEAPENTRY32);
        } while ( Heap32Next(&he) );

        heap_data.size = total_size;
        heap_data.last_address = total_size - 1 + heap_data.base_address;
        heaps->push_back(heap_data);

        printf( "\nHeap ID: %d\n", hl.th32HeapID );
        printf("Base address: 0x%p\n", heap_data.base_address );
        printf("Size of heap: %u\n", total_size);
        printf("Final address: 0x%p\n", heap_data.last_address);

      }
      hl.dwSize = sizeof(HEAPLIST32);
    } while (Heap32ListNext( hHeapSnap, &hl));
  
  } else { 
    printf ("Cannot list first heap (%d)\n", GetLastError());
    func_result = ProgramResult(ResultType::kError, "Cannot list first heap");
  }
   
  CloseHandle(hHeapSnap);
  return func_result;
}

bool ProcessCapturer::IsSuspended() {
  return suspended_;
}

DWORD ProcessCapturer::GetPid() {
  return pid_;
}

} // namespace process_manipulation