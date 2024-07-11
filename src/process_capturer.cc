#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "Kernel32.lib")

#include "process_capturer.h"

namespace process_manipulation {

ProcessCapturer::ProcessCapturer(int pid) 
    : pid_(pid) {
  suspended_ = false;
  
  // TODO: check if the process is wow64.
  //       would work in 32 bit?

}

ProgramResult ProcessCapturer::PauseProcess(bool force_pause) {

  if (!IsProcessAlive()) {
    return ProgramResult(ProgramResult::ResultType::kError, "Process is not alive");
  }

  if (!force_pause && suspended_) {
    return ProgramResult(ProgramResult::ResultType::kError, "Process was already suspended");
  }

  printf("[i] Creating process snapshot\n");
  HANDLE handle_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (handle_thread_snap == INVALID_HANDLE_VALUE) {
    return ProgramResult(ProgramResult::ResultType::kError, "Could not create a snapshot of the threads");
  }

  THREADENTRY32 thread_entry; 
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(handle_thread_snap, &thread_entry);
  if (!copied) {
    return ProgramResult(ProgramResult::ResultType::kError, "Could not copy the first thread entry");
  }
  if (GetLastError() == ERROR_NO_MORE_FILES) {
    return ProgramResult(ProgramResult::ResultType::kError, "Did not find any thread information in the snapshot");
  }

  int n_threads = 0;
  do {
    printf(" [%i]\r", ++n_threads);
    if (thread_entry.th32OwnerProcessID == pid_) {
      HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);
      if (thread_handle == NULL) {
        return ProgramResult(ProgramResult::ResultType::kError, "Could not open thread");
      }
            
      DWORD suspension_count = SuspendThread(thread_handle);
      if (suspension_count == (DWORD) - 1) { // TODO include exact number in error text with a formatter
        return ProgramResult(ProgramResult::ResultType::kError, "Thread reached its maximum number of suspensions");
      }
      printf("[%i] Reamining suspensions: %i\n", n_threads, suspension_count);

      bool closed = CloseHandle(thread_handle);
      if (!closed) {
        return ProgramResult(ProgramResult::ResultType::kError, "Could not close handle to thread");
      }
    }
  } while (Thread32Next(handle_thread_snap, &thread_entry));

    bool closed = CloseHandle(handle_thread_snap);
    if (!closed) {
      return ProgramResult(ProgramResult::ResultType::kError, "Could not close handle to process");
    }

    return ProgramResult(ProgramResult::ResultType::kOk, "All process' threads paused");
    
}

ProgramResult ProcessCapturer::ResumeProcess(bool force_resume) {
  if (!IsProcessAlive()) {
    return ProgramResult(ProgramResult::ResultType::kError, "Process is not alive");
  }

  if (!force_resume && !suspended_) {
    return ProgramResult(ProgramResult::ResultType::kError, "Process is still running");
  }

    printf("[i] Creating process snapshot\n");
  HANDLE handle_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (handle_thread_snap == INVALID_HANDLE_VALUE) {
    return ProgramResult(ProgramResult::ResultType::kError, "Could not create a snapshot of the threads");
  }

  THREADENTRY32 thread_entry;
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(handle_thread_snap, &thread_entry);
  if (!copied) {
    return ProgramResult(ProgramResult::ResultType::kError, "Could not copy the first thread entry");
  }
  if (GetLastError() == ERROR_NO_MORE_FILES) {
    return ProgramResult(ProgramResult::ResultType::kError, "Did not find any thread information in the snapshot");
  }

  int n_threads = 0;
  do {
    printf(" [%i]\r", ++n_threads);
    if (thread_entry.th32OwnerProcessID == pid_) {
      HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);
      if (thread_handle == NULL) {
        return ProgramResult(ProgramResult::ResultType::kError, "Could not open thread");
      }

      DWORD suspension_count = ResumeThread(thread_handle);
      if (suspension_count == (DWORD) - 1) { // TODO include exact number in error text with a formatter
        return ProgramResult(ProgramResult::ResultType::kError, "Failed to resume the thread");
      }
      printf("[%i] Reamining suspensions: %i\n", n_threads, suspension_count);

      bool closed = CloseHandle(thread_handle);
      if (!closed) {
        return ProgramResult(ProgramResult::ResultType::kError, "Could not close handle to thread");
      }
    }
  } while (Thread32Next(handle_thread_snap, &thread_entry));

    bool closed = CloseHandle(handle_thread_snap);
    if (!closed) {
      return ProgramResult(ProgramResult::ResultType::kError, "Could not close handle to process");
    }

    return ProgramResult(ProgramResult::ResultType::kOk, "All process' threads resumed");
}

ProgramResult ProcessCapturer::KillProcess(UINT exit_code) {

  if (!IsProcessAlive()) {
    return ProgramResult(ProgramResult::ResultType::kError, "Process is not running");
  }

  HANDLE proc_handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid_);

  if (proc_handle == NULL) {
    return ProgramResult(ProgramResult::ResultType::kError, "Could not open the process");
  }

  bool success = TerminateProcess(proc_handle, exit_code);

  if (!success) {
    return ProgramResult(ProgramResult::ResultType::kError, "Could not terminate the process");
  }
  return ProgramResult(ProgramResult::ResultType::kOk, "Process terminated");
}

void ProcessCapturer::SetSuspendPtr(int ThreadSuspendFunction) {
  // TODO - implement ProcessCapturer::setSuspendPtr
  throw "Not yet implemented";
}

bool ProcessCapturer::IsSuspended() {
  return suspended_;
}

/**
 * Determines if the process exists / is alive (not killed), independently of
 * the status (paused or running)
*/
bool ProcessCapturer::IsProcessAlive() {
  bool active = false;
  HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION , FALSE, pid_);

  if (process_handle == NULL) {
    return false;

  } else {
    DWORD exit_code;
    bool res = GetExitCodeProcess(process_handle, &exit_code);
    if (res != 0 && exit_code == STILL_ACTIVE) {
      active = true;
    }

    CloseHandle(process_handle);
    return active;
  }
}

ProgramResult ProcessCapturer::GetMemoryChunk(int start, int size, char* buffer) {
  // TODO - implement ProcessCapturer::getMemoryChunk
  throw "Not yet implemented";
}

DWORD ProcessCapturer::GetPid() {
  return pid_;
}

} // namespace process_manipulation