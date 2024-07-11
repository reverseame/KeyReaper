#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "Kernel32.lib")

#include "process_capturer.h"
using namespace error_handling;

namespace process_manipulation {

ProcessCapturer::ProcessCapturer(int pid) 
    : pid_(pid), suspended_(false) {
  
  // TODO: check if the process is wow64.
  //       would work in 32 bit?

}

ProgramResult ProcessCapturer::PauseProcess(bool force_pause) {

  if (!IsProcessAlive()) {
    return ProgramResult(ProgramResult::ResultType::kError, PROC_NOT_ALIVE_ERR_MSG);
  }

  if (!force_pause && IsSuspended()) {
    return ProgramResult(ProgramResult::ResultType::kError, PROC_SUSP_ERR_MSG);
  }

  printf("[i] Creating process snapshot\n");
  HANDLE handle_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (handle_thread_snap == INVALID_HANDLE_VALUE) {
    return ProgramResult(ProgramResult::ResultType::kError, THREAD_SNAP_ERR_MSG);
  }

  THREADENTRY32 thread_entry; 
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(handle_thread_snap, &thread_entry);
  if (!copied) {
    return ProgramResult(ProgramResult::ResultType::kError, THREAD_SNAP_FIRST_ERR_MSG);
  }
  if (GetLastError() == ERROR_NO_MORE_FILES) {
    return ProgramResult(ProgramResult::ResultType::kError, THREAD_SNAP_NO_INFO_ERR_MSG);
  }

  int n_threads = 0;
  do {
    if (thread_entry.th32OwnerProcessID == pid_) {
      printf(" [%i]\r", ++n_threads);
      HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
      if (thread_handle == NULL) {
        return ProgramResult(ProgramResult::ResultType::kError, THREAD_OPEN_ERR_MSG);
      }
            
      DWORD suspension_count = SuspendThread(thread_handle);
      if (suspension_count == (DWORD) - 1) { // TODO include exact number in error text with a formatter
        return ProgramResult(ProgramResult::ResultType::kError, THEAD_MAX_SUS_COUNT_ERR_MSG);
      }
      printf("[%i] Suspend count: %i\n", n_threads, suspension_count + 1);

      bool closed = CloseHandle(thread_handle);
      if (!closed) {
        return ProgramResult(ProgramResult::ResultType::kError, THREAD_CLOSE_ERR_MSG);
      }
    }
  } while (Thread32Next(handle_thread_snap, &thread_entry));

    bool closed = CloseHandle(handle_thread_snap);
    if (!closed) {
      return ProgramResult(ProgramResult::ResultType::kError, PROC_CLOSE_ERR_MSG);
    }

    suspended_ = true;
    return ProgramResult(ProgramResult::ResultType::kOk, "All process' threads paused");
}

ProgramResult ProcessCapturer::ResumeProcess(bool force_resume) {
  printf("Resuming process\n");

  if (!IsProcessAlive()) {
    return ProgramResult(ProgramResult::ResultType::kError, PROC_NOT_ALIVE_ERR_MSG);
  }

  if (!force_resume && !IsSuspended()) {
    return ProgramResult(ProgramResult::ResultType::kError, PROC_STILL_RUN_ERR_MSG);
  }

  printf("[i] Creating process snapshot\n");
  HANDLE handle_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (handle_thread_snap == INVALID_HANDLE_VALUE) {
    return ProgramResult(ProgramResult::ResultType::kError, THREAD_SNAP_ERR_MSG);
  }

  THREADENTRY32 thread_entry;
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(handle_thread_snap, &thread_entry);
  if (!copied) {
    return ProgramResult(ProgramResult::ResultType::kError, THREAD_SNAP_FIRST_ERR_MSG);
  }
  if (GetLastError() == ERROR_NO_MORE_FILES) {
    return ProgramResult(ProgramResult::ResultType::kError, THREAD_SNAP_NO_INFO_ERR_MSG);
  }

  int n_threads = 0;
  do {
    if (thread_entry.th32OwnerProcessID == pid_) {
      printf("[%i] Reducing to zero the number of pauses\n", ++n_threads);

      HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
      if (thread_handle == NULL) {
        return ProgramResult(ProgramResult::ResultType::kError, THREAD_OPEN_ERR_MSG);
      }

      DWORD suspension_count;
      do {
        suspension_count = ResumeThread(thread_handle) - 1; // ResumeThread returns the PREVIOUS pause count
        if (suspension_count == (DWORD) - 1) { // TODO include exact number in error text with a formatter
          return ProgramResult(ProgramResult::ResultType::kError, THREAD_RESUME_ERR_MSG);
        }
      } while (suspension_count > 0);
      
      bool closed = CloseHandle(thread_handle);
      if (!closed) {
        return ProgramResult(ProgramResult::ResultType::kError, THREAD_CLOSE_ERR_MSG);
      }
    }
  } while (Thread32Next(handle_thread_snap, &thread_entry));

    bool closed = CloseHandle(handle_thread_snap);
    if (!closed) {
      return ProgramResult(ProgramResult::ResultType::kError, PROC_CLOSE_ERR_MSG);
    }

    suspended_ = false;
    return ProgramResult(ProgramResult::ResultType::kOk, "All process' threads resumed");
}

ProgramResult ProcessCapturer::KillProcess(UINT exit_code) {

  if (!IsProcessAlive()) {
    return ProgramResult(ProgramResult::ResultType::kError, PROC_NOT_ALIVE_ERR_MSG);
  }

  HANDLE proc_handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid_);

  if (proc_handle == NULL) {
    return ProgramResult(ProgramResult::ResultType::kError, PROC_OPEN_ERR_MSG);
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

bool ProcessCapturer::IsSuspended() {
  return suspended_;
}

DWORD ProcessCapturer::GetPid() {
  return pid_;
}

} // namespace process_manipulation