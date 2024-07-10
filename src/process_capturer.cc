#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "Kernel32.lib")

#include "process_capturer.h"


ProcessCapturer::ProcessCapturer(int pid) {
  
  pid_ = pid;
  suspended_ = false;

  // TODO: check if the process is wow64.
  //       would work in 32 bit?

}

/**
 * Warning! This function does not check the state of the process.
*/
ProgramResult ProcessCapturer::PauseProcess() {

  if (suspended_) {
    return ProgramResult(ProgramResult::ResultType::kError, "Process was already suspended");
  }

  HANDLE handle_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (handle_thread_snap == INVALID_HANDLE_VALUE) {
    return ProgramResult(ProgramResult::ResultType::kError, "Could not create a snapshot of the threads");
  }

  printf("[i] Creating process snapshot\n");
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
      HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE,
      thread_entry.th32ThreadID);
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

ProgramResult ProcessCapturer::ResumeProcess() {
  // TODO - implement ProcessCapturer::resumeProcess
  throw "Not yet implemented";
}

ProgramResult ProcessCapturer::KillProcess() {
  // TODO - implement ProcessCapturer::killProcess
  throw "Not yet implemented";
}

void ProcessCapturer::SetSuspendPtr(int ThreadSuspendFunction) {
  // TODO - implement ProcessCapturer::setSuspendPtr
  throw "Not yet implemented";
}

bool ProcessCapturer::IsSuspended() {
  // TODO - implement ProcessCapturer::isSuspended
  throw "Not yet implemented";
}

ProgramResult ProcessCapturer::GetMemoryChunk(int start, int size, char* buffer) {
  // TODO - implement ProcessCapturer::getMemoryChunk
  throw "Not yet implemented";
}

DWORD ProcessCapturer::GetPid() {
  return pid_;
}