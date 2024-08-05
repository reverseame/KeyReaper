#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "Kernel32.lib")

#include "key_scanner.h"
#include "process_capturer.h"
using ProgramResult = error_handling::ProgramResult;
using ErrorResult = error_handling::ErrorResult;
using OkResult = error_handling::OkResult;
using StructureScanner = key_scanner::StructureScan;
using Key = key_scanner::Key;

#include <iostream>
SIZE_T show_module(MEMORY_BASIC_INFORMATION info) {
    SIZE_T usage = 0;

    printf(" Allocation base: 0x%p\n", (void*) info.AllocationBase);
    printf(" Region size: 0x%zx\n", info.RegionSize);
    printf(" Last region address: 0x%p\n", (void*)(info.RegionSize + (ULONG_PTR) info.AllocationBase));


    std::cout << " [i] " << info.BaseAddress << "(" << info.RegionSize / 1024 << ")\t";
    switch (info.State) {
    case MEM_COMMIT:
        std::cout << "Committed";
        break;
    case MEM_RESERVE:
        std::cout << "Reserved";
        break;
    case MEM_FREE:
        std::cout << "Free";
        break;
    }
    std::cout << "\t";
    switch (info.Type) {
    case MEM_IMAGE:
        std::cout << "Code Module";
        break;
    case MEM_MAPPED:
        std::cout << "Mapped     ";
        break;
    case MEM_PRIVATE:
        std::cout << "Private    ";
    }
    std::cout << "\t";

    int guard = 0, nocache = 0;

    if ( info.AllocationProtect & PAGE_NOCACHE)
        nocache = 1;
    if ( info.AllocationProtect & PAGE_GUARD )
        guard = 1;

    info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

    if ((info.State == MEM_COMMIT) && (info.AllocationProtect == PAGE_READWRITE || info.AllocationProtect == PAGE_READONLY))
        usage += info.RegionSize;

    switch (info.AllocationProtect) {
    case PAGE_READONLY:
        std::cout << "Read Only";
        break;
    case PAGE_READWRITE:
        std::cout << "Read/Write";
        break;
    case PAGE_WRITECOPY:
        std::cout << "Copy on Write";
        break;
    case PAGE_EXECUTE:
        std::cout << "Execute only";
        break;
    case PAGE_EXECUTE_READ:
        std::cout << "Execute/Read";
        break;
    case PAGE_EXECUTE_READWRITE:
        std::cout << "Execute/Read/Write";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        std::cout << "COW Executable";
        break;
    }

    if (guard)
        std::cout << "\tguard page";
    if (nocache)
        std::cout << "\tnon-cacheable";
    std::cout << "\n\n";
    return usage;
}

namespace process_manipulation {

ProcessCapturer::ProcessCapturer(int pid) 
    : pid_(pid), suspended_(false), is_privileged_(false) {

  ProgramResult pr = ObtainSeDebug();
  std::cout << " [i] " << pr.GetResultInformation() << std::endl;
  
  // TODO: check if the process is wow64.
  //       would work in 32 bit?

}

ProgramResult ProcessCapturer::PauseProcess(bool force_pause) {

  if (!IsProcessAlive()) {
    return ErrorResult(PROC_NOT_ALIVE_ERR_MSG);
  }

  if (!force_pause && IsSuspended()) {
    return ErrorResult(PROC_SUSP_ERR_MSG);
  }

  printf("[i] Creating process snapshot\n");
  HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (thread_snapshot == INVALID_HANDLE_VALUE) {
    return ErrorResult(THREAD_SNAP_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("All process' threads paused");

  THREADENTRY32 thread_entry; 
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(thread_snapshot, &thread_entry);
  if (!copied) {
    func_result = ErrorResult(THREAD_SNAP_FIRST_ERR_MSG);

  } else if (GetLastError() == ERROR_NO_MORE_FILES) {
    func_result = ErrorResult(THREAD_SNAP_NO_INFO_ERR_MSG);

  } else {
    int n_threads = 0;
    do {
      if (thread_entry.th32OwnerProcessID == pid_) {
        printf(" [%i]\r", ++n_threads);

        HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, 
                                          thread_entry.th32ThreadID);
        if (thread_handle == NULL) {
          func_result = ErrorResult(THREAD_OPEN_ERR_MSG);
          break;
        }
              
        DWORD suspension_count = SuspendThread(thread_handle);
        if (suspension_count == (DWORD) - 1) {
          // TODO include exact number in error text with a formatter
          func_result = ErrorResult(THEAD_MAX_SUS_COUNT_ERR_MSG);
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
    return ErrorResult(PROC_NOT_ALIVE_ERR_MSG);
  }

  if (!force_resume && !IsSuspended()) {
    return ErrorResult(PROC_STILL_RUN_ERR_MSG);
  }

  printf("[i] Creating process snapshot\n");
  HANDLE handle_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (handle_thread_snap == INVALID_HANDLE_VALUE) {
    return ErrorResult(THREAD_SNAP_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("All process' threads resumed");

  THREADENTRY32 thread_entry;
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(handle_thread_snap, &thread_entry);
  if (!copied) {
    func_result = ErrorResult(THREAD_SNAP_FIRST_ERR_MSG);

  } else if (GetLastError() == ERROR_NO_MORE_FILES) {
    func_result = ErrorResult(THREAD_SNAP_NO_INFO_ERR_MSG);

  } else {
    int n_threads = 0;
    do {
      if (thread_entry.th32OwnerProcessID == pid_) {
        printf("[%i] Reducing to zero the number of pauses\n", ++n_threads);

        HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
        if (thread_handle == NULL) {
          func_result = ErrorResult(THREAD_OPEN_ERR_MSG);
          break;
        }

        // Reduce the suspension count to zero
        DWORD suspension_count;
        do {
          suspension_count = ResumeThread(thread_handle) - 1; // ResumeThread returns the PREVIOUS pause count
          if (suspension_count == (DWORD) - 1) {
            // TODO include exact number in error text with a formatter
            func_result = ErrorResult(THREAD_RESUME_ERR_MSG);
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

  ProgramResult func_result = OkResult("Process terminated");

  if (!IsProcessAlive()) {
    func_result = ErrorResult(PROC_NOT_ALIVE_ERR_MSG);

  } else {
    HANDLE proc_handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid_);
    if (proc_handle == NULL) {
      func_result = ErrorResult(PROC_OPEN_ERR_MSG);

    } else {
      bool success = TerminateProcess(proc_handle, exit_code);
      if (!success) {
        func_result = ErrorResult("Could not terminate the process");
      }
    }

    suspended_ = false;
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

ProgramResult ProcessCapturer::GetMemoryChunk(LPCVOID start, SIZE_T size, BYTE* buffer, SIZE_T* bytes_read) {
  HANDLE process_handle = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE, pid_ );

  if (process_handle == NULL) {
    return ErrorResult(PROC_OPEN_ERR_MSG);
  }

  ProgramResult func_result = OkResult("Heap data retrieved");

  *bytes_read = !NULL; // don't init at zero (NULL), otherwise, it will take the parameter as optional
  BOOL result = ReadProcessMemory(process_handle, start, reinterpret_cast<LPVOID>(buffer), size, bytes_read);
  if (result == 0) {
    { // TODO: only verbose mode
      printf("Bytes read: %zu\n", *bytes_read);
      printf("Base address:      0x%p\n", (void*) start);
      ULONG_PTR last_address_read = (ULONG_PTR) start + *bytes_read;
      printf("Last address read: 0x%p\n", (void*) last_address_read);
      printf("Expected last add: 0x%p\n", (void*) ((ULONG_PTR) start + size - 1));
    }

    MEMORY_BASIC_INFORMATION info;
    LPCVOID starting_address = (LPCVOID)((ULONG_PTR) start + (ULONG_PTR) *bytes_read + 1);
    // LPCVOID address = (LPCVOID) ((ULONG_PTR) start + size - 1); // breaking part of the chunk
    
    SIZE_T info_bytes = VirtualQueryEx(process_handle, starting_address, &info, sizeof(info));

    printf(" FAULTING ADDRESS: %p\n", starting_address);
    if (info_bytes == ERROR_INVALID_PARAMETER && info_bytes != sizeof(info)) {
      printf(" Address above the valid address space\n");
      func_result = ErrorResult(std::string("Address above the valid address space. Win error: ").append(std::to_string(GetLastError())));

    } else {

      /*
      unsigned long usage = 0;
      for ( LPCVOID address = starting_address;
        VirtualQueryEx(process_handle, address, &info, sizeof(info)) == sizeof(info);
        address = (LPCVOID)((ULONG_PTR) address + info.RegionSize) ) {
        usage += show_module(info);
      }
      */
      func_result = ErrorResult(std::string("Could not read process memory. Error: ").append(std::to_string(GetLastError())));
    }

  } else {
    if (*bytes_read > size) {
      printf("Data written was bigger than buffer\n");
      exit(ERROR_BUFFER_OVERFLOW);
    }
  }

  printf("Buffer size: %+10zu\n", size);
  printf("Bytes read:  %+10zu\n", *bytes_read);
  CloseHandle(process_handle);
  return func_result;
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
    return ErrorResult("Could not open handle to snapshot");
  }

  ProgramResult func_result = OkResult("Heap enumerated successfully");

  if( Heap32ListFirst(hHeapSnap, &hl)) {
    do {
      HEAPENTRY32 he;
      ZeroMemory(&he, sizeof(HEAPENTRY32));
      he.dwSize = sizeof(HEAPENTRY32);

      if( Heap32First(&he, pid_, hl.th32HeapID )) {

        HeapInformation heap_data = HeapInformation(he);
        ULONG_PTR next_address = he.dwAddress; // the first address of the following block

        SIZE_T total_size = 0;
        do {
          total_size += he.dwBlockSize;
          he.dwSize = sizeof(HEAPENTRY32);

          /*
          {
            printf("Block base: %p\n", (void*) he.dwAddress);
            printf("Block size: %u\n", he.dwBlockSize);
            printf("Final addr: %p\n", he.dwAddress + he.dwBlockSize - 1);
            printf("Next addre: %p\n", he.dwAddress + he.dwBlockSize);
            //printf("---\n");
          }
          */

          // Q: what if the blocks are not adjacent
          if (next_address != he.dwAddress) { printf("\nMismatch\n\n"); }
          next_address = he.dwAddress + he.dwBlockSize;

          // TODO: may consider ruling out free blocks LF32_FREE
          // Q: what if they are scattered?
          // (The heap manager probably tries to minimize fragmentation)
          /*
          {
            DWORD flags = he.dwFlags;
            if (flags == LF32_FREE) {printf("FREE (%d)\t", flags);}
            else if (flags == LF32_FIXED) {printf("FIXED (%d)\t", flags);}
            else if (flags == LF32_MOVEABLE) {printf("MOVEABLE (%d)\t", flags);}
            else {printf("Else: %d\t", flags);}
            printf("\n----\n");
          }
          */
        } while ( Heap32Next(&he) );

        // If the last block is free, then is the top chunk
        if (he.dwFlags == LF32_FREE) {
          // It will generate invalid addresses, therefore we should remove it
          total_size -= he.dwBlockSize;
        }

        heap_data.size = total_size;
        heap_data.final_address = total_size - 1 + heap_data.base_address;
        heaps->push_back(heap_data);

        printf("======\n");
        printf("Heap ID: %zd\n", hl.th32HeapID );
        printf("Base address: 0x%p\n", (void*) heap_data.base_address );
        printf("Size of heap: %zu\n", total_size);
        printf("Final address: 0x%p\n", (void*) heap_data.final_address);
        printf("\n");
      }
      hl.dwSize = sizeof(HEAPLIST32);
    } while (Heap32ListNext( hHeapSnap, &hl));
  
  } else { 
    printf ("Cannot list first heap (%d)\n", GetLastError());
    func_result = ErrorResult("Cannot list first heap");
  }
   
  CloseHandle(hHeapSnap);
  return func_result;
}

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
ProgramResult ProcessCapturer::CopyProcessHeap(HeapInformation heap_to_copy, unsigned char** output_buffer, SIZE_T* size) {
  printf("Getting heaps\n");

  HEAPLIST32 hl;
  HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid_);
  hl.dwSize = sizeof(HEAPLIST32);

  if ( hHeapSnap == INVALID_HANDLE_VALUE ) {
    printf ("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
    return ErrorResult("Could not open handle to snapshot");
  }

  ProgramResult func_result = OkResult("Heaps copied successfully");

  HANDLE process_handle = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE, pid_ );
  if (process_handle == NULL) {
    return ErrorResult(PROC_OPEN_ERR_MSG);
  }

  unsigned char* buffer = NULL;
  SIZE_T position = 0;
  SIZE_T failed_reads = 0;
  bool found = false;

  // TODO: consider controlling the heap mutex with HeapLock and also check 
  //       if it was already locked
  // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaplock
  if( Heap32ListFirst(hHeapSnap, &hl)) {
    do {
      HEAPENTRY32 he;
      ZeroMemory(&he, sizeof(HEAPENTRY32));
      he.dwSize = sizeof(HEAPENTRY32);

      if (hl.th32HeapID != heap_to_copy.id) { continue; }
      found = true;
      printf("Total size: %zu\n", heap_to_copy.size);

      buffer = (unsigned char*) calloc(sizeof(unsigned char), heap_to_copy.size);
      if (buffer == NULL) {
        func_result = ErrorResult("Could not allocate memory for the heap data");
      
      } else if ( Heap32First(&he, pid_, hl.th32HeapID )) {
        
        // TODO: instead of checking each heap block, check the pages within
        //       this could reveal pages hiddenly used with old valid addresses?
        do {
          printf("[%zu]\r", position);
          bool nullify = false;
          SIZE_T bytes_read = !NULL;

          // LF32_MOVEABLE??
          if (he.dwFlags == LF32_FREE) {
            nullify = true;
            bytes_read = 0;

          } else {
            he.dwSize = sizeof(HEAPENTRY32);
            SIZE_T bytes_read = !NULL; // don't init at zero (NULL), otherwise, it will take the parameter as optional
            BOOL result = ReadProcessMemory(process_handle, (LPCVOID) he.dwAddress, (LPVOID) (buffer + position), he.dwBlockSize, &bytes_read);
            if (result == 0) { // read error
              //printf("Error copying at buffer position %d. Retrieved %u bytes, filling up to %u with FF\n", position, bytes_read, he.dwBlockSize - 1);
              //printf("Windows error: %d\n", GetLastError()); 
              nullify = true;
            }
          } 

          if (nullify) {
            // Nullifiy region
            failed_reads += he.dwBlockSize - bytes_read;
            for (size_t i = bytes_read + 1; i < he.dwBlockSize; i++) {
              buffer[position + i] = 0xFF;
            }
          }
      
          position += he.dwBlockSize;

        } while ( Heap32Next(&he) && position < heap_to_copy.size);
        // && position < heap_to_copy.size
        // if we want not to consider the top chunk
      }

      hl.dwSize = sizeof(HEAPLIST32);
    } while (Heap32ListNext( hHeapSnap, &hl) && !found);

    printf("Failed reads: %zu\n", failed_reads);
    *size = position;
    *output_buffer = buffer;
    CloseHandle(process_handle);
  
  } else { 
    printf ("Cannot list first heap (%d)\n", GetLastError());
    func_result = ErrorResult("Cannot list first heap");
  }
   
  CloseHandle(hHeapSnap);
  return func_result;
}

// https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
error_handling::ProgramResult ProcessCapturer::ObtainSeDebug() {
  
  ProgramResult func_result = OkResult("Process obtained SeDebugPrivilege successfully");

  HANDLE token;
  bool success = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
  if (success) {
    TOKEN_PRIVILEGES new_privilege;
    PRIVILEGE_SET privilegeSet;
    LUID luid;
    // https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
    bool success = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    if (success) {
      
      privilegeSet.PrivilegeCount = 1;
      privilegeSet.Privilege[0].Luid = luid;
      privilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
      privilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;

      BOOL privilege_found = false;
      if (!PrivilegeCheck(token, &privilegeSet, &privilege_found)) {
        printf("PrivilegeCheck failed. Error: %lu. Trying to elevate\n", GetLastError());
        privilege_found = false;
      }

      if (privilege_found) {
        is_privileged_ = true;
        func_result = OkResult("Privilege already owned");

      } else {
        new_privilege.PrivilegeCount = 1;
        new_privilege.Privileges[0].Luid = luid;
        new_privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        success = AdjustTokenPrivileges(token, FALSE, &new_privilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        if (success && GetLastError() == ERROR_SUCCESS) {
          is_privileged_ = true;
          
        } else {
          func_result = ErrorResult("Could not obtain SeDebugPrivilege");
        }
      }
    } else {
      func_result = ErrorResult("Could not retrieve token information");
    }

    CloseHandle(token);

  } else {
    func_result = ErrorResult("Could not open process token");
  }

  return func_result;
}

bool ProcessCapturer::IsPrivileged() {
  return is_privileged_;
}

void ProcessCapturer::PrintMemory(unsigned char* buffer, SIZE_T num_of_bytes, ULONG_PTR starting_visual_address) {
  printf("            0           4           8           C");
  for (size_t i = 0; i < num_of_bytes; i++) {
    if (i % 16 == 0) {
      printf("\n [%p] ", (void*) (i + (ULONG_PTR) starting_visual_address));
    }
    printf("%02X ", buffer[i]);
  } printf("\n");
}

bool ProcessCapturer::IsSuspended() {
  return suspended_;
}

DWORD ProcessCapturer::GetPid() const {
  return pid_;
}

} // namespace process_manipulation