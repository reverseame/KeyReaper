#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "Kernel32.lib")

#include "key_scanner.h"
#include "process_capturer.h"
using ProgramResult = error_handling::ProgramResult;
using ErrorResult = error_handling::ErrorResult;
using OkResult = error_handling::OkResult;
using Key = key_scanner::Key;

#include <vector>
#include <algorithm>
using namespace std;

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
nt_suspend::pNtSuspendProcess ProcessCapturer::fNtPauseProcess = nullptr; // static class member

ULONG_PTR BlockInformation::GetBaseAddress() const { return base_address_; }
ULONG_PTR BlockInformation::GetLastAddress() const { return base_address_ + size_ - 1; }

SIZE_T BlockInformation::GetSize() const { return size_; }

bool BlockInformation::operator<(const BlockInformation& other) const {
  return base_address_ < other.base_address_;
}

bool BlockInformation::operator==(const BlockInformation& other) const {
  return base_address_ == other.base_address_;
}

bool BlockInformation::IsAdjacent(const BlockInformation other) const {
  return (other.base_address_ == base_address_ + size_);
}

void BlockInformation::CoalesceWith(const BlockInformation new_block) {
  size_ += new_block.GetSize();
}

SIZE_T HeapInformation::GetSize() const {
  if (blocks_.empty()) {
    return 0;
  }

  return final_address_ - base_address_;
}

ULONG_PTR HeapInformation::GetBaseAddress() const {
  return base_address_;
}

ULONG_PTR HeapInformation::GetLastAddress() const {
  return final_address_;
}

const vector<BlockInformation> HeapInformation::GetBlocks() const {
  return blocks_;
}

bool HeapInformation::IsAddressInHeap(ULONG_PTR pointer) const {
  return pointer <= GetLastAddress() && pointer >= GetBaseAddress();
};

bool HeapInformation::IsBlockInHeap(BlockInformation block) const {
  return IsAddressInHeap(block.GetBaseAddress()) && IsAddressInHeap(block.GetLastAddress());
}

bool HeapInformation::RebaseAddress(ULONG_PTR* pointer, ULONG_PTR new_base_address) const {
  if (!IsAddressInHeap(*pointer)) {
    
    printf(" > Pointer: %p\n", (void*) *pointer);
    printf(" > Final:   %p\n", (void*) GetLastAddress());
    printf(" > Base:    %p\n", (void*) GetBaseAddress());
    
    return false;
  
  } else {
    *pointer -= GetBaseAddress();
    *pointer += new_base_address;
    return true;
  }
}

void HeapInformation::AddBlock(BlockInformation new_block) {

  ULONG_PTR new_block_last_add = new_block.GetBaseAddress() + new_block.GetSize() - 1;
  if (final_address_ < new_block_last_add) final_address_ = new_block_last_add;

  // If blocks are adjacent, they get coalesced
  if (!blocks_.empty() && blocks_.back().IsAdjacent(new_block)) {
    blocks_.back().CoalesceWith(new_block);

  } else {
    // Add block to list
    blocks_.push_back(new_block);
  }
}

ProcessCapturer::ProcessCapturer(int pid) 
    : pid_(pid), suspended_(false), is_privileged_(false) {

  ProgramResult pr = ObtainSeDebug();
  std::cout << " [i] " << pr.GetResultInformation() << std::endl;
  
  // TODO: check if the process is wow64.
  //       would work in 32 bit?

}

// TODO: add an argument for caching the thread list
error_handling::ProgramResult ProcessCapturer::EnumerateThreads(std::vector<DWORD> *TID_list) {

  if (!IsProcessAlive()) {
    return ErrorResult(PROC_NOT_ALIVE_ERR_MSG);
  }

  printf("[i] Creating process snapshot\n");
  HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (thread_snapshot == INVALID_HANDLE_VALUE) {
    return ErrorResult(THREAD_SNAP_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("All process's theads information retrieved");

  THREADENTRY32 thread_entry;
  thread_entry.dwSize = sizeof(THREADENTRY32);
  BOOL copied = Thread32First(thread_snapshot, &thread_entry);
  if (!copied) {
    func_result = ErrorResult(THREAD_SNAP_FIRST_ERR_MSG);
      
  } else if (GetLastError() == ERROR_NO_MORE_FILES) {
  func_result = ErrorResult(THREAD_SNAP_NO_INFO_ERR_MSG);

  } else {
    do {
      if (thread_entry.th32OwnerProcessID == pid_) {
        TID_list->push_back(thread_entry.th32ThreadID);
      }
    } while (Thread32Next(thread_snapshot, &thread_entry));
  }

  // We should always close the handle
  CloseHandle(thread_snapshot);
  return func_result;
}

ProgramResult ProcessCapturer::PauseProcess(bool force_pause) {
  printf("Pausing process\n");

  if (!force_pause && IsSuspended()) {
    return ErrorResult(PROC_SUSP_ERR_MSG);
  }

  vector<DWORD> thread_list;
  ProgramResult enumeration_result = EnumerateThreads(&thread_list);
  if (enumeration_result.IsErr()) return enumeration_result; // Retrieve error yielded

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("All process' threads paused");

  for (auto thread_id : thread_list) {

    ProgramResult pause_result = PauseSingleThread(thread_id);
    if (pause_result.IsErr()) {
      func_result = pause_result;
      break;
    }
  }

  if (func_result.IsOk()) suspended_ = true;
  return func_result;
}

error_handling::ProgramResult ProcessCapturer::PauseProcessNt(bool force_pause) {

  if (fNtPauseProcess == nullptr) {
    ProgramResult exports_result = InitializeExports();
    if (exports_result.IsErr()) {
      return exports_result;
    }
  }

  ProgramResult func_result = OkResult("Successfully paused the process");

  HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);
  NTSTATUS pause_result = fNtPauseProcess(process_handle);
  if (pause_result < 0) {
    printf("ERROR: %u", pause_result);
    func_result = ErrorResult("Could not pause process using NT");
  }

  CloseHandle(process_handle);
  return func_result;
}

ProgramResult ProcessCapturer::ResumeProcess(bool force_resume) {
  printf("Resuming process\n");

  if (!force_resume && !IsSuspended()) {
    return ErrorResult(PROC_STILL_RUN_ERR_MSG);
  }

  vector<DWORD> thread_list;
  ProgramResult enumeration_result = EnumerateThreads(&thread_list);
  if (enumeration_result.IsErr()) return enumeration_result; // Retrieve error yielded

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("All process' threads resumed");

  for (auto thread_id : thread_list) {

    ProgramResult resume_result = ResumeSingleThread(thread_id);
    if (resume_result.IsErr()) {
      func_result = resume_result;
      break;
    }
  }

  if (func_result.IsOk()) suspended_ = false;
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

error_handling::ProgramResult ProcessCapturer::PauseSingleThread(DWORD th32ThreadID_to_pause) {

  // Get handle to thread
  HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, th32ThreadID_to_pause);
  if (thread_handle == NULL) {
    return ErrorResult(THREAD_OPEN_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("Thread successfully paused");

  // Pause thread
  DWORD suspension_count = SuspendThread(thread_handle);
  if (suspension_count == (DWORD) - 1) {
    // TODO include exact number in error text with a formatter
    func_result = ErrorResult(THEAD_PAUSE_ERR_MSG);
  }
  printf("[%u] Suspension count: %u\n", th32ThreadID_to_pause, suspension_count + 1);
  
  CloseHandle(thread_handle);
  return func_result;
}

error_handling::ProgramResult ProcessCapturer::ResumeSingleThread(DWORD th32ThreadID_to_resume) {

  // Obtain a handle to the thread
  HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, th32ThreadID_to_resume);
  if (thread_handle == NULL) {
    return ErrorResult(THREAD_OPEN_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("Thread successfully paused");
  
  // Reduce the suspension count to zero
  printf("[%u] Reducing to zero the number of pauses\n", th32ThreadID_to_resume);
  DWORD suspension_count;
  do {
    suspension_count = ResumeThread(thread_handle) - 1; // ResumeThread returns the PREVIOUS pause count
    if (suspension_count == (DWORD) - 1) {
      // TODO include exact number in error text with a formatter
      func_result = ErrorResult(THREAD_RESUME_ERR_MSG);
      break;
    }
  } while (suspension_count > 0);

  CloseHandle(thread_handle);
  return func_result;
}

error_handling::ProgramResult ProcessCapturer::KillSingleThread(DWORD th32ThreadID_to_kill, DWORD exit_code) {

  // Get handle to thread
  HANDLE thread_handle = OpenThread(THREAD_TERMINATE, FALSE, th32ThreadID_to_kill);
  if (thread_handle == NULL) {
    return ErrorResult(THREAD_OPEN_ERR_MSG);
  }

  // Errors will overwrite this variable. If there are not, the program will return this
  ProgramResult func_result = OkResult("Thread successfully terminated");

  // Kill thread
  DWORD termination_result = TerminateThread(thread_handle, exit_code);
  if (termination_result == 0) {
    func_result = ErrorResult("Could not terminate thread");
  }

  CloseHandle(thread_handle);
  return func_result;
}

void ProcessCapturer::SetSuspendPtr(int ThreadSuspendFunction) {
  // TODO - implement ProcessCapturer::setSuspendPtr
  throw "Not yet implemented";
}

error_handling::ProgramResult ProcessCapturer::InitializeExports() {

  ProgramResult func_result = OkResult("Successfully initialized all exports");

  HMODULE ntdll_handle = GetModuleHandleA("NTDLL");
  if (ntdll_handle == NULL) {
    func_result = ErrorResult("Could not obtain a handle to NTDLL");
  
  } else {
    ProcessCapturer::fNtPauseProcess = (nt_suspend::pNtSuspendProcess) GetProcAddress(ntdll_handle, "NtSuspendProcess");
    if (ProcessCapturer::fNtPauseProcess == NULL) {
      func_result = ErrorResult("Could not initialize NtResumeProcess function");
    }
  }

  return func_result;
}

bool ProcessCapturer::IsProcessAlive() const {
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

  ProgramResult func_result = OkResult("Data copied");

  *bytes_read = !NULL; // don't init at zero (NULL), otherwise the call won't (over)write this variable with the number of bytes read
  BOOL result = ReadProcessMemory(process_handle, start, reinterpret_cast<LPVOID>(buffer), size, bytes_read);
  if (result == 0) {
    func_result = ErrorResult( "Could not read process' memory. Windows error: " + error_handling::GetLastErrorAsString() );

  } else {
    if (*bytes_read > size) {
      printf("[x] Data written was bigger than buffer\n");
      exit(ERROR_BUFFER_OVERFLOW);
    }
  }

  printf("Buffer size: %+10zu\n", size);
  printf("Bytes read:  %+10zu\n", *bytes_read);
  CloseHandle(process_handle);
  return func_result;
}


ProgramResult ProcessCapturer::EnumerateHeaps(std::vector<HeapInformation> *heaps) {
  printf("Getting and coalescing heaps\n");

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
        SIZE_T orignial_block_amount = 0;
        HeapInformation heap_data = HeapInformation(he);
        do {
          // Don't add free blocks, since they will fail to copy
          if (he.dwFlags != LF32_FREE) {
            orignial_block_amount++;

            heap_data.AddBlock(
              BlockInformation(he.dwAddress, he.dwBlockSize)
            );
          }
          he.dwSize = sizeof(HEAPENTRY32);
        } while ( Heap32Next(&he) );

        // Order does not matter, since the reconstruction adjusts the position accordingly
        // sort(heap_data.blocks_.begin(), heap_data.blocks_.end());

        // Add the enumerated heap to the list
        heaps->push_back(heap_data);

        printf("======\n");
        printf("Heap ID: %zd\n", hl.th32HeapID );
        printf(" Base address: 0x%p\n", (void*) heap_data.GetBaseAddress());
        printf(" Size of heap: %zu\n", heap_data.GetSize());
        printf(" Final address: 0x%p\n", (void*) heap_data.GetLastAddress());
        printf("  - Original block amount:   %zu\n", orignial_block_amount);
        printf("  - Blocks after coallition: %zu\n", heap_data.GetBlocks().size());
        printf("\n");
      }

      hl.dwSize = sizeof(HEAPLIST32);
    } while ( Heap32ListNext(hHeapSnap, &hl) );
  
  } else { 
    printf ("Cannot list first heap (%d)\n", GetLastError());
    func_result = ErrorResult("Cannot list first heap");
  }
   
  CloseHandle(hHeapSnap);
  return func_result;
}

ProgramResult ProcessCapturer::CopyHeapData(HeapInformation heap_to_copy, unsigned char **output_buffer) {
  printf("Copying heap data\n");

  if (heap_to_copy.GetBlocks().empty()) {
    return ErrorResult("This heap is either empty or data not properly initialized. Please call EnumerateHeaps before this function");
  }

  HANDLE process_handle = OpenProcess( PROCESS_VM_READ , FALSE, pid_ );

  if (process_handle == NULL) {
    return ErrorResult(PROC_OPEN_ERR_MSG);
  }

  ProgramResult func_result = OkResult("Heap copied succcessfully");

  // Reservar la memoria para todo el heap
  unsigned char* buffer = (unsigned char*) calloc(heap_to_copy.GetSize(), sizeof(unsigned char*));

  SIZE_T failed_reads = 0;
  for (BlockInformation block : heap_to_copy.GetBlocks()) {

    // Copy the block to its relative position in the buffer
    ULONG_PTR block_position = block.GetBaseAddress() - heap_to_copy.GetBaseAddress();
    if ( heap_to_copy.IsBlockInHeap(block) ) {
      SIZE_T bytes_read = !NULL; // don't init at zero (NULL), otherwise the call won't (over)write this variable with the number of bytes read
      BOOL read_ok = ReadProcessMemory(process_handle, (void*) block.GetBaseAddress(), buffer + block_position, block.GetSize(), &bytes_read);

      if (!read_ok) {
        if (GetLastError() == ERROR_PARTIAL_COPY) { // Acceptable error.
          // TODO: check the page in which are located to ensure we have enough permissions
          failed_reads += block.GetSize() - bytes_read;

        } else {
          cout << error_handling::GetLastErrorAsString() << endl; 
        }
      }
    } else {
      printf("Block out of heap?\n");
    }
  }

  *output_buffer = buffer;
  cout << "Failed reads: " << failed_reads << endl;
  CloseHandle(process_handle);
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

bool ProcessCapturer::IsPrivileged() const {
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

bool ProcessCapturer::IsSuspended() const {
  return suspended_;
}

DWORD ProcessCapturer::GetPid() const {
  return pid_;
}

} // namespace process_manipulation