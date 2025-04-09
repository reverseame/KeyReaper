#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <fstream>
#include <tlhelp32.h>
#pragma comment(lib, "Kernel32.lib")

#include "key_scanner.h"
#include "process_capturer.h"
#include <ntdll.h>
#include <TitanEngine.h>
#include <winntheap.h>
#include "config.h"
#include "injection/injector.h"
#include "injection/custom_ipc.h"
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

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va)          ((ULONG_PTR)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
static bool IgnoreThisRead(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
  typedef BOOL(WINAPI * QUERYWORKINGSETEX)(HANDLE, PVOID, DWORD);
  static auto fnQueryWorkingSetEx = QUERYWORKINGSETEX(GetProcAddress(GetModuleHandleW(L"psapi.dll"), "QueryWorkingSetEx"));
  if(!fnQueryWorkingSetEx)
    return false;
  PSAPI_WORKING_SET_EX_INFORMATION wsi;
  wsi.VirtualAddress = (PVOID) PAGE_ALIGN(lpBaseAddress);
  if(fnQueryWorkingSetEx(hProcess, &wsi, sizeof(wsi)) && !wsi.VirtualAttributes.Valid) {
    MEMORY_BASIC_INFORMATION mbi;
    if(VirtualQueryEx(hProcess, wsi.VirtualAddress, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT/* && mbi.Type == MEM_PRIVATE*/) {
      memset(lpBuffer, 0, nSize);
      if(lpNumberOfBytesRead)
        *lpNumberOfBytesRead = nSize;
      return true;
    }
  }
  return false;
}

bool MemoryReadSafePage(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
  if(IgnoreThisRead(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead))
    return true;
  return MemoryReadSafe(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

bool MemIsCanonicalAddress(UINT_PTR Address) {
#ifndef _WIN64
    // 32-bit mode only supports 4GB max, so limits are
    // not an issue
    return true;
#else
    // The most-significant 16 bits must be all 1 or all 0.
    // (64 - 16) = 48bit linear address range.
    //
    // 0xFFFF800000000000 = Significant 16 bits set
    // 0x0000800000000000 = 48th bit set
    return (((Address & 0xFFFF800000000000) + 0x800000000000) & ~0x800000000000) == 0;
#endif //_WIN64
}

bool MemReadDumb(HANDLE proc_handle, UINT_PTR BaseAddress, void* Buffer, SIZE_T Size) {
  if(!MemIsCanonicalAddress(BaseAddress) || !Buffer || !Size)
    return false;

  SIZE_T offset = 0;
  SIZE_T requestedSize = Size;
  SIZE_T sizeLeftInFirstPage = PAGE_SIZE - (BaseAddress & (PAGE_SIZE - 1));
  SIZE_T readSize = min(sizeLeftInFirstPage, requestedSize);

  bool success = true;
  while(readSize) {
    SIZE_T bytesRead = 0;
    if(!MemoryReadSafePage(proc_handle, (PVOID)(BaseAddress + offset), (PBYTE)Buffer + offset, readSize, &bytesRead))
      success = false;
    offset += readSize;
    requestedSize -= readSize;
    readSize = min((SIZE_T)PAGE_SIZE, requestedSize);
  }
  return success;
}

ULONG_PTR GetRegionStart(HANDLE process, ULONG_PTR valid_address_in_region) {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQueryEx(process, (LPCVOID) valid_address_in_region, &mbi, sizeof(mbi))) {
    return  (ULONG_PTR) mbi.BaseAddress;
  }
  return 0;
}

SIZE_T GetRegionSize(HANDLE hProcess, ULONG_PTR heapBase) {
  SIZE_T totalSize = 0;
  MEMORY_BASIC_INFORMATION mbi;
  LPVOID currentAddress = reinterpret_cast<LPVOID>(heapBase);

  while (VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi))) {
    // Stop if we hit an uncommitted region
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE)
      break;

    totalSize += mbi.RegionSize;
    currentAddress = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
  }

  return totalSize;
}

nt_suspend::pNtSuspendProcess ProcessCapturer::fNtPauseProcess = nullptr; // static class member

SIZE_T HeapSegment::GetSize() const {
  return size_;
}

ULONG_PTR HeapSegment::GetBaseAddress() const {
  return base_address_;
}

ULONG_PTR HeapSegment::GetLastAddress() const {
  return base_address_ + size_;
}

bool HeapSegment::IsAddressInHeap(ULONG_PTR pointer) const {
  return pointer <= GetLastAddress() && pointer >= GetBaseAddress();
};

bool HeapSegment::RebaseAddress(ULONG_PTR* pointer, ULONG_PTR new_base_address) const {
  if (!IsAddressInHeap(*pointer)) {
    
    // printf(" > Pointer: %p\n", (void*) *pointer);
    // printf(" > Final:   %p\n", (void*) GetLastAddress());
    // printf(" > Base:    %p\n", (void*) GetBaseAddress());
    
    return false;
  
  } else {
    *pointer -= GetBaseAddress();
    *pointer += new_base_address;
    return true;
  }
}

ProcessCapturer::ProcessCapturer(unsigned int pid) 
    : pid_(pid), suspended_(false), is_privileged_(false), is_controller_dll_injected_(false), 
    is_mailslot_server_started_(false), mailslot_thread_handle_(NULL), is_controller_server_running_(false),
    injection_client_(pid), proc_handle_(NULL) {

  if (!IsProcessAlive()) return;
  
  HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (proc == NULL) {
    printf("[x] Could not open general handle to process\n");
    exit(1);
  
  } else proc_handle_ = proc;

  ProgramResult pr = ObtainSeDebug();
  // std::cout << " [i] " << pr.GetResultInformation() << std::endl;
  if (pr.IsOk()) printf(" [i] Running privileged (SE_DEBUG token)\n");
  else printf(" [i] Running without privileges (could not obtain SE_DEBUG token)\n");

  // DYNAMIC FUNCTIONS
  HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
  if (!hNtDll) {
    printf("[x] NTDLL could not be initialized\n");
    fnNtQueryInformationProcess_ = NULL;
  
  } else {
    fnNtQueryInformationProcess_ = (pNtQueryInformationProcess) GetProcAddress(hNtDll, "NtQueryInformationProcess");
    fnNtQueryVirtualMemory_ = (pNtQueryVirtualMemory) GetProcAddress(hNtDll, "NtQueryVirtualMemory");
    if (fnNtQueryInformationProcess_ == NULL || fnNtQueryVirtualMemory_ == NULL) printf("[x] Some functions could not be dynamically initalized\n");
  }
}

ProcessCapturer::~ProcessCapturer() {
  if (proc_handle_ != NULL) CloseHandle(proc_handle_);
  cout << "[cleanup] " << StopControllerServerOnProcess().GetResultInformation() << endl;
  cout << "[cleanup] " << StopMailSlotExporterOnServer().GetResultInformation() << endl;
  injection_client_.Close();
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
  if (proc_handle_ == NULL) return ErrorResult("The handle to the process was not open");
  if (fNtPauseProcess == nullptr) {
    ProgramResult exports_result = InitializeExports();
    if (exports_result.IsErr()) {
      return exports_result;
    }
  }

  ProgramResult func_result = OkResult("Successfully paused the process");
  NTSTATUS pause_result = fNtPauseProcess(proc_handle_);
  if (pause_result < 0) {
    printf("ERROR: %u", pause_result);
    func_result = ErrorResult("Could not pause process using NT");
  }

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
    if (proc_handle_ == NULL) {
      func_result = ErrorResult(PROC_OPEN_ERR_MSG);

    } else {
      bool success = TerminateProcess(proc_handle_, exit_code);
      if (!success) {
        func_result = ErrorResult("Could not terminate the process");
      }
    }

    suspended_ = false;
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
  bool is_alive = false;

  HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION , FALSE, pid_);
  if (process_handle != NULL) {
    DWORD exit_code;
    bool result = GetExitCodeProcess(process_handle, &exit_code);
    if (result != 0 && exit_code == STILL_ACTIVE) {
      is_alive = true;
    }
  }

  CloseHandle(process_handle);
  return is_alive;
}

ProgramResult ProcessCapturer::GetMemoryChunk(LPCVOID start, SIZE_T size, BYTE* buffer, SIZE_T* bytes_read) {
  if (proc_handle_ == NULL) {
    return ErrorResult(PROC_OPEN_ERR_MSG);
  }

  if (size == 0) return ErrorResult("Empty copy requested");

  ProgramResult func_result = OkResult("Data copied");

  *bytes_read = !NULL; // don't init at zero (NULL), otherwise the call won't (over)write this variable with the number of bytes read
  BOOL result = ReadProcessMemory(proc_handle_, start, reinterpret_cast<LPVOID>(buffer), size, bytes_read);
  if (result == 0) {
    func_result = ErrorResult( "Could not read process' memory. Windows error: " + error_handling::GetLastErrorAsString() );

  } else {
    if (*bytes_read > size) {
      printf("[x] Data written was bigger than buffer\n");
      exit(ERROR_BUFFER_OVERFLOW);
    }
  }

  // printf("  > COPY: [0x%p-0x%08X]\n", start, (ULONG_PTR) start + size - 1);
  return func_result;
}


void ProcessCapturer::InspectMemoryRegions() {
  MEMORY_BASIC_INFORMATION mbi;
  LPVOID address = 0;
  if (proc_handle_ == NULL) {
    printf(" [x] Could not open a HANDLE to the process.\n");
    return;
  }

  while (VirtualQueryEx(proc_handle_, address, &mbi, sizeof(mbi))) {
    printf("Base Address: 0x%p | Size: 0x%lx | State: 0x%x | Protect: 0x%x\n",
            mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect);

    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
      printf(" --> This region is readable.\n");
    }

    address = (LPBYTE) mbi.BaseAddress + mbi.RegionSize;
  }
}

ProgramResult ProcessCapturer::StartControllerServerOnProcess() {
  if (is_controller_server_running_) return OkResult("Server already running");
  
  // Performs the injection if necessary
  auto res = InjectControllerOnProcess();
  if (res.IsErr()) return res;

  res = injection::StartControllerServer(pid_, &controller_server_handle_);
  if (res.IsOk()) is_controller_server_running_ = true;
  return res;
}

ProgramResult ProcessCapturer::StopControllerServerOnProcess(bool terminate) {
  if (!is_controller_server_running_) {
    return ErrorResult("Controller server is not running");
  }

  if (terminate) {
    if (controller_server_handle_ == NULL) 
      return ErrorResult("The handle to the server thread is not valid");
    
    BOOL result = TerminateThread(controller_server_handle_, 0);
    if (result == 0) return ErrorResult("Could not terminate remote thread");
  
  } else { // Not terminate, but send a stop signal
    auto res = injection_client_.SendRequest({
      custom_ipc::command::kEndServer, // command
      vector<BYTE>() // data (empty)
    });

    if (res.IsErr()) return res;
  }

  is_controller_server_running_ = false;
  controller_server_handle_ = NULL;
  return OkResult("Stopped controller server");
}

ProgramResult ProcessCapturer::CopyPEB(void* peb) {
  if (proc_handle_ == NULL) return ErrorResult("The handle to the process is not available");
  
  void* peb_address = GetPEBLocation();
  if (peb != NULL) {
    SIZE_T bytes_read = 0;
    auto buffer = vector<BYTE>(sizeof(PEB));
    ZeroMemory(buffer.data(), sizeof(PEB));

    BOOL result = ReadProcessMemory(proc_handle_, peb_address, buffer.data(), sizeof(PEB), &bytes_read);
    if (result) {
      if (bytes_read != buffer.size()) buffer.resize(bytes_read);
      memcpy_s(peb, sizeof(PEB), buffer.data(), buffer.size());
      return OkResult("PEB successfully copied");

    } else return ErrorResult("Could not read remote process memory");
  } else return ErrorResult("Could get PEB location");
}

void* ProcessCapturer::GetPEBLocation() {
  if (proc_handle_ == NULL) return nullptr;
  if (fnNtQueryInformationProcess_ == NULL) return nullptr;

  PROCESS_BASIC_INFORMATION pbi;
  NTSTATUS status = fnNtQueryInformationProcess_(proc_handle_, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

  if (status == 0) return pbi.PebBaseAddress;
  else return nullptr;
}

ProgramResult ProcessCapturer::InjectDLLOnProcess(wstring dll_full_path) {
  // TODO: check if file exists or DLL name is valid
  return injection::InjectDLLOnProcess(pid_, dll_full_path);
}

ProgramResult ProcessCapturer::InjectControllerOnProcess() {
  if (is_controller_dll_injected_)
    return OkResult("Server was already injected");

  auto res = injection::InjectDLLOnProcess(pid_, Config::Instance().GetKeyExtractorDLLPath());
  if (res.IsOk()) is_controller_dll_injected_ = true;
  return res;
}

ProgramResult ProcessCapturer::StartMailSlotExporterOnServer() {
  auto result = injection::StartMailSlotExporter(pid_, &mailslot_thread_handle_);
  if (result.IsOk()) is_mailslot_server_started_ = true;
  return result;
}

ProgramResult ProcessCapturer::StopMailSlotExporterOnServer() {
  if (!is_mailslot_server_started_) {
    return ErrorResult("Mailslot server is not running");
  }

  if (mailslot_thread_handle_ == NULL) {
    return ErrorResult("The handle to the server thread is not valid");
  }

  BOOL result = TerminateThread(mailslot_thread_handle_, 0);
  if (result == 0) return ErrorResult("Could not terminate remote thread");
  
  is_mailslot_server_started_ = false;
  mailslot_thread_handle_ = NULL;
  return OkResult("Stopped Mailslot server");
}

ProgramResult ProcessCapturer::GetKeyBlobFromRemote(HCRYPTKEY key_handle, DWORD blob_type, vector<BYTE>& key_blob) {
  auto res = InjectControllerOnProcess(); // OK if it's already injected
  if (res.IsErr()) return res;

  res = StartControllerServerOnProcess(); // OK if it's already running
  if (res.IsErr()) return res;

  res = injection_client_.StartClient(); // OK if it's already initialized
  if (res.IsErr()) return res;

  custom_ipc::KeyDataMessage key_data = { key_handle, blob_type };
  res = injection_client_.SendRequest({
    custom_ipc::command::kExportKey, // command
    key_data.serialize() // data
  });
  if (res.IsErr()) return res;

  custom_ipc::Response response;
  res = injection_client_.GetResponse(response);
  if (res.IsErr()) return res;
  
  if (response.code) key_blob = response.data;
  else return ErrorResult("Could not export key blob");

  return OkResult("Key blob received");
}

void ProcessCapturer::WriteBufferToFile(unsigned char* buffer, SIZE_T size, string file_name) {
  ofstream file(file_name, ios::binary);
  if (file) {
    file.write(reinterpret_cast<const char*>(buffer), size);
  } else printf("Could not open file\n");
  // ProcessCapturer::PrintMemory(buffer, size);
}

ProgramResult ProcessCapturer::ExtendedHeapSearch(vector<HeapSegment> &heaps) {
  PEB peb; 
  ZeroMemory(&peb, sizeof(peb));
  auto res = CopyPEB(&peb);
  if (res.IsErr()) return res;
  
  // Get the base addresses of the heaps
  SIZE_T bytes_read;
  auto heaps_base_addresses = vector<void*>(peb.NumberOfHeaps);
  res = GetMemoryChunk(peb.ProcessHeaps, peb.NumberOfHeaps * sizeof(void*), (BYTE*) heaps_base_addresses.data(), &bytes_read);
  if (res.IsErr()) return res;
  sort(heaps_base_addresses.begin(), heaps_base_addresses.end()); // to ensure that we start looking from the lowest

  LPVOID address = heaps_base_addresses[0]; // start the search at the lowest heap
  auto buffer = vector<BYTE>(sizeof(nt_heap::HEAP_SEGMENT)); // allocate space for copying the heap segment
  while (true) {
    MEMORY_BASIC_INFORMATION mbi;
    if (fnNtQueryVirtualMemory_(proc_handle_, address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL) != 0) {
      break;
    } // Stop if querying fails (end of memory space)

    /*
    if (mbi.Type != MEM_PRIVATE) { // IMAGE (DLL) OR MAPPED
      printf("[%p] Skipping image or mapped file\n", mbi.BaseAddress); 
    
    } else if (mbi.State != MEM_COMMIT) { // RESERVED OR FREE
      printf("[%p] Skipping over not commited section\n", mbi.BaseAddress); 

    } else if (mbi.Protect & PAGE_GUARD) { // STACK
      printf("[%p] Skipping page with guard\n", mbi.BaseAddress);
    */
    
    if (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)) {
      ZeroMemory(buffer.data(), sizeof(nt_heap::HEAP_SEGMENT)); // clear previous buffer contents
      SIZE_T bytes_read;
      auto result = GetMemoryChunk(mbi.BaseAddress, sizeof(nt_heap::HEAP_SEGMENT), buffer.data(), &bytes_read);

      if (result.IsOk() && bytes_read == sizeof(nt_heap::HEAP_SEGMENT)) {
        nt_heap::PHEAP_SEGMENT heap_segment = (nt_heap::PHEAP_SEGMENT) buffer.data();
        if ((void*) heap_segment->BaseAddress == mbi.BaseAddress) {
          heaps.push_back(
            HeapSegment((ULONG_PTR) address, GetRegionSize(proc_handle_, (ULONG_PTR) address))
          );
        }
      } else printf("[x] Error copying the remote heap segment\n");
    }

    // next region
    address = (PVOID)((SIZE_T) mbi.BaseAddress + mbi.RegionSize);
  }
  return OkResult("Heaps enumerated successfully");
}

ProgramResult ProcessCapturer::SimpleHeapSearch(vector<HeapSegment>& heaps) {
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
        SIZE_T original_block_amount = 0;
        auto base = GetRegionStart(proc_handle_, he.dwAddress);
        auto size = GetRegionSize(proc_handle_, he.dwAddress);

        if (size != 0 && base != 0) {
          heaps.push_back(
            HeapSegment(base, size)
          );
        } else printf(" [x] Failed to acquire heap region size or base address\n");
      } else printf(" [x] Failed to query one of the heaps");

      hl.dwSize = sizeof(HEAPLIST32);
    } while ( Heap32ListNext(hHeapSnap, &hl) );
  
  } else { 
    printf ("Cannot list first heap (%d)\n", GetLastError());
    func_result = ErrorResult("Cannot list first heap");
  }
   
  CloseHandle(hHeapSnap);
  return func_result;
}

ProgramResult ProcessCapturer::EnumerateHeaps(vector<HeapSegment>& heaps, bool extended_search) {
  printf("Getting heaps\n");

  if (extended_search) return ExtendedHeapSearch(heaps); // v2  ==  Reads the memory regions and searches for heap structures
  else return SimpleHeapSearch(heaps); // v1  ==  Enumerates the heaps with a HEAP snapshot (CreateToolhelp32Snapshot)
}

ProgramResult ProcessCapturer::CopyHeapData(HeapSegment heap_to_copy, vector<BYTE>* buffer) { 
  if (!proc_handle_) return ErrorResult("Failed to open process handle");

  buffer->resize(heap_to_copy.GetSize());
  MemReadDumb(proc_handle_, heap_to_copy.GetBaseAddress(), buffer->data(), buffer->size());

  return OkResult("Heap copied succcessfully");
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