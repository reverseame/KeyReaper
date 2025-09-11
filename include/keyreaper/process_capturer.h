#ifndef PROCESSCAPTURER_H
#define PROCESSCAPTURER_H
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <tlhelp32.h>

#include "ntdll.h"
#include "winntheap.h"
#include "injection/custom_ipc.h"
#include "program_result.h"
#include "cryptoapi.h"

namespace nt_suspend {
// https://ntopcode.wordpress.com/2018/01/16/anatomy-of-the-thread-suspension-mechanism-in-windows-windows-internals/
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

typedef NTSTATUS(NTAPI *pNtSuspendProcess)(
  HANDLE ProcessHandle
);
}

typedef NTSTATUS (NTAPI* pNtQueryVirtualMemory)(
  HANDLE, PVOID, int, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS (NTAPI* pNtQueryInformationProcess)(
  HANDLE, int, PVOID, ULONG, PULONG);

namespace process_manipulation {

// from x64dbg
ULONG_PTR GetRegionStart(HANDLE process, ULONG_PTR valid_address_in_region);
SIZE_T GetRegionSize(HANDLE hProcess, ULONG_PTR heapBase);
bool MemReadDumb(HANDLE proc_handle, UINT_PTR BaseAddress, void* Buffer, SIZE_T Size);

class HeapSegment {
 public:
  HeapSegment(ULONG_PTR base_address, SIZE_T size) :
      base_address_(base_address), size_(size) {};
  /**
   * Retrieves the size of the heap region
   */
  SIZE_T GetSize() const;
  ULONG_PTR GetBaseAddress() const;
  ULONG_PTR GetLastAddress() const;

  /**
   * Checks if an address belongs to the heap
   */
  bool IsAddressInHeap(ULONG_PTR pointer) const;
  /** 
   * Given a pointer within the heap, the function updates it based on
   * the new address and the base address of the pointer.
   * Its purpose is to locate a pointer within a buffer after it has been
   * written to a buffer, where the base address of the buffer and the heap
   * do not match.
   */
  bool RebaseAddress(ULONG_PTR* pointer, ULONG_PTR new_base_address) const;

 private:
  ULONG_PTR base_address_;
  SIZE_T size_;
};

class ProcessCapturer {
 public:
  // Constructors
  ProcessCapturer(unsigned int pid);
  ~ProcessCapturer();

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
   * @param excluded_tids The Thread IDs (TID) that will be
   *        excluded from the pause.
   * @param force_pause Forces the program to pause even if 
   *        it was already suspended before, or something else
   *        resumed it. Internally, it increases the pause count 
   *        of the threads by one, so there is no drawback to
   *        this option.
   */
  error_handling::ProgramResult PauseProcess(std::vector<DWORD> excluded_tids = std::vector<DWORD>(), bool force_pause = false);

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
  void WriteBufferToFile(unsigned char* buffer, SIZE_T size, std::string file_name);

  error_handling::ProgramResult EnumerateHeaps(std::vector<HeapSegment>& heaps, bool extended_search = false);

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
   *  * @param heap_to_copy This is obtained through the EnumerateHeaps function,
   *                          and contains information about the strcuture of the heap
   *  * @param buffer This is where the function will place the allocated buffer with the heap data.
   *                  The allocation is performed by the function, therefore the user only needs to 
   *                  supply a pointer. The size of the buffer will be the same as the heap.
   * 
   */
  error_handling::ProgramResult CopyHeapData(HeapSegment heap_to_copy, std::vector<BYTE>* buffer);

  // Privileges
  error_handling::ProgramResult ObtainSeDebug();
  bool IsPrivileged() const;

  void static PrintMemory(unsigned char* buffer, SIZE_T num_of_bytes, ULONG_PTR starting_visual_address = 0x0);

  // Query
  DWORD GetPid() const;

  /** When a process is suspended by the program, an internal variable keeps track of it.
   *  PauseProcess function sets it and ResumeProcess unsets it.
   *  Pausing a specific thread does not affect it.
   * 
   * This function may be used to recover this information
   */
  bool IsSuspended() const;

  /**
   * Determines if the process ended or is alive (not killed), independently of
   * the internal status (paused or running)
  */
  bool IsProcessAlive() const;

  // INJECTION
  /**
   * Injects the specified DLL to the target process.
   * @param dll_full_path Either the name or full path of the DLL
   */
  error_handling::ProgramResult InjectDLLOnProcess(std::wstring dll_full_path);
  /**
   * Injects the custom DLL with the server for exporting keys. This can be
   * configured through the config file.
   * This funciton DOES NOT start the server
   */
  error_handling::ProgramResult InjectControllerOnProcess();
  error_handling::ProgramResult StartMailSlotExporterOnServer();
  error_handling::ProgramResult StopMailSlotExporterOnServer();

  /**
   * Retrieves the key blob of the specified key by calling `CryptExportKey` on the remote process.
   * This funciton handles the injection and server startup, so it is not necessary to perform it manually.
   * The remote process will try to force the export bit on the key, so even keys created without the
   * `CRYPT_EXPORTABLE` flag will be exported, which does NOT work with private key pairs that were not
   * flagged as exportable. Anyway, malware does activate this flag to dump the key to a file.
   * 
   * @param key_handle The `HCRYPTKEY` to be exported
   * @param blob_type The type of blob format to be exported the key in. Note that not all types of blob
   * are valid for every type of key. For example, asymmetric keys should use `PUBLICKEYBLOB` and `PRIVATEKEYBLOB`.
   * AES keys should be exported using `PLAINTEXTKEYBLOB`.
   * @param blob [out] A reference to a vector where the resulting blobs will be placed. If the export fails,
   * the function returns an `ErrorResult`, including and error because the key was not exportable.
   */
  error_handling::ProgramResult GetKeyBlobFromRemote(HCRYPTKEY key_handle, DWORD blob_type, std::vector<BYTE>& key_blob, cryptoapi::CryptoAPIProvider provider);

  /**
   * Returns a copy of the Process Environment Block of the target process
   * @param peb A pointer to a PEB structure
   */
  error_handling::ProgramResult CopyPEB(void* peb);
  void* GetPEBLocation();

 private:
  /**
   * Function for initializing dynamically imported functions, such as `NtSuspendProcess`.
   */
  error_handling::ProgramResult InitializeExports();
  void InspectMemoryRegions();

  /**
   * Starts the controller server on process, which allows to perform specific
   * operations on the remote process.
   */
  error_handling::ProgramResult StartControllerServerOnProcess();
  error_handling::ProgramResult StopControllerServerOnProcess(bool terminate = false);

    /**
   * Looks for heaps by enumerating the memory regions of the process and matching 
   * for the HEAP_ENTRY structure
   * @param heaps (OUT) vector where the heap region base and size will be placed
   */
  error_handling::ProgramResult ExtendedHeapSearch(std::vector<HeapSegment>& heaps);
  error_handling::ProgramResult SimpleHeapSearch(std::vector<HeapSegment>& heaps);

  HANDLE proc_handle_;
  pNtQueryInformationProcess fnNtQueryInformationProcess_;
  pNtQueryVirtualMemory fnNtQueryVirtualMemory_;
  static nt_suspend::pNtSuspendProcess fNtPauseProcess;
  custom_ipc::CustomClient injection_client_;
  DWORD pid_;
  int suspended_;
  bool is_privileged_;
  bool is_controller_dll_injected_; //  to keep track of the injection status (injected or not)
  bool is_controller_server_running_; // to keep track of the controller server status
  bool is_mailslot_server_started_;
  HANDLE mailslot_thread_handle_;
  HANDLE controller_server_handle_;
};

} // namespace process_manipulation

#endif
