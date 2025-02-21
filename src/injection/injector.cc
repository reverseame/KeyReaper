#include <windows.h>
#include <string>
#include <psapi.h>

#include <iostream>
#include <thread>
#include "program_result.h"
#include "injection/interproc_coms.h"
#include "injection/injector.h"
#include "config.h"

using namespace std;
using namespace error_handling;

namespace injection {

bool IsDLLLoadedOnProcess(DWORD pid, wstring w_dll_path, HANDLE process_handle) {
  if (!process_handle) return false;

  HMODULE module_array[1024];
  DWORD bytes_needed;
  if (EnumProcessModulesEx(process_handle, module_array, sizeof(module_array), &bytes_needed, LIST_MODULES_ALL)) {
    for (size_t i = 0; i < (bytes_needed / sizeof(HMODULE)); i++) {
      WCHAR module_name[MAX_PATH];
      if (GetModuleBaseNameW(process_handle, module_array[i], module_name, sizeof(module_name) / sizeof(WCHAR))) {
        if (_wcsicmp(module_name, w_dll_path.c_str()) == 0) {
          printf(" DLL found in process\n");
          return true;
        }
      }
    }
  } else cerr << " [x] Failed to enumerate modules: " << GetLastErrorAsString() << endl;

  return false;
}

ProgramResult InjectDLLOnProcess(DWORD pid, wstring w_dll_path) {
  ProgramResult result = OkResult("Process injected");

  // GET THE LOADLIBRARY OFFSET IN MEMORY
  HMODULE k32_module = GetModuleHandleA("kernel32.dll");
  if (k32_module == NULL) return ErrorResult("Could not load Kernel32 library");
  LPTHREAD_START_ROUTINE load_library_func = (LPTHREAD_START_ROUTINE) GetProcAddress(k32_module, "LoadLibraryW");
  if (load_library_func == NULL) return ErrorResult("Could not obtain LoadLibraryW offset");

  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (process == NULL) return ErrorResult("[INJ] Could not open remote process");

  if (!IsDLLLoadedOnProcess(pid, w_dll_path, process)) {
  // allocate memory buffer for remote process
    LPVOID remote_buffer;
    SIZE_T size_in_bytes = (w_dll_path.length() + 1) * sizeof(wchar_t);
    remote_buffer = VirtualAllocEx(process, NULL, size_in_bytes, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remote_buffer) {
      BOOL res = WriteProcessMemory(process, remote_buffer, w_dll_path.c_str(), size_in_bytes, NULL);
      if (res) {
        HANDLE thread_handle = CreateRemoteThread(process, NULL, 0, load_library_func, remote_buffer, 0, NULL);
        if (!thread_handle) result = ErrorResult("[INJ] Failed to start a thread on the target process");
        else {
          WaitForSingleObject(thread_handle, INFINITE);
          CloseHandle(thread_handle);
        }
      } else result = ErrorResult("[INJ] Could not write into the remote buffer");
    } else result = ErrorResult("[INJ] Failed to allocate memory in the remote process");

    if (!IsDLLLoadedOnProcess(pid, w_dll_path, process)) result = ErrorResult("The DLL was not found in the remote process after injection attempt");
  } else result = OkResult("The DLL was already loaded on the process");

  CloseHandle(process);
  return result;
}

ProgramResult StartControllerServer(DWORD pid, HANDLE* thread_handle) {
  return CallRemoteFunction(pid, Config::Instance().GetKeyExtractorDLLPath(), "StartServer", thread_handle);
}

error_handling::ProgramResult StartMailSlotExporter(DWORD pid, HANDLE* thread_handle) {
  return CallRemoteFunction(pid, Config::Instance().GetKeyExtractorDLLPath(), "StartMailSlotExporter", thread_handle);
}

error_handling::ProgramResult CallRemoteFunction(DWORD pid, std::wstring w_dll_path, string function_name, HANDLE* thread_handle) {
  HMODULE injected_dll = LoadLibraryW(w_dll_path.c_str());
  if (injected_dll == NULL) 
    return ErrorResult("Could not load the specified DLL");

  FARPROC start_server_function = GetProcAddress(injected_dll, function_name.c_str());
  FreeLibrary(injected_dll);

  if (start_server_function == NULL) 
    return ErrorResult("Failed to obtain [" + function_name + "] function");

  // Open process
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (process == NULL) 
    return ErrorResult("Could not open remote process");

  HANDLE t_handle = CreateRemoteThread(
    process, NULL, 0,
    (LPTHREAD_START_ROUTINE) start_server_function,
    NULL, 0, NULL
  );

  if (thread_handle != NULL) *thread_handle = t_handle;
  else CloseHandle(t_handle);
  
  CloseHandle(process);
  if (*thread_handle == NULL) return ErrorResult("Could not start a thread with "+ function_name + "function"); 
  else return OkResult("Successfully started " + function_name + " on remote process");
}
} // namespace injection