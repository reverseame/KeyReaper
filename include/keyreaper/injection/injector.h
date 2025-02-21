#ifndef INJECTOR_H
#define INJECTOR_H

#include <string>
#include <windows.h>
#include "program_result.h"

/**
 * Stateless injection functions. The state is handled by the ProcessCapturer.
 */
namespace injection {

/** 
 * Checks if a DLL is already loaded in memory
 * @param pid The Process ID (PID) of the target process
 * @param dll_path the path or name to the DLL to be checked
 * @param process_handle A HANDLE with the enough permissions to enumerate the loaded DLLs
 */
bool IsDLLLoadedOnProcess(DWORD pid, std::wstring dll_path, HANDLE process_handle);
error_handling::ProgramResult InjectDLLOnProcess(DWORD pid, std::wstring dll_path);

/**
 * Calls a function on the remote process. The DLL must be present on the remote process 
 * before calling this function. The function will call CreateRemoteThread, which does
 * not yield an error even if the DLL is not present in the remote process. The process
 * will be forced to run in the specified address, and if it does not exist (in case the
 * DLL is not laoded) **it will crash the whole program**.
 * 
 * @param pid The Process ID (PID) of the target process
 * @param thread_handle A pointer to store the HANDLE of the created thread. The parameter is ignored if set to NULL
 */
error_handling::ProgramResult StartControllerServer(DWORD pid, HANDLE* thread_handle);
error_handling::ProgramResult StartMailSlotExporter(DWORD pid, HANDLE* thread_handle);

/**
 * Calls a function on the remote process. The DLL must be present on the remote process 
 * before calling this function. The function will call CreateRemoteThread.
 * 
 * @param pid The Process ID (PID) of the target process
 * @param w_dll_path The name or path to the DLL that contains the function
 * @param function_name The name of the function of the referenced DLL to be started
 * @param thread_handle A pointer to store the HANDLE of the created thread. The parameter is ignored if set to NULL
 */
error_handling::ProgramResult CallRemoteFunction(DWORD pid, std::wstring w_dll_path, std::string function_name, HANDLE* thread_handle);

} // namespace injection

#endif // INJECTOR_H