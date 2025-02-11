#ifndef INJECTOR_H
#define INJECTOR_H

#include <string>
#include <windows.h>
#include "program_result.h"

/**
 * Stateless injection functions. The state is handled by the ProcessCapturer.
 */
namespace injection {

void ShowGUIMessage(std::string message);
bool IsDLLLoadedOnProcess(DWORD pid, std::wstring dll_path, HANDLE process_handle);
error_handling::ProgramResult InjectDLLOnProcess(DWORD pid, std::wstring dll_path);
error_handling::ProgramResult StartServer(DWORD pid, HANDLE* thread_handle);
error_handling::ProgramResult StartMailSlotExporter(DWORD pid, HANDLE* thread_handle);

} // namespace injection

#endif // INJECTOR_H