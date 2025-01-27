#ifndef INJECTOR_H
#define INJECTOR_H

#include <string>
#include <windows.h>
#include "program_result.h"

namespace injection {

error_handling::ProgramResult InjectDLLOnProcess(DWORD pid, std::string dll_path);
error_handling::ProgramResult StartServer(DWORD pid, HANDLE* thread_handle);
error_handling::ProgramResult StartMailSlotExporter(DWORD pid, HANDLE* thread_handle);
error_handling::ProgramResult StopServer(DWORD pid);

} // namespace injection

#endif // INJECTOR_H