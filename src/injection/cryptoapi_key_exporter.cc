/*
Template auhtor
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

#include "../program_result.h"
using ErrorResult = error_handling::ErrorResult;
using OkResult = error_handling::OkResult;

#include "interproc_coms.h"
using namespace process_injection;

DWORD timeout_millis = 20000;

extern "C" __declspec(dllexport) void StartServer(LPVOID lpParam) {
  NamedPipeServer server = NamedPipeServer(kPipeName, timeout_millis);
  // ShowGUIMessage("Creating server");
  server.CreateServer();
  // ShowGUIMessage("Waiting for connection");
  error_handling::ProgramResult pr = server.WaitForConnection();
  // ShowGUIMessage(pr.GetResultInformation());
  if (pr.IsOk()) {
    // ShowGUIMessage("Entering server loop");
    server.ServerLoop();
  } // else ShowGUIMessage("Did not enter server loop due to previous error");
  // ShowGUIMessage("Closing server");
  server.CloseServer();
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    ShowGUIMessage("Successfully injected");
    break;
  case DLL_PROCESS_DETACH:
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    break;
  }
  return TRUE;
}

