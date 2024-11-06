#include "injection/interproc_coms.h"
#include "program_result.h"
#include <stdio.h>
#include <string>
#include <iostream>

using namespace error_handling;
using namespace process_injection;
using namespace std;

int main() {
  DWORD timeout = 20000;

  NamedPipeClient client = NamedPipeClient(kPipeName, timeout);
  printf("Connecting to pipe [timeout %u ms]\n", timeout);
  ProgramResult pr = client.ConnectToPipe();
  if (pr.IsOk()) {
    printf("Successfully connected to the pipe\n");

    printf("Press any key to send messsage to server...");
    getchar();
    printf("Sending key handle\n");
    
    printf("Enter Key handle: ");
    string hex_str;
    cin >> hex_str;
    ULONG_PTR key_handle = stoul(hex_str, nullptr, 16);
    printf(" Input handle: %08X\n", key_handle);

    BYTE* key_blob;
    DWORD key_blob_size;
    ProgramResult pr2 = client.GetKey(key_handle, &key_blob, &key_blob_size);

    printf(" KEY DATA:\n");
    for (unsigned int i = 0; i < key_blob_size; i++) {
      printf("%02X ", key_blob[i]);
    } printf("\n");
    free(key_blob);

    if (pr2.IsOk()) printf("%s\n", pr2.GetResultInformation().c_str());
    else printf("Could not send key handle: %s\n", pr2.GetResultInformation().c_str());

    printf("Press any key to continue...");
    getchar();

    pr = client.SendStopSignal();
    printf("%s\n", pr.GetResultInformation().c_str());
    printf("Closing connection\n");
    pr = client.CloseConnection();
    printf(pr.GetResultInformation().c_str());
    
  } else {
    printf("%s\n", pr.GetResultInformation().c_str());
  }

  return 0;
}