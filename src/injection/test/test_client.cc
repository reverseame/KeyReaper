#include "../interproc_coms.h"
#include "../../program_result.h"
#include <stdio.h>

using namespace error_handling;
using namespace process_injection;

int main() {
  DWORD timeout = 3000;

  NamedPipeClient client = NamedPipeClient(kPipeName, timeout);
  printf("Connecting to pipe [timeout %u ms]\n", timeout);
  ProgramResult pr = client.ConnectToPipe();
  if (pr.IsOk()) {
    printf("Successfully connected to the pipe\n");

    printf("Press any key to send messsage to server...");
    getchar();
    printf("Sending key handle\n");
    ProgramResult pr2 = client.SendKeyHandle(0x000000);

    if (pr2.IsOk()) printf("%s\n", pr2.GetResultInformation().c_str());
    else printf("Could not send key handle: %s\n", pr2.GetResultInformation().c_str());
    
  } else {
    printf("%s\n", pr.GetResultInformation().c_str());
  }

  printf("Press any key to continue...");
  getchar();

  pr = client.SendStopSignal();
  printf("%s\n", pr.GetResultInformation().c_str());
  printf("Closing connection\n");
  pr = client.CloseConnection();
  printf(pr.GetResultInformation().c_str());

  return 0;
}