#include "../interproc_coms.h"
#include "../../program_result.h"
#include <stdio.h>

using namespace error_handling;
using namespace process_injection;

int main() {
  DWORD timeout_millis = 5000;

  NamedPipeServer server = NamedPipeServer(kPipeName, timeout_millis);
  printf("Creating server\n");
  server.CreateServer();

  printf("Waiting for connection\n");
  ProgramResult pr = server.WaitForConnection();
  printf("%s\n", pr.GetResultInformation().c_str());
  
  if (pr.IsOk()) {
    printf("Entering server loop\n");
    ProgramResult pr = server.ServerLoop();
    printf("%s\n", pr.GetResultInformation().c_str());
  } else printf("Did not enter server loop due to previous error\n");

  printf("Closing server\n");
  pr = server.CloseServer();
  printf("%s\n", pr.GetResultInformation().c_str());

  return 0;
}