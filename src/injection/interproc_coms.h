#ifndef INTERPROCCOMS_H
#define INTERPROCCOMS_H

#include <windows.h>
#include <string>

#include "../program_result.h"

namespace process_injection {

namespace command_messages {

#define SEND_KEY_CMD 1
#define END_SERVER_CMD 99

struct CommandMessage {
  unsigned int command;
  LPARAM first_arg; // architecture dependant
};

} // namespace messages

extern const char* kPipeName;

class NamedPipeServer {
 public:
  NamedPipeServer(const char* pipe_name) :
      pipe_handle_ (INVALID_HANDLE_VALUE), pipe_name_(pipe_name) {};
  ~NamedPipeServer() { CloseServer(); };

  // Server operations
  error_handling::ProgramResult CreateServer();
  error_handling::ProgramResult WaitForConnection(DWORD timeout_millis);
  error_handling::ProgramResult ServerLoop();
  error_handling::ProgramResult CloseServer();

  // Communication operations
  error_handling::ProgramResult ReadCommand(command_messages::CommandMessage* command, DWORD timeout_millis);
  error_handling::ProgramResult SendKeyBlob(ULONG_PTR key_handle);

  // Process operations
  error_handling::ProgramResult GetKeyBlob(ULONG_PTR key_handle);

 private:
  HANDLE pipe_handle_;
  std::string pipe_name_;

};

class NamedPipeClient {
 public:
  NamedPipeClient(const char* pipe_name) :
      pipe_name_(pipe_name), pipe_handle_(INVALID_HANDLE_VALUE) {};
  ~NamedPipeClient() { CloseConnection(); };

  error_handling::ProgramResult ConnectToPipe(DWORD timeout_millis);
  error_handling::ProgramResult CloseConnection();
  error_handling::ProgramResult SendKeyHandle(ULONG_PTR key_handle);
  error_handling::ProgramResult ReadKeyBlob(char* buffer, size_t bufferSize, DWORD timeout_millis);

 private:
  HANDLE pipe_handle_;
  std::string pipe_name_;
};

} // namespace process_injection

#endif