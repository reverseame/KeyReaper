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

void ShowGUIMessage(std::string message);

extern const char* kPipeName;

class NamedPipeCommunicator {
 public:
  NamedPipeCommunicator(const char* pipe_name, DWORD operation_timeout) :
      pipe_handle_ (INVALID_HANDLE_VALUE), pipe_name_(pipe_name), timeout_millis_(operation_timeout) {};
  error_handling::ProgramResult ReadMessage(char* buffer, size_t buffer_size);
  error_handling::ProgramResult WriteMessage(char* buffer, size_t buffer_size);

 protected:
  HANDLE pipe_handle_;
  std::string pipe_name_;
  DWORD timeout_millis_;
};

class NamedPipeServer : public NamedPipeCommunicator {
 public:
  NamedPipeServer(const char* pipe_name, DWORD operation_timeout) : 
      NamedPipeCommunicator(pipe_name, operation_timeout) {};
  ~NamedPipeServer() { CloseServer(); };

  // Server operations
  error_handling::ProgramResult CreateServer();
  error_handling::ProgramResult WaitForConnection();
  error_handling::ProgramResult ServerLoop();
  error_handling::ProgramResult CloseServer();

  // Communication operations
  error_handling::ProgramResult ReadCommand(command_messages::CommandMessage* command);
  error_handling::ProgramResult SendKeyBlob(ULONG_PTR key_handle);

  // Process operations
  error_handling::ProgramResult GetKeyBlob(ULONG_PTR key_handle);
};

class NamedPipeClient : public NamedPipeCommunicator {
 public:
  NamedPipeClient(const char* pipe_name, DWORD operation_timeout) :
      NamedPipeCommunicator(pipe_name, operation_timeout) {};
  ~NamedPipeClient() { CloseConnection(); };

  error_handling::ProgramResult ConnectToPipe();
  error_handling::ProgramResult CloseConnection();
  
  error_handling::ProgramResult SendKeyHandle(ULONG_PTR key_handle);
  error_handling::ProgramResult SendStopSignal();
  error_handling::ProgramResult ReadKeyBlob(char* buffer, size_t bufferSize);
};

} // namespace process_injection

#endif