#ifndef INTERPROCCOMS_H
#define INTERPROCCOMS_H

#include <windows.h>
#include <string>

#include "program_result.h"

namespace process_injection {

namespace command_messages {

#define SEND_KEY_CMD 1
#define END_SERVER_CMD 99

struct CommandMessage {
  unsigned int command;
  WPARAM first_arg; // architecture dependant
};

} // namespace messages

extern const char* kPipeName;

class NamedPipeCommunicator {
 public:
  NamedPipeCommunicator(const char* pipe_name, DWORD operation_timeout) :
      pipe_handle_ (INVALID_HANDLE_VALUE), pipe_name_(pipe_name), timeout_millis_(operation_timeout) {};
  error_handling::ProgramResult ReadMessage(BYTE* buffer, size_t buffer_size);
  error_handling::ProgramResult WriteMessage(BYTE* buffer, size_t buffer_size);
  error_handling::ProgramResult WriteError(size_t original_message_size, BYTE fill_byte);

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
  error_handling::ProgramResult SendKey(ULONG_PTR key_handle);

 private:
  error_handling::ProgramResult GetKeySize(ULONG_PTR key_handle);
  error_handling::ProgramResult SendKeyBlob(ULONG_PTR key_handle, DWORD key_size);
};

class NamedPipeClient : public NamedPipeCommunicator {
 public:
  NamedPipeClient(const char* pipe_name, DWORD operation_timeout) :
      NamedPipeCommunicator(pipe_name, operation_timeout) {};
  ~NamedPipeClient() { CloseConnection(); };

  // Communication
  error_handling::ProgramResult ConnectToPipe();
  error_handling::ProgramResult CloseConnection();

  // Operations
  error_handling::ProgramResult GetKey(ULONG_PTR key_handle, BYTE** plain_key_blob, DWORD* plain_blob_size);
  error_handling::ProgramResult SendStopSignal();

 private:
  error_handling::ProgramResult SendKeyHandle(ULONG_PTR key_handle);
  error_handling::ProgramResult ReadBlobSize(DWORD* blob_size);
  error_handling::ProgramResult ReadPlainBlob(BYTE* buffer, DWORD buffer_size);
};

} // namespace process_injection

#endif