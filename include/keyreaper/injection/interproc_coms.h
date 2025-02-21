#ifndef INTERPROCCOMS_H
#define INTERPROCCOMS_H

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>

#include <nng/nng.h>

#include "program_result.h"

namespace custom_ipc {

namespace command {
const ULONG kEndServer = 0;
const ULONG kExportKey = 1;
} // namespace command

namespace result {
const bool kError = false;
const bool kOk = true;
} // namespace result

const std::string kGenericSocketName = "ipc:///KeyReaper/";

struct CommandMessage {
  unsigned int command;
  WPARAM first_arg; // architecture dependant
};

struct KeyDataMessage {
  HCRYPTKEY key_handle;
  DWORD blob_type;

  std::vector<unsigned char> serialize() const;
  static KeyDataMessage deserialize(const std::vector<unsigned char>& buffer);
  /**
   * This function will deserialize the buffer and overwrite the
   * contents of the struct. It is suggested to use over an empty struct.
   */
  void deserialize_here(const std::vector<unsigned char>& buffer);
};

struct Request {
  unsigned int command;
  std::vector<unsigned char> data;
  
  std::vector<unsigned char> serialize() const;
  static Request deserialize(const std::vector<unsigned char>& buffer);
  void deserialize_here(const std::vector<unsigned char>& buffer);
};

struct Response {
  unsigned int code;
  std::vector<unsigned char> data;

  std::vector<unsigned char> serialize() const;
  static Response deserialize(const std::vector<unsigned char>& buffer);
  void deserialize_here(const std::vector<unsigned char>& buffer);
};

// Mailslot
HANDLE WaitForMailSlot(std::string mailslot_name, DWORD timeout);
void SendKeyHandleToMailSlot(HCRYPTKEY key);

/**
 * Calls `MessageBoxA` in the current process. Useful when injecting to a process
 * without graphical interface. The operation is non-blocking
 * @param message The message to show
 */
void ShowGUIMessage(std::string message);

// NNG CLIENT/SERVER
class CustomEndpoint {
 public:
  virtual ~CustomEndpoint() { Close(); }
  /**
   * Function that clears up the client. Automatically called on by the destructor.
   */
  void Close();
 
 protected:
  explicit CustomEndpoint();
  
  error_handling::ProgramResult SendMessage(const std::vector<BYTE>& buffer);
  error_handling::ProgramResult ReceiveMessage(std::vector<BYTE>& out_buffer);
  virtual int OpenSocket() = 0;  // Must be implemented by derived classes

  nng_socket socket_;
  std::string socket_name_;
  bool is_initialized_;
};

class CustomClientV2 : public CustomEndpoint {
 public:
  explicit CustomClientV2(unsigned int timeout_millis = 20000);
  error_handling::ProgramResult StartClient();
  error_handling::ProgramResult SendRequest(Request req);
  error_handling::ProgramResult GetResponse(Response& res);

 private:
  int OpenSocket() override;
  nng_dialer dialer_;
  unsigned int timeout_millis_;
};

class CustomServerV2 : public CustomEndpoint {
 public:
  explicit CustomServerV2();
  error_handling::ProgramResult StartServer();
  error_handling::ProgramResult GetRequest(Request& req);
  error_handling::ProgramResult SendResponse(Response res);

 private:
  int OpenSocket() override;
};

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
  error_handling::ProgramResult ReadCommand(CommandMessage* command);
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

} // namespace custom_ipc

#endif