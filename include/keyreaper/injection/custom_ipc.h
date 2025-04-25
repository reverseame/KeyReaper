#ifndef CUSTOM_IPC_H
#define CUSTOM_IPC_H

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>

#include <nng/nng.h>

#include "program_result.h"

namespace custom_ipc {

enum Command {
  kEndServer,
  kExportKey
};

enum Result {
  kError,
  kOk
};

const std::string kGenericSocketName = "ipc:///KeyReaper/";

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
  explicit CustomEndpoint(std::string name);
  
  error_handling::ProgramResult SendMessage(const std::vector<BYTE>& buffer);
  error_handling::ProgramResult ReceiveMessage(std::vector<BYTE>& out_buffer);
  virtual int OpenSocket() = 0;  // Must be implemented by derived classes

  nng_socket socket_;
  std::string socket_name_;
  bool is_initialized_;
};

class CustomClient : public CustomEndpoint {
 public:
  /**
   * @param pid The PID of the process is used to set a unique channel
   * name between the server and the client, and to avoid duplicates.
   * Should be initialized with the PID of the target process
   * @param timeout_millis The timeout in milliseconds to consider that 
   * the server not running. It defaults to 20 seconds.
   */
  explicit CustomClient(DWORD pid, unsigned int timeout_millis = 20000);
  error_handling::ProgramResult StartClient();
  error_handling::ProgramResult SendRequest(Request req);
  error_handling::ProgramResult GetResponse(Response& res);

 private:
  int OpenSocket() override;
  nng_dialer dialer_;
  unsigned int timeout_millis_;
};

class CustomServer : public CustomEndpoint {
 public:
  /**
   * @param pid The PID of the process is used to set a unique channel
   * name between the server and the client, and to avoid duplicates.
   * Should be initialized with GetCurrentProcessId()
   */
  explicit CustomServer(DWORD pid);
  error_handling::ProgramResult StartServer();
  error_handling::ProgramResult GetRequest(Request& req);
  error_handling::ProgramResult SendResponse(Response res);

 private:
  int OpenSocket() override;
};

} // namespace custom_ipc

#endif