#include "interproc_coms.h"

#include <iostream>

using namespace std;
using namespace error_handling;
using CommandMessage = process_injection::command_messages::CommandMessage;

namespace process_injection {

const char* kPipeName = R"(\\.\pipe\YourPipeName)";

// SERVER
ProgramResult NamedPipeServer::CreateServer() {

  ProgramResult func_result = OkResult("Connection successfully established");
  
  pipe_handle_ = CreateNamedPipeA(
    pipe_name_.c_str(),
    PIPE_ACCESS_DUPLEX, // Bidirectional
    PIPE_TYPE_BYTE | PIPE_WAIT,
    1,
    1024,
    1024,
    0,
    NULL
  );

  if (pipe_handle_ == INVALID_HANDLE_VALUE) {
    func_result = ErrorResult("Failed to create named pipe: " + GetLastErrorAsString());
  }

  return func_result;
}

ProgramResult NamedPipeServer::WaitForConnection(DWORD timeout_millis) {
  if (pipe_handle_ == NULL) return ErrorResult("Named pipe was not properly initialized");

  ProgramResult func_result = OkResult("Connection stablished");

  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (overlapped.hEvent) {

    BOOL connected = ConnectNamedPipe(pipe_handle_, &overlapped);
    if (!connected && GetLastError() == ERROR_IO_PENDING) {
      DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeout_millis);
      if (waitResult != WAIT_OBJECT_0) {
        // std::cerr << "Timed out waiting for client to connect." << std::endl;
        func_result = ErrorResult("Timed out while waiting for connection");
      }
    }
    CloseHandle(overlapped.hEvent);
  } else {
    func_result = ErrorResult("Failed to create synchronization event");
  }

  return func_result;
}

ProgramResult NamedPipeServer::ServerLoop() {
  CommandMessage cmd;
  DWORD timeout_millis = 20000; // 20 secs

  while(true) {
    ProgramResult pr = ReadCommand(&cmd, timeout_millis);
    if (pr.IsErr()) {
      string err_msg = "Error while reading command: " + pr.GetResultInformation();
      MessageBoxA(NULL, err_msg.c_str(), "Yes, injected!", MB_OK);
      return ErrorResult(err_msg);
    }

    switch(cmd.command) {
      case SEND_KEY_CMD:
        MessageBoxA(NULL, "Received key command", "Yes, injected!", MB_OK);
        // SendKeyBlob(reinterpret_cast<ULONG_PTR>(cmd.first_arg));
        break;
      case END_SERVER_CMD:
        MessageBoxA(NULL, "Received end command", "Yes, injected!", MB_OK);
        return OkResult("Exited via command");
      default:
        MessageBoxA(NULL, "Unrecognized command", "Yes, injected!", MB_OK);
    }
  }
}

ProgramResult NamedPipeServer::CloseServer() {
  ProgramResult func_result = OkResult("Connection successfully closed");
  if (pipe_handle_ !=  INVALID_HANDLE_VALUE) {
    CloseHandle(pipe_handle_);
  } else {
    func_result = ErrorResult("Error closing connection: server never created or alraedy closed");
  }

  return func_result;
}

ProgramResult NamedPipeServer::ReadCommand(CommandMessage* cmd, DWORD timeout_millis) {

  DWORD bytesRead = 0;
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  
  if (!overlapped.hEvent) {
    return ErrorResult("Could not create synchronization event");
  }

  ProgramResult func_result = OkResult("Key handle successfully read");

  BOOL success = ReadFile(pipe_handle_, cmd, sizeof(CommandMessage), &bytesRead, &overlapped);
  if (!success && GetLastError() == ERROR_IO_PENDING) {
    DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeout_millis);
    if (waitResult != WAIT_OBJECT_0) {
      CloseHandle(overlapped.hEvent);
      return ErrorResult("Failed to receive object");
    }
  }

  if (bytesRead != sizeof(CommandMessage)) {
    func_result = ErrorResult("Copied data does not match in size");
  }

  CloseHandle(overlapped.hEvent);
  return func_result;
}

// CLIENT
ProgramResult NamedPipeClient::ConnectToPipe(DWORD timeout_milliseconds) {

  ProgramResult func_result = OkResult("Successfully connected to server");
  while (timeout_milliseconds > 0) {
    pipe_handle_ = CreateFileA(
      pipe_name_.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      0,                         // No sharing
      NULL,                      // Default security attributes
      OPEN_EXISTING,             // Existing pipe only
      0,                         // Default attributes
      NULL                       // No template file
    );

    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
      if (GetLastError() == ERROR_PIPE_BUSY) {
        // Wait and retry if the pipe is busy
        if (!WaitNamedPipeA(pipe_name_.c_str(), 1000)) {
          timeout_milliseconds -= 1000;
        }
      } else {
        func_result = ErrorResult("Failed to connect to pipe" + GetLastErrorAsString());
        break;
      }
    } else {
      func_result = ErrorResult("Failed to connect to pipe");
    }
  }

  return func_result;
}

ProgramResult NamedPipeClient::SendKeyHandle(ULONG_PTR key_handle) {

  ProgramResult func_result = OkResult("Key handle successfully sent");

  DWORD bytesWritten = 0;
  CommandMessage cmd;
  cmd.command = SEND_KEY_CMD;
  cmd.first_arg = (WPARAM) key_handle;

  BOOL result = WriteFile(
    pipe_handle_, &cmd, 
    sizeof(CommandMessage), &bytesWritten, 
    NULL
  );

  if (bytesWritten != sizeof(CommandMessage)) {
    func_result = ErrorResult("Key handle was not correctly copied");
  }

  return func_result;
}

ProgramResult NamedPipeClient::CloseConnection() {
  ProgramResult func_result = OkResult("Connection successfully closed");
  if (pipe_handle_ !=  INVALID_HANDLE_VALUE) {
    CloseHandle(pipe_handle_);
  } else {
    func_result = ErrorResult("Error closing connection: server never created or alraedy closed");
  }

  return func_result;
}

} // namespace process_injection