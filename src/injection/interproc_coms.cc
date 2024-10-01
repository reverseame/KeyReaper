#include "interproc_coms.h"

#include <iostream>

using namespace std;
using namespace error_handling;
using CommandMessage = process_injection::command_messages::CommandMessage;

namespace process_injection {

void ShowGUIMessage(std::string message) {
  MessageBoxA(NULL, message.c_str(), "Injected process", MB_OK);
}

const char* kPipeName = R"(\\.\pipe\YourPipeName)";

ProgramResult NamedPipeCommunicator::ReadMessage(char* buffer, size_t buffer_size) {
  
  // Check buffer validity
  if (buffer == nullptr || buffer_size == 0) {
    return ErrorResult("Not valid buffer or buffer size");
  }

  // Prepare for async communication (timeout)
  DWORD bytes_read = 0;
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  
  if (!overlapped.hEvent) {
    return ErrorResult("Could not create synchronization event");
  }

  // Clear the memory region
  ZeroMemory(buffer, buffer_size);
  ProgramResult func_result = OkResult("Data successfully read");

  // Read the data
  BOOL success = ReadFile(
    pipe_handle_, 
    buffer, 
    buffer_size, 
    &bytes_read, 
    &overlapped
  );

  // If the operation did not complete inmediately (was not ready)
  if (!success && GetLastError() == ERROR_IO_PENDING) {
    // Wait for the I/O operation to complete
    DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeout_millis_);

    // If successfully ended (object 0)
    if (waitResult == WAIT_OBJECT_0) {
      if (!GetOverlappedResult(pipe_handle_, &overlapped, &bytes_read, FALSE)) {
        // Failed to get the result of the overlapped operation
        func_result = ErrorResult("Failed to receive object");
      
        // Received but size mismatch
      } else if (bytes_read != buffer_size) {
        func_result = ErrorResult("Copied data does not match in size" + bytes_read);
      }

    // If got a timeout while waiting for an answer
    } else if (waitResult == WAIT_TIMEOUT) {
      printf("Timeout\n");
      CancelIo(pipe_handle_);
      func_result = ErrorResult("Timeout while waiting for object");
    
    } else {
      func_result = ErrorResult("Error while waiting for message");
    }

  // If simply failed
  } else if (!success) {
    func_result = ErrorResult("Error reading channel: " + GetLastErrorAsString());
  }

  CloseHandle(overlapped.hEvent);
  return func_result;
}

ProgramResult NamedPipeCommunicator::WriteMessage(char* buffer, size_t buffer_size) {

  // Check buffer validity
  if (buffer == nullptr || buffer_size == 0) {
    return ErrorResult("Not valid buffer or buffer size");
  }

  // Prepare for async communication (timeout)
  DWORD bytes_written = 0;
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  
  if (!overlapped.hEvent) {
    return ErrorResult("Could not create synchronization event");
  }

  ProgramResult func_result = OkResult("Data successfully written");

  // Write the data
  BOOL success = WriteFile(
    pipe_handle_, 
    buffer, 
    buffer_size, 
    &bytes_written, 
    &overlapped
  );

  // If the operation did not complete inmediately (was not ready)
  if (!success && GetLastError() == ERROR_IO_PENDING) {
    // Wait for the I/O operation to complete
    DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeout_millis_);

    // If successfully ended
    if (waitResult == WAIT_OBJECT_0) {
      if (!GetOverlappedResult(pipe_handle_, &overlapped, &bytes_written, FALSE)) {
        // Failed to get the result of the overlapped operation
        func_result = ErrorResult("Failed to write object");
      
        // Received but size mismatch
      } else if (bytes_written != buffer_size) {
        func_result = ErrorResult("Copied data does not match in size" + bytes_written);
      }

    // If got a timeout while waiting for an answer
    } else if (waitResult == WAIT_TIMEOUT) {
      printf("Timeout\n");
      CancelIo(pipe_handle_);
      func_result = ErrorResult("Timeout while waiting for object");
    
    } else {
      func_result = ErrorResult("Error while waiting for message");
    }

  // If simply failed
  } else if (!success) {
    func_result = ErrorResult("Error reading channel: " + GetLastErrorAsString());
  }

  CloseHandle(overlapped.hEvent);
  return func_result;
}

// SERVER
ProgramResult NamedPipeServer::CreateServer() {

  ProgramResult func_result = OkResult("Connection successfully established");
  
  pipe_handle_ = CreateNamedPipeA(
    pipe_name_.c_str(),
    PIPE_ACCESS_DUPLEX, // Bidirectional & asynchronous (allow timeout with overlapped)
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

ProgramResult NamedPipeServer::WaitForConnection() {
  if (pipe_handle_ == NULL) return ErrorResult("Named pipe was not properly initialized");

  ProgramResult func_result = OkResult("Connection stablished");

  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  if (overlapped.hEvent) {
    BOOL connected = ConnectNamedPipe(pipe_handle_, &overlapped);
    
    if (!connected) {
      DWORD last_error = GetLastError();
      if (last_error == ERROR_IO_PENDING) {
        DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeout_millis_);

        if (waitResult != WAIT_OBJECT_0) {
          printf("Timeout");
          // std::cerr << "Timed out waiting for client to connect." << std::endl;
          CloseHandle(overlapped.hEvent);
          return ErrorResult("Timed out while waiting for connection");
        }

      } else if (last_error != ERROR_PIPE_CONNECTED) {
        printf("Error A");
        func_result = ErrorResult("Error while waiting for connection: " + GetLastErrorAsString());
      } // else success ERROR_PIPE_CONNECTED
    } // else successfully connected
    CloseHandle(overlapped.hEvent);

  } else {
    func_result = ErrorResult("Failed to create synchronization event");
  }

  return func_result;
}

ProgramResult NamedPipeServer::ServerLoop() {
  CommandMessage cmd;

  while(true) {
    printf("Listening for commands\n");
    ProgramResult pr = ReadCommand(&cmd);
    if (pr.IsErr()) {
      printf("Command error: %s\n", pr.GetResultInformation().c_str());
      string err_msg = "Error while reading command: " + pr.GetResultInformation();
      // MessageBoxA(NULL, err_msg.c_str(), "Yes, injected!", MB_OK);
      return ErrorResult(err_msg);
    } else printf("Command successfully read\n");

    switch(cmd.command) {
      case SEND_KEY_CMD:
        printf("Received key command\n");
        // MessageBoxA(NULL, "Received key command", "Yes, injected!", MB_OK);
        // SendKeyBlob(reinterpret_cast<ULONG_PTR>(cmd.first_arg));
        break;
      case END_SERVER_CMD:
        // MessageBoxA(NULL, "Received end command", "Yes, injected!", MB_OK);
        printf("Exiting via command\n");
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

ProgramResult NamedPipeServer::ReadCommand(CommandMessage* cmd) {

  ProgramResult func_result = OkResult("Key handle successfully read");
  ProgramResult pr = ReadMessage(reinterpret_cast<char*>(cmd), sizeof(CommandMessage));

  if (pr.IsErr()) func_result = pr;
  return func_result;
}

// CLIENT
ProgramResult NamedPipeClient::ConnectToPipe() {

  DWORD start_time = GetTickCount();
  ProgramResult func_result = OkResult("Successfully connected to server");

  cout << " Entering client connection timeout loop" << endl;
  while (timeout_millis_ > 0) {
    pipe_handle_ = CreateFileA(
      pipe_name_.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      0,                         // No sharing
      NULL,                      // Default security attributes
      OPEN_EXISTING,             // Existing pipe only
      0,                         // Default attributes
      NULL                       // No template file
    );

    // Successfully connected
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
      printf("Successfully connected\n");
      break;
    }

    DWORD last_error = GetLastError();
    if (last_error == ERROR_PIPE_BUSY || last_error == ERROR_FILE_NOT_FOUND) {
      if (!WaitNamedPipeA(pipe_name_.c_str(), 1000)) {
        DWORD current_time = GetTickCount();
        timeout_millis_ -= (current_time - start_time);
        start_time = current_time;
        printf(" Time left: %u ms\t\t\t\t\r", timeout_millis_);

        if (timeout_millis_ <= 0) {
          printf(" Timeout limit reached\n");
          func_result = ErrorResult("Pipe connection timeout");
          break;
        }
      }
    } else {
      func_result = ErrorResult("Failed to connect to pipe" + GetLastErrorAsString());
      break;
    }
  }

  return func_result;
}

ProgramResult NamedPipeClient::SendKeyHandle(ULONG_PTR key_handle) {

  ProgramResult func_result = OkResult("Key handle successfully sent");

  CommandMessage cmd;
  cmd.command = SEND_KEY_CMD;
  cmd.first_arg = (WPARAM) key_handle;

  ProgramResult pr = WriteMessage(reinterpret_cast<char*>(&cmd), sizeof(CommandMessage));
  if (pr.IsErr()) func_result = pr;
  return func_result;
}

ProgramResult NamedPipeClient::SendStopSignal() {
  ProgramResult func_result = OkResult("Stop signal successfully sent");

  CommandMessage cmd;
  cmd.command = END_SERVER_CMD;
  cmd.first_arg = 0;

  ProgramResult pr = WriteMessage(reinterpret_cast<char*>(&cmd), sizeof(CommandMessage));
  if (pr.IsErr()) func_result = pr;
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