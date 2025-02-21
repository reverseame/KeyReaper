#include <iostream>
#include <chrono>
#include <thread>
#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include "injection/interproc_coms.h"

using namespace std;
using namespace error_handling;
using CommandMessage = custom_ipc::CommandMessage;

namespace custom_ipc {

const char* kPipeName = R"(\\.\pipe\YourPipeName)";

void ShowGUIMessage(string message) {
  string window_title = "PID: " + to_string(GetCurrentProcessId());
  thread([message, window_title]() {
    MessageBoxA(NULL, message.c_str(), window_title.c_str(), MB_OK);
  }).detach();
}

HANDLE WaitForMailSlot(string mailslot_name, DWORD timeout) {
  HANDLE mailslot;
  auto startTime = chrono::steady_clock::now();

  while (true) {
    // Try to open the mailslot
    mailslot = CreateFileA(
      mailslot_name.c_str(),
      GENERIC_WRITE,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );

    if (mailslot != INVALID_HANDLE_VALUE) {
      break; // Successfully opened
    }

    // Check if timeout expired
    auto elapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - startTime).count();
    if (elapsed > timeout) {
      cerr << "Timeout: Could not open mailslot after " << timeout << " ms\n";
      break;
    }

    this_thread::sleep_for(chrono::milliseconds(100)); // Small delay before retrying
  }
  return mailslot;
}

void SendKeyHandleToMailSlot(HCRYPTKEY key) {
  printf("Sending key over the MailSlot. Data size: %u\n", sizeof(HCRYPTKEY));
  LPCSTR mailslot_name = "\\\\.\\mailslot\\KeyReaperServer";

  DWORD timeout = 10000;
  HANDLE mailslot = WaitForMailSlot(mailslot_name, timeout);

  if (mailslot == INVALID_HANDLE_VALUE) {
    cerr << "Mailslot not available within timeout: " << timeout << endl;
    return;
  }

  DWORD bytes_written;
  BYTE* buffer = (BYTE*) &key;
  // Write to the mailslot
  if (WriteFile(mailslot, buffer, sizeof(HCRYPTKEY), &bytes_written, NULL)) {
    cout << "Successfully wrote " << bytes_written << " bytes to the mailslot." << endl;
  } else {
    cerr << "Failed to write to the mailslot. Error: " << error_handling::GetLastErrorAsString() << endl;
  }

  // Close the handle
  CloseHandle(mailslot);
}

ProgramResult NamedPipeCommunicator::ReadMessage(BYTE* buffer, size_t buffer_size) {
  
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

ProgramResult NamedPipeCommunicator::WriteMessage(BYTE* buffer, size_t buffer_size) {

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

ProgramResult NamedPipeCommunicator::WriteError(size_t original_message_size, BYTE fill_byte) {
  BYTE* message = (BYTE*) malloc(original_message_size);
  if (message == NULL) {
    return ErrorResult("Could not allocate space for writing the error");
  }

  FillMemory(message, original_message_size, 0xFF);
  ProgramResult pr = WriteMessage(message, original_message_size);

  free(message);
  return pr;
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
          // cerr << "Timed out waiting for client to connect." << endl;
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
      case command::kExportKey:
        printf("Received key command %08X\n", cmd.first_arg);
        // MessageBoxA(NULL, "Received key command", "Yes, injected!", MB_OK);
        SendKey(static_cast<ULONG_PTR>(cmd.first_arg));
        break;
      case command::kEndServer:
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
  ProgramResult pr = ReadMessage(reinterpret_cast<BYTE*>(cmd), sizeof(CommandMessage));

  if (pr.IsErr()) func_result = pr;
  return func_result;
}

ProgramResult NamedPipeServer::SendKey(ULONG_PTR key_handle) {

  ProgramResult func_result = OkResult("The key was successfully sent");

  // Get the key size
  DWORD blob_size = NULL;
  BOOL success = CryptExportKey(
    key_handle, NULL,
    PLAINTEXTKEYBLOB, 0,
    NULL, &blob_size
  );

  if (success) {
    // Send key size
    ProgramResult res = WriteMessage(reinterpret_cast<BYTE*>(&blob_size), sizeof(DWORD));

    if (res.IsOk()) {
      BYTE* buffer = (BYTE*) calloc(sizeof(BYTE), blob_size);

      if (buffer != NULL) {
        DWORD bytes_written = blob_size;
        success = CryptExportKey(
          key_handle, NULL,
          PLAINTEXTKEYBLOB, 0,
          buffer, &bytes_written
        );

        if (success) {
          // send raw key blob
          res = WriteMessage(buffer, bytes_written);
          printf("\n KEY DATA:\n");
          for (unsigned int i = 0; i < bytes_written; i++) {
            printf("%02X ", buffer[i]);
          } printf("\n");

          if (res.IsErr()) {
            func_result = res; // propagate error 
          }
        } else {
          WriteError(blob_size, 0xFF);
          func_result = ErrorResult("Could not copy key data [CryptExportKey]: " + GetLastErrorAsString());
        }

        free(buffer);
      } else {
        func_result = ErrorResult("Could not allocate memory for copying the key data");
      }
    } else {
      func_result = res;
    }
  } else {
    // If operation failed, signal the error 
      // (otherwise it will ocurr a timeout in the other end)
    
    // REVIEW: something is not working
    WriteError(sizeof(DWORD), 0x0);
    func_result = ErrorResult("Error obtaining key size [CryptExportKey]: " + GetLastErrorAsString());
  }
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
  cmd.command = command::kExportKey;
  cmd.first_arg = (WPARAM) key_handle;

  ProgramResult pr = WriteMessage(reinterpret_cast<BYTE*>(&cmd), sizeof(CommandMessage));
  if (pr.IsErr()) func_result = pr;
  return func_result;
}

ProgramResult NamedPipeClient::ReadBlobSize(DWORD* blob_size) {
  
  ProgramResult func_result = OkResult("Blob size read from remote");
  DWORD size;
  ProgramResult res = ReadMessage(reinterpret_cast<BYTE*>(&size), sizeof(DWORD));

  if (res.IsErr()) {
    size = 0;
    func_result = res;
  }

  *blob_size = size;
  return func_result;
}

ProgramResult NamedPipeClient::ReadPlainBlob(BYTE* buffer, DWORD buffer_size) {

  ProgramResult func_result = OkResult("Blob read from remote");
  ProgramResult res = ReadMessage(buffer, static_cast<size_t>(buffer_size));

  if (res.IsErr()) {
    func_result = res;
  }

  return func_result;
}

/** 
 * A function to retrieve a key blob from the remote server.
 * The data in the output buffer of this function is meant to be used in CryptImportKey.
 * 
 * @param key_handle The handle to a key in the process holding the server
 * @param raw_key_blob The byte array where the data will be held. The allocation is performed by this function
 * @param raw_structure_size The size of the buffer
 */
ProgramResult NamedPipeClient::GetKey(ULONG_PTR key_handle, BYTE** raw_key_blob, DWORD* raw_structure_size) {
  *raw_key_blob = nullptr;
  *raw_structure_size = 0;

  ProgramResult func_result = OkResult("Key retrieved");

  printf("Sending key handle\n");
  ProgramResult result = SendKeyHandle(key_handle);

  if (result.IsOk()) {
    DWORD key_size;
    result = ReadBlobSize(&key_size);

    if (result.IsOk()) {
      if (key_size > 0) {
        *raw_key_blob = (BYTE*) calloc(sizeof(BYTE), static_cast<size_t>(key_size));

        if (*raw_key_blob != NULL) {
          result = ReadPlainBlob(*raw_key_blob, key_size);

          if (result.IsOk()) {
            // Write to output variables
            *raw_structure_size = key_size;

          } else {
            // free the region we allocated
            free(*raw_key_blob);
            *raw_key_blob = nullptr;
            func_result = ErrorResult("Failed to read remote key");
          }
        } else {
          printf("Failed to allocate space for the key");
          func_result = ErrorResult("Failed to allocate space for the key");
        }
      } else {
        printf("Remote error: could not copy key data");
        func_result = ErrorResult("Remote error: could not copy key data");
      }
    } else {
      printf("Failed to read remote key size\n");
      func_result = ErrorResult("Failed to read remote key size");
    }
  } else {
    printf("Failed to send key handle\n");
    func_result = ErrorResult("Failed to send key handle");
  }

  return func_result;
}

ProgramResult NamedPipeClient::SendStopSignal() {
  ProgramResult func_result = OkResult("Stop signal successfully sent");

  CommandMessage cmd;
  cmd.command = command::kEndServer;
  cmd.first_arg = 0;

  ProgramResult pr = WriteMessage(reinterpret_cast<BYTE*>(&cmd), sizeof(CommandMessage));
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

ProgramResult CustomEndpoint::SendMessage(const vector<BYTE> &buffer) {
  if (!is_initialized_) return ErrorResult("Socket is not initialized (server invalid or not started)");

  nng_msg* msg = nullptr;
  int nng_res = nng_msg_alloc(&msg, buffer.size());
  if (nng_res != 0) return ErrorResult("Failed to allocate message");

  memcpy(nng_msg_body(msg), buffer.data(), buffer.size());

  nng_res = nng_sendmsg(socket_, msg, 0);
  if (nng_res != 0) {
    nng_msg_free(msg);
    return ErrorResult("Failed to send message: " + string(nng_strerror(nng_res)));
  }

  return OkResult("Message sent successfully");
}

ProgramResult CustomEndpoint::ReceiveMessage(vector<BYTE>& out_buffer) {
  if (!is_initialized_) return ErrorResult("Socket is not initialized");

  nng_msg* msg = nullptr;
  int nng_res = nng_recvmsg(socket_, &msg, 0);
  if (nng_res != 0) return ErrorResult("Failed to receive message: " + string(nng_strerror(nng_res)));

  size_t recv_len = nng_msg_len(msg);
  BYTE* msg_body = static_cast<BYTE*>(nng_msg_body(msg));
  
  out_buffer.assign(msg_body, msg_body + recv_len);
  
  nng_msg_free(msg);
  return OkResult("Message received successfully");
}

void CustomEndpoint::Close() {
  if (is_initialized_) {
    nng_close(socket_);
    is_initialized_ = false;
  }
}

CustomEndpoint::CustomEndpoint()
    : socket_name_(kGenericSocketName + to_string(GetCurrentProcessId())), 
      is_initialized_(false) {}

CustomClientV2::CustomClientV2(unsigned int timeout_millis) 
    : CustomEndpoint(), timeout_millis_(timeout_millis) {}

int CustomClientV2::OpenSocket() {
  return nng_req_open(&socket_);
}

ProgramResult CustomClientV2::StartClient() {
  if (is_initialized_) return OkResult("Client already started");

  int nng_res = OpenSocket();
  if (nng_res != 0) return ErrorResult("Failed to open client socket: " + string(nng_strerror(nng_res)));

  if ((nng_res = nng_dialer_create(&dialer_, socket_, socket_name_.c_str())) != 0) {
    nng_close(socket_);
    return ErrorResult("Failed to create dialer: " + string(nng_strerror(nng_res)));
  }

  nng_setopt_ms(socket_, NNG_OPT_RECVTIMEO, timeout_millis_);  
  nng_setopt_ms(socket_, NNG_OPT_SENDTIMEO, timeout_millis_);  
  nng_setopt_int(socket_, NNG_OPT_REQ_RESENDTIME, 2000);  

  // Start dialer in non-blocking mode
  if ((nng_res = nng_dialer_start(dialer_, NNG_FLAG_NONBLOCK)) != 0) 
    return ErrorResult("Failed to start dialer: " + string(nng_strerror(nng_res)));

  is_initialized_ = true;
  return OkResult("Client started successfully");
}

ProgramResult CustomClientV2::SendRequest(Request req) {
  return SendMessage(req.serialize());
}

ProgramResult CustomClientV2::GetResponse(Response &res) {
  vector<BYTE> buffer;
  auto status = ReceiveMessage(buffer);
  if (status.IsErr()) return status;

  res.deserialize_here(buffer);
  return OkResult("Response deserialized");
}

CustomServerV2::CustomServerV2() 
    : CustomEndpoint() {}

int CustomServerV2::OpenSocket() {
  return nng_rep_open(&socket_);
}

ProgramResult CustomServerV2::SendResponse(Response res) {
  return SendMessage(res.serialize());
}

ProgramResult CustomServerV2::StartServer() {
  if (is_initialized_)
    return OkResult("Server already initialized");

  int nng_res = nng_rep_open(&socket_);
  if (nng_res != 0)
    return ErrorResult("Failed to open reply socket: " + string(nng_strerror(nng_res)));

  nng_res = nng_listen(socket_, socket_name_.c_str(), nullptr, 0);
  if (nng_res != 0) {
    if (nng_res == NNG_EADDRINUSE) {
      cout << "SERVER: Another server is already running on " 
           << socket_name_ << ". Stopping.\n";
      nng_close(socket_);
      is_initialized_ = false;
      return ErrorResult("Another server is already running. Stopping.");

    } else {
      nng_close(socket_);
      return ErrorResult("Failed to listen on socket: " + string(nng_strerror(nng_res)));
    }
  }

  is_initialized_ = true;
  return OkResult("Server successfully started");
}

ProgramResult CustomServerV2::GetRequest(Request &req) {
  vector<BYTE> buffer;
  auto res = ReceiveMessage(buffer);
  if (res.IsErr()) return res;

  req.deserialize_here(buffer);
  return OkResult("Data deserialized");
}

vector<unsigned char> Request::serialize() const {
  vector<unsigned char> buffer(sizeof(command) + sizeof(SIZE_T) + data.size());

  SIZE_T data_size = data.size();
  memcpy(buffer.data(), &command, sizeof(command));
  memcpy(buffer.data() + sizeof(command), &data_size, sizeof(data_size));
  memcpy(buffer.data() + sizeof(command) + sizeof(data_size), data.data(), data_size);

  return buffer;
}

Request Request::deserialize(const vector<unsigned char> &buffer) {
  Request req;
  SIZE_T data_size;
  
  memcpy(&req.command, buffer.data(), sizeof(req.command));
  memcpy(&data_size, buffer.data() + sizeof(req.command), sizeof(data_size));
  
  req.data.resize(data_size);
  memcpy(req.data.data(), buffer.data() + sizeof(req.command) + sizeof(data_size), data_size);

  return req;
}
void Request::deserialize_here(const std::vector<unsigned char> &buffer) {
}

vector<unsigned char> Response::serialize() const
{
    vector<unsigned char> buffer(sizeof(code) + sizeof(SIZE_T) + data.size());

    SIZE_T data_size = data.size();
    memcpy(buffer.data(), &code, sizeof(code));
    memcpy(buffer.data() + sizeof(code), &data_size, sizeof(data_size));
    memcpy(buffer.data() + sizeof(code) + sizeof(data_size), data.data(), data_size);

    return buffer;
}

Response Response::deserialize(const vector<unsigned char> &buffer) {
  Response res;
  SIZE_T data_size;
  
  memcpy(&res.code, buffer.data(), sizeof(res.code));
  memcpy(&data_size, buffer.data() + sizeof(res.code), sizeof(data_size));
  
  res.data.resize(data_size);
  memcpy(res.data.data(), buffer.data() + sizeof(res.code) + sizeof(data_size), data_size);

  return res;
}

void Response::deserialize_here(const std::vector<unsigned char> &buffer) {
  SIZE_T data_size;

  memcpy(&code, buffer.data(), sizeof(code));
  memcpy(&data_size, buffer.data() + sizeof(code), sizeof(data_size));
  
  data.resize(data_size);
  memcpy(data.data(), buffer.data() + sizeof(code) + sizeof(data_size), data_size);
}

vector<unsigned char> KeyDataMessage::serialize() const {
  auto buffer = vector<unsigned char>(sizeof(KeyDataMessage));

  memcpy(buffer.data(), &key_handle, sizeof(key_handle));
  memcpy(buffer.data() + sizeof(key_handle), &blob_type, sizeof(blob_type));

  return buffer;
}

KeyDataMessage KeyDataMessage::deserialize(const vector<unsigned char> &buffer) {
  KeyDataMessage key_data;

  memcpy(&key_data.key_handle, buffer.data(), sizeof(key_handle));
  memcpy(&key_data.blob_type, buffer.data() + sizeof(key_handle), sizeof(blob_type));

  return key_data;
}

void KeyDataMessage::deserialize_here(const std::vector<unsigned char> &buffer) {
  memcpy(&key_handle, buffer.data(), sizeof(key_handle));
  memcpy(&blob_type, buffer.data() + sizeof(key_handle), sizeof(blob_type));
}

} // namespace custom_ipc
