#include <iostream>
#include <chrono>
#include <thread>
#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>

#include "injection/interproc_coms.h"

using namespace std;
using namespace error_handling;

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

  return OkResult("Message successfully sent");
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

CustomEndpoint::CustomEndpoint(string name)
    : socket_name_(kGenericSocketName + name), 
      is_initialized_(false) {}

CustomClient::CustomClient(DWORD pid, unsigned int timeout_millis)
    : CustomEndpoint(to_string(pid)), timeout_millis_(timeout_millis) {}

int CustomClient::OpenSocket() {
  return nng_req_open(&socket_);
}

ProgramResult CustomClient::StartClient() {
  if (is_initialized_) return OkResult("Client already started");
  else printf("Listening on socket: %s\n", socket_name_.c_str());

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

ProgramResult CustomClient::SendRequest(Request req) {
  return SendMessage(req.serialize());
}

ProgramResult CustomClient::GetResponse(Response &res) {
  vector<BYTE> buffer;
  auto status = ReceiveMessage(buffer);
  if (status.IsErr()) return status;
  if (buffer.empty()) return ErrorResult("Message is empty");

  res.deserialize_here(buffer);
  return OkResult("Response deserialized");
}

CustomServer::CustomServer(DWORD pid) 
    : CustomEndpoint(to_string(pid)) {}

int CustomServer::OpenSocket() {
  return nng_rep_open(&socket_);
}

ProgramResult CustomServer::SendResponse(Response res) {
  return SendMessage(res.serialize());
}

ProgramResult CustomServer::StartServer() {
  if (is_initialized_) return OkResult("Server already initialized");

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

ProgramResult CustomServer::GetRequest(Request &req) {
  vector<BYTE> buffer;
  auto res = ReceiveMessage(buffer);
  if (res.IsErr()) return res;
  if (buffer.empty()) return ErrorResult("Message is empty");

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
  SIZE_T data_size;
  
  memcpy(&command, buffer.data(), sizeof(command));
  memcpy(&data_size, buffer.data() + sizeof(command), sizeof(data_size));
  
  data.resize(data_size);
  memcpy(data.data(), buffer.data() + sizeof(command) + sizeof(data_size), data_size);
}

/*
  SIZE_T data_size;

  memcpy(&code, buffer.data(), sizeof(code));
  memcpy(&data_size, buffer.data() + sizeof(code), sizeof(data_size));
  
  data.resize(data_size);
  memcpy(data.data(), buffer.data() + sizeof(code) + sizeof(data_size), data_size);
*/

vector<unsigned char> Response::serialize() const {
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
