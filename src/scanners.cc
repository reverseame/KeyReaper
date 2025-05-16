#include <memory>
#include <windows.h>
#include <functional>
#include <algorithm>
#include <iostream>

#include "key.h"
#include "scanners.h"
#include "process_capturer.h"
#include "cryptoapi.h"
#include "injection/custom_ipc.h"
#include <aes.h>

using namespace std;
using ProcessCapturer = process_manipulation::ProcessCapturer;
using HeapSegment = process_manipulation::HeapSegment;


namespace key_scanner {

void ScannerBuilder::AddCryptoAPIScan() {
  do_crapi_structure_scan_ = true;
}

void ScannerBuilder::AddRoundKeyScan() {
  do_round_key_scan_ = true;
}

ScannerVector ScannerBuilder::GetScanners() {

  unique_ptr<vector<unique_ptr<ScanStrategy>>> strategies = make_unique<vector<unique_ptr<ScanStrategy>>>();

  if (do_round_key_scan_) {
    RoundKeyScan s = RoundKeyScan();
    strategies->push_back(make_unique<RoundKeyScan>(s));
  }

  if (do_crapi_structure_scan_) {
    CryptoAPIScan s = CryptoAPIScan();
    strategies->push_back(make_unique<CryptoAPIScan>(s));
  }

  return ScannerVector(move(strategies));
}

bool InitializeDLLPointers(HMODULE cryptoapi_module, vector<uintptr_t>& function_list) {
  for (string func_name : cryptoapi::cryptoapi_function_names) {
    FARPROC func_address = GetProcAddress(cryptoapi_module, func_name.c_str());

    if (func_address != NULL) {
      // Cast and add it to the list with all the functions
      function_list.push_back(reinterpret_cast<uintptr_t>(func_address));

    } else {
      cerr << " [x] Could not initialize a function pointer to " << func_name << endl;
      cerr << "   * " << error_handling::GetLastErrorAsString() << endl;
      return false;
    }
  }
  return true;
}

HMODULE CryptoAPIScan::rsaenh_base_address = NULL;
HMODULE CryptoAPIScan::dssenh_base_address = NULL;
vector<uintptr_t> CryptoAPIScan::rsaenh_functions = vector<uintptr_t>();
vector<uintptr_t> CryptoAPIScan::dssenh_functions = vector<uintptr_t>();
bool CryptoAPIScan::cryptoapi_functions_initialized = false;

void CryptoAPIScan::InitializeCryptoAPI() {
  if (!cryptoapi_functions_initialized) {
    rsaenh_functions.clear();

    if (rsaenh_base_address == NULL) rsaenh_base_address = LoadLibraryA("rsaenh.dll");
    if (dssenh_base_address == NULL) dssenh_base_address = LoadLibraryA("dssenh.dll");

    if (rsaenh_base_address != NULL)
      cryptoapi_functions_initialized = InitializeDLLPointers(rsaenh_base_address, rsaenh_functions);
    else printf(" [x] Could not initialize rsaenh.dll\n");

    if (dssenh_base_address != NULL) 
      cryptoapi_functions_initialized = InitializeDLLPointers(dssenh_base_address, dssenh_functions);
    else printf(" [x] Could not initialize dssenh.dll\n");
  }
}

unordered_set<HCRYPTKEY> SearchHCRYPTKEYs(unsigned char* input_buffer, process_manipulation::HeapSegment heap_info, vector<BYTE> byte_pattern) {
  auto found_hcryptkeys = unordered_set<HCRYPTKEY>();
  auto searcher = boyer_moore_horspool_searcher(byte_pattern.data(), byte_pattern.data() + byte_pattern.size());

  unsigned char* search_start = input_buffer;
  unsigned char* search_result;

  // While there are matches left
  while ((search_result = search(search_start, input_buffer + heap_info.GetSize(), searcher)) != input_buffer + heap_info.GetSize()) {
    uintptr_t position = search_result - input_buffer;

    HCRYPTKEY key = heap_info.GetBaseAddress() + position;
    found_hcryptkeys.insert(key);

    search_start = search_result + byte_pattern.size();
  }
  
  return found_hcryptkeys;
}

vector<BYTE> CryptoAPIScan::GetCryptoAPIFunctionsPattern(vector<uintptr_t>& function_list) {
  if (!cryptoapi_functions_initialized) return vector<BYTE>();

  uintptr_t pos = 0;
  size_t pattern_size = function_list.size() * sizeof(void*);
  vector<BYTE> byte_pattern = vector<BYTE>(pattern_size);
  for (auto& offset : function_list) {
    memcpy(byte_pattern.data() + pos, &offset, sizeof(void*));
    pos += sizeof(void*);
  }

  return byte_pattern;
}

/*
// KEY MANUAL EXTRACTION TEST
typedef NTSTATUS (NTAPI *PFN_NTDEVICEIOCONTROLFILE)(
  HANDLE FileHandle,
  HANDLE Event,
  PIO_APC_ROUTINE ApcRoutine,
  PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG IoControlCode,
  PVOID InputBuffer,
  ULONG InputBufferLength,
  PVOID OutputBuffer,
  ULONG OutputBufferLength
);

void GetPrivateRSAPair(unsigned char* input_buffer, HeapSegment heap_info) {

  // 1. Search for "RSA2" and copy the bytes
  // 2. Perform the same call as the CryptoAPI 
  
 HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (!hNtdll) {
    printf("Failed to get handle to ntdll.dll\n");
    return;
  }

  // Get the address of NtDeviceIoControlFile
  PFN_NTDEVICEIOCONTROLFILE NtDeviceIoControlFile =
    (PFN_NTDEVICEIOCONTROLFILE)GetProcAddress(hNtdll, "NtDeviceIoControlFile");
  if (!NtDeviceIoControlFile) {
    printf("Failed to get address of NtDeviceIoControlFile\n");
    return;
  }
  BYTE rsa2_pattern[] = { 
    'R', 'S', 'A', '2'
  };
  DWORD pattern_size = 4;
  DWORD rsa2_size = 0x2BC;
  auto rsa2_searcher = boyer_moore_horspool_searcher(rsa2_pattern, rsa2_pattern + pattern_size);
  
  size_t matches = 0;
  unsigned char* search_start = input_buffer;
  unsigned char* search_result;
  while((search_result = search(search_start, input_buffer + heap_info.GetSize(), rsa2_searcher)) != input_buffer + heap_info.GetSize()) {
    matches++;
    uintptr_t position = search_result - input_buffer;
    printf("[%zu] RSA2 shadow found [0x%p]\n", matches, (void*) position);
    ProcessCapturer::PrintMemory(search_result, rsa2_size, 0);

    search_start = search_result + pattern_size;
    getchar();
  }
  if (matches == 0) printf("No matches found\n");

  HANDLE hSourceProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, 7892);
  if (!hSourceProcess) {
    printf("Failed to open source process: %lu\n", GetLastError());
    return;
  }

  HANDLE hTargetProcess = GetCurrentProcess(); // Duplicate into the current process
  HANDLE hDuplicatedHandle;

  if (DuplicateHandle(
    hSourceProcess,      // Source process
    (HANDLE) 0x12C,  // Handle to duplicate
    hTargetProcess,      // Target process
    &hDuplicatedHandle,  // New handle
    0,                   // Access rights (0 = same as source)
    FALSE,               // Not inheritable
    DUPLICATE_SAME_ACCESS)) { // Same access rights
    printf("Successfully duplicated handle\n");
  } else {
    printf("Failed to duplicate handle: %lu\n", GetLastError());
  }

  CloseHandle(hSourceProcess);

  IO_STATUS_BLOCK status_block;
  NTSTATUS res = NtDeviceIoControlFile(
    hDuplicatedHandle,
    0,
    0,
    0,
    &status_block,
    0x390012,
    search_result,
    rsa2_size,
    search_result,
    rsa2_size
  );
  printf("0x%X\n", res);
  ProcessCapturer::PrintMemory(search_result, rsa2_size, 0);
  getchar();
}

*/

void InjectExtractKeys(unordered_set<HCRYPTKEY> key_handles) {
  for (auto key : key_handles) {
    custom_ipc::SendKeyHandleToMailSlot(key);
  }
}

void ExtractRemoteKey(HCRYPTKEY key_handle, DWORD blob_type, cryptoapi::CryptoAPIProvider provider, unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>& key_set, ProcessCapturer& capturer) {
  vector<BYTE> key_blob;
  auto res = capturer.GetKeyBlobFromRemote(key_handle, blob_type, key_blob, provider);
  
  if (res.IsOk()) {
    BLOBHEADER* blob = reinterpret_cast<BLOBHEADER*>(key_blob.data());
    // printf("BLOB DATA:\n * ALG_ID: %X\n", blob->aiKeyAlg);
    // ProcessCapturer::PrintMemory(key_blob.data(), key_blob.size());
    key_set.insert(
      make_shared<CryptoAPIKey>(
        // TODO: replace the key_blob.size() for the actual key size
        CryptoAPIKey(blob->aiKeyAlg, key_blob.size(), key_blob.data(), key_handle)
      )
    );
  } 

  printf(" [%s][%s] (0x%p) %s\n",
      res.IsOk() ? "i" : "x",
      blob_type == PUBLICKEYBLOB ? "PUBK" : 
      blob_type == PRIVATEKEYBLOB ? "PRVK" :
      blob_type == PLAINTEXTKEYBLOB ? "PLAIN" : "UNKN",
    (void*) key_handle, res.GetResultInformation().c_str());
}

unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> ExtractKeys(unordered_set<HCRYPTKEY>& key_handles, unsigned char* input_buffer, HeapSegment heap_info, ProcessCapturer& capturer, cryptoapi::CryptoAPIProvider provider) {
  auto found_keys = unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>();
  for (auto key_handle : key_handles) {
    // printf(" HANDLE: %p\n", (void*) key_handle);
    auto address = key_handle;
    heap_info.RebaseAddress(&address, (ULONG_PTR) input_buffer);

    // XOR with the magic constant
    SIZE_T data_read = 0;
    auto buffer = vector<BYTE>();
    auto raw_key = vector<BYTE>();

    cryptoapi::HCRYPTKEY* h_crypt_key = reinterpret_cast<cryptoapi::HCRYPTKEY*>(address);

    ULONG_PTR magic_constant;
    if (provider == cryptoapi::kDssEnh) magic_constant = DSSENH_CONSTANT;
    else if (provider == cryptoapi::kRsaEnh) magic_constant = RSAENH_CONSTANT;
    else {
      printf(" [x] Invalid provider, aborting\n");
      return found_keys;
    }

    ULONG_PTR unk_struct = (ULONG_PTR) (h_crypt_key->magic) ^ magic_constant; // virtual address
    cryptoapi::unk_struct* unkown_struct_ptr = NULL;

    if (!heap_info.RebaseAddress(&unk_struct, (ULONG_PTR) input_buffer)) {
      printf(" Magic struct address [0x%p] is outside of the heap dump, trying a manual copy\n", (void*) unk_struct);
      buffer.resize(sizeof(cryptoapi::unk_struct), 0);

      error_handling::ProgramResult res = capturer.GetMemoryChunk((BYTE*) unk_struct, sizeof(cryptoapi::unk_struct), buffer.data(), &data_read);
      if (res.IsOk() && data_read == sizeof(cryptoapi::unk_struct)) {
        unkown_struct_ptr = (cryptoapi::unk_struct*) buffer.data();
      
      } else {
        cerr << " [x] Error while copying the data: " << res.GetResultInformation() << endl;
        continue;
      }
    } else {
      unkown_struct_ptr = (cryptoapi::unk_struct*) unk_struct;
    }

    // DSSENH
    if (provider == cryptoapi::CryptoAPIProvider::kDssEnh) {
      ExtractRemoteKey(key_handle, PRIVATEKEYBLOB, provider, found_keys, capturer);
      ExtractRemoteKey(key_handle, PUBLICKEYBLOB, provider, found_keys, capturer);
    
    // RSAENH
    } else if (provider == cryptoapi::CryptoAPIProvider::kRsaEnh) {
      ULONG_PTR ptr = (ULONG_PTR) unkown_struct_ptr->key_data;
  
      cryptoapi::RSAENH_CRYPTKEY* key_data_struct = NULL;
      if (!heap_info.RebaseAddress(&ptr, (ULONG_PTR) input_buffer)) {
        printf(" Key data [0x%p] is out of this heap, trying a manual copy\n", unkown_struct_ptr->key_data);
        buffer.resize(sizeof(cryptoapi::RSAENH_CRYPTKEY), 0);
  
        error_handling::ProgramResult res = capturer.GetMemoryChunk((BYTE*) ptr, sizeof(cryptoapi::RSAENH_CRYPTKEY), buffer.data(), &data_read);
        if (res.IsOk() && data_read == sizeof(cryptoapi::RSAENH_CRYPTKEY)) {
          key_data_struct = (cryptoapi::RSAENH_CRYPTKEY*) buffer.data();
        } else {
          cerr << " [x] Error while copying the data: " << res.GetResultInformation() << endl;
          continue;
        }
  
      } else {
        key_data_struct = (cryptoapi::RSAENH_CRYPTKEY*) ptr;
      }
  
      DWORD alg = key_data_struct->alg;
      if ( alg == CALG_RSA_KEYX || alg == CALG_RSA_SIGN ) { // If asymmetric
        ExtractRemoteKey(key_handle, PRIVATEKEYBLOB, provider, found_keys, capturer);
        ExtractRemoteKey(key_handle, PUBLICKEYBLOB, provider, found_keys, capturer);
  
      } else { // symmetric algorithms
        ptr = (ULONG_PTR) key_data_struct->key_bytes;
  
        if (!heap_info.RebaseAddress(&ptr, (ULONG_PTR) input_buffer)) {
          printf(" Key [0x%p] is out of this heap, trying a manual copy\n", (void*) ptr);
          raw_key.resize(key_data_struct->key_size, '\0');
    
          error_handling::ProgramResult res = capturer.GetMemoryChunk((BYTE*) key_data_struct->key_bytes, key_data_struct->key_size, raw_key.data(), &data_read);
          if (res.IsOk() && data_read == key_data_struct->key_size) {
            ptr = (ULONG_PTR) raw_key.data();
          } else {
            cerr << " [x] Error while copying the data: " << res.GetResultInformation() << endl;
            continue;
          }
        }
  
        // ProcessCapturer::PrintMemory((unsigned char*) ptr, 16, (ULONG_PTR) key_data_struct->key_bytes);
        found_keys.insert(
          make_shared<CryptoAPIKey>(
            CryptoAPIKey(key_data_struct, (unsigned char*) ptr, key_handle)
          )
        );
      }
    } else printf("[x] Unrecognized provider\n");
  }

  return found_keys;
}

unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> CryptoAPIScan::Scan(unsigned char *input_buffer, HeapSegment heap_info, ProcessCapturer& capturer) const {
  auto found_keys = unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>();

  InitializeCryptoAPI();
  if (cryptoapi_functions_initialized) {
    // RSAENH
    vector<BYTE> byte_pattern = GetCryptoAPIFunctionsPattern(rsaenh_functions);
    auto rsaenh_key_handles = SearchHCRYPTKEYs(input_buffer, heap_info, byte_pattern);
    
    if (rsaenh_key_handles.size() != 0) {
      printf(" [i] %u RSAENH key handles found\n", rsaenh_key_handles.size());
      auto rsaenh_keys = ExtractKeys(rsaenh_key_handles, input_buffer, heap_info, capturer, cryptoapi::CryptoAPIProvider::kRsaEnh);
      found_keys.insert(rsaenh_keys.begin(), rsaenh_keys.end());
    } else printf(" [!] No matches for RSAENH keys\n");

    // DSSENH
    byte_pattern = GetCryptoAPIFunctionsPattern(dssenh_functions);
    auto dssenh_key_handles = SearchHCRYPTKEYs(input_buffer, heap_info, byte_pattern);

    if (dssenh_key_handles.size() != 0) {
      printf(" [i] %u DSSENH key handles found\n", dssenh_key_handles.size());
      auto dss_keys = ExtractKeys(dssenh_key_handles, input_buffer, heap_info, capturer, cryptoapi::CryptoAPIProvider::kDssEnh);
      found_keys.insert(dss_keys.begin(), dss_keys.end());   
    } else printf(" [!] No matches for DSSENH keys\n");
    
  } else printf("Could not load initialize necessary CryptoAPI functions\n");
  return found_keys;
}

unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction> RoundKeyScan::Scan(unsigned char *buffer, HeapSegment heap_info, ProcessCapturer& capturer) const {
  interrogate::interrogate_context ctx;
  int key_sizes[] = { 128, 192, 256 };
  auto found_keys = unordered_set<shared_ptr<Key>, Key::KeyHashFunction, Key::KeyHashFunction>();

  for (auto key_size : key_sizes) {
    ctx.keysize = key_size;
    ctx.from = 0;
    ctx.filelen = heap_info.GetSize();
    auto keys = interrogate::aes_search(&ctx, buffer);
    
    for (auto key : keys) {
      printf("FOUND KEY: \n");
      ProcessCapturer::PrintMemory(key.data(), key.size());
      found_keys.insert(
        make_shared<Key>(key.size(), CipherAlgorithm::kAES, key.data())
      );
    }
  }

  return found_keys;
}

ScannerVector::ScannerVector(unique_ptr<vector<unique_ptr<ScanStrategy>>> scanners) {
  scanners_ = move(scanners);
}

} // namespace key_scanner
