/**
 * This is a decryptor for the PoC ransomware (custom ransomware, basic ransomware)
 * using CryptoAPI.
 */

#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>

#include <nlohmann/json.hpp>
#include <argparse/argparse.hpp>

#define NOMINMAX  // To avoid macro collision (windows and argparse)
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib") // crypto api

#include "../../program_result.h"
#include "../../key.h"

using namespace std;
using namespace error_handling;
using namespace key_scanner;
using json = nlohmann::json;
namespace fs = std::filesystem;

std::vector<BYTE> LoadFileData(const std::string& filename) {
  std::ifstream file(filename, std::ios::binary);
  return { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };
}

CRAPI_PLAINTEXTKEYBLOB GetKeyFromJSON(string json_file) {
  CRAPI_PLAINTEXTKEYBLOB key_blob_bytes = CRAPI_PLAINTEXTKEYBLOB();
  vector<BYTE> key_bytes = vector<BYTE>();

  ifstream file(json_file);
  if (file) {
    json json_data;
    try {
      file >> json_data;

      if (json_data.size() > 0) {
        if (json_data.size() != 1) {
          printf(" [!] More than one key found. Only the first one in the list will be used");
        }
        
        auto key = json_data.begin().key();
        auto size = key.size();
        auto data = json_data.begin().value();

        if (data.contains("algorithm")) {
          if( data["algorithm"] == "AES" ) {
            key_bytes.reserve(size / 2);

            printf(" [i] Recovered key: ");
            for (size_t position = 0; position < size; position+=2) {
              std::string byteString = key.substr(position, 2);
              BYTE byte = static_cast<BYTE>(stoi(byteString, nullptr, 16));
              key_bytes.push_back(byte);
              printf(" %02X", byte);
            } printf("\n");

          } else {
            printf(" [x] Key is not AES");
          }
        } else {
          printf(" [x] Size field not found\n");
        }
      } else {
        printf(" [x] The JSON file must contain at least one key");
      }

    } catch (json::parse_error& e) {
      cerr << "Parse error: " << e.what() << endl;
    }

    file.close();
  } else {
    cerr << "Error: Could not open the file!" << endl;
  }

  if (key_bytes.size() == 16) {
    key_blob_bytes = CRAPI_PLAINTEXTKEYBLOB(16, CALG_AES_128, reinterpret_cast<const BYTE*>(key_bytes.data()));

  } else {
    printf(" [x] Key size does not match AES 128");
  }

  return key_blob_bytes;
}

BOOL ImportCryptoKeyToProvider(string keys_json, HCRYPTPROV hProv, HCRYPTKEY *hKey) {
  BOOL status = false;
  
  CRAPI_PLAINTEXTKEYBLOB key = GetKeyFromJSON(keys_json);
  if (key.isOk()) {
    status = CryptImportKey(hProv, (BYTE*) &key, key.size(), 0, 0, hKey);
  } else printf(" [x] No key could be retieved");

	return status;
}

int DecryptFiles(string keys_json) {
  HCRYPTPROV aes_provider = NULL;
  HCRYPTKEY key_handle = NULL;

  if (!CryptAcquireContextW(
      &aes_provider, NULL, 
      L"Microsoft Enhanced RSA and AES Cryptographic Provider", 
      PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT)) {
    cerr << "Error: CryptAcquireContext failed - " << GetLastErrorAsString() << endl;
    return 2;
  }

  if (!ImportCryptoKeyToProvider(keys_json, aes_provider, &key_handle)) {
    cerr << "Error: CryptImportKey failed - " << GetLastError() << " (" << GetLastErrorAsString() << ")" << endl;
    CryptReleaseContext(aes_provider, 0);
    return 3;
  }

  auto encryptedData = LoadFileData("");

  return 0;
}

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program("program_name");

  program.add_argument("-k", "--keys")
    .default_value("./keys.json")
    .help("JSON file with the keys");

  try {
    program.parse_args(argc, argv);
  }
  catch (const exception& err) {
    cerr << err.what() << endl;
    cerr << program;
    exit(1);
  }

  cout << program.get<string>("--keys") << endl;
  DecryptFiles(program.get<string>("--keys"));

  return 0;

}