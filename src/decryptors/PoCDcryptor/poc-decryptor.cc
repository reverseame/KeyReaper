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

CRAPI_PLAINTEXTKEYBLOB GetKeyFromJSON(string json_file) {
  CRAPI_PLAINTEXTKEYBLOB key_blob_bytes = CRAPI_PLAINTEXTKEYBLOB();
  vector<BYTE> key_bytes = vector<BYTE>();

  cout << " [i] Reading key from file:" << json_file << endl;
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

            printf(" [i] Recovered key:");
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

bool SaveDecryptedDataToFile(const fs::path& encrypted_file_path, const std::vector<BYTE>& decrypted_data) {
  fs::path output_file_path = encrypted_file_path;  // Same name and path,
  output_file_path.replace_extension("");           // removing the ".enc" extension

  ofstream decrypted_file(output_file_path, ios::binary);
  if (!decrypted_file) {
    cerr << " [x] Failed to create decrypted file: " << output_file_path << '\n';
    return false;
  }

  decrypted_file.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
  decrypted_file.close();

  std::cout << " [i] Decrypted file saved as: " << output_file_path << '\n';
  return true;
}

bool DecryptData(HCRYPTKEY key_handle, vector<BYTE>& encrypted_data) { //, BYTE* iv) {
  DWORD data_len = static_cast<DWORD>(encrypted_data.size());

  // Decrypt the data
  if (!CryptDecrypt(key_handle, 0, TRUE, 0, encrypted_data.data(), &data_len)) {
    cerr << "Error decrypting data: " << GetLastError() << '\n';
    return false;
  }

  // Resize the vector to the actual decrypted data length (may have padding removed)
  encrypted_data.resize(data_len);
  return true;
}

BOOL ImportCryptoKeyToProvider(string keys_json, HCRYPTPROV hProv, HCRYPTKEY *hKey) {
  BOOL status = false;
  
  CRAPI_PLAINTEXTKEYBLOB key = GetKeyFromJSON(keys_json);
  if (key.isOk()) {
    status = CryptImportKey(hProv, (BYTE*) &key, key.size(), 0, 0, hKey);
  } else printf(" [x] No key could be retieved");

	return status;
}

int DecryptFiles(string keys_json, string path) {
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

  // ENUMERATE FILES
  cout << " [i] Loading files from: " << path << endl << endl;
  string ext(".enc");
  for (const auto &p : fs::recursive_directory_iterator(path)) {
    if (p.path().extension() == ext) {
      cout << " [i] Decrypting file: " << p.path().string() << '\n';

      ifstream file(p.path(), std::ios::binary);
      if (!file) {
        cout << " [x] Failed to open file: " << p.path() << endl;
        continue;
      }

      vector<BYTE> encrypted_data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
      file.close();

      if (DecryptData(key_handle, encrypted_data)) {
        if (!SaveDecryptedDataToFile(p.path(), encrypted_data)) {
          cout << " [x] Failed to write unencrypted data to file" << endl;
        } else {
          cout << " [i] Deleting encrypted file" << endl;
          fs::remove(p);
        }
      }
      printf(" ----------\n");
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program("custom_crapi_decryptor");

  program.add_argument("-k", "--keys")
    .default_value("./keys.json")
    .help("JSON file with the keys");

  program.add_argument("-p", "--path")
    .default_value("C:/TEST/")
    .help("Path with the files to decrypt");

  // TODO: add an argument for comparing a file with its original, to verify that the key is correct

  try {
    program.parse_args(argc, argv);
  }
  catch (const exception& err) {
    cerr << err.what() << endl;
    cerr << program;
    exit(1);
  }

  DecryptFiles(
    program.get<string>("--keys"),
    program.get<string>("--path")
  );

  return 0;

}