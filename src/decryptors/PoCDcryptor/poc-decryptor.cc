/**
 * This is a decryptor for the PoC ransomware (custom ransomware, basic ransomware)
 * using CryptoAPI.
 */

#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <variant>
#include <chrono>

#include <nlohmann/json.hpp>
#include <CLI/CLI.hpp>
#include <indicators/indeterminate_progress_bar.hpp>
#include <indicators/cursor_control.hpp>
#include <indicators/termcolor.hpp>

#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib") // crypto api

#include "program_result.h"
#include "key.h"

using namespace std;
using namespace error_handling;
using namespace key_scanner;
namespace fs = std::filesystem;

using namespace indicators;
using json = nlohmann::json;

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
          printf(" [!] More than one key found. Only the first one in the list will be used\n");
        }
        
        auto key = json_data.begin().key();
        auto size = key.size();
        auto data = json_data.begin().value();

        if (data.contains("algorithm")) {
          if( data["algorithm"] == "AES" ) {
            key_bytes.reserve(size / 2);

            printf(" [i] Recovered key:");
            for (size_t position = 0; position < size; position+=2) {
              string byteString = key.substr(position, 2);
              BYTE byte = static_cast<BYTE>(stoi(byteString, nullptr, 16));
              key_bytes.push_back(byte);
              printf(" %02X", byte);
            } printf("\n");

          } else {
            printf(" [x] Key is not AES\n");
          }
        } else {
          printf(" [x] Size field not found\n");
        }
      } else {
        printf(" [x] The JSON file must contain at least one key\n");
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
    printf(" [x] Key size does not match AES 128\n");
  }

  return key_blob_bytes;
}

bool SaveDecryptedDataToFile(const fs::path& encrypted_file_path, const vector<BYTE>& decrypted_data) {
  fs::path output_file_path = encrypted_file_path;  // Same name and path,
  output_file_path.replace_extension("");           // removing the ".enc" extension

  ofstream decrypted_file(output_file_path, ios::binary);
  if (!decrypted_file) {
    // cerr << " [x] Failed to create decrypted file: " << output_file_path << '\n';
    return false;
  }

  decrypted_file.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
  decrypted_file.close();

  // cout << " [i] Decrypted file saved as: " << output_file_path << '\n';
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
  } else printf(" [x] No key could be retieved\n");

	return status;
}

void IteratePathDecryptingBar(string path, string extension, bool recursive, IndeterminateProgressBar& bar, HCRYPTKEY key_handle) {
  using DirIterator = std::variant<fs::recursive_directory_iterator, fs::directory_iterator>;
  DirIterator iterator = recursive ? DirIterator(fs::recursive_directory_iterator(path))
                                   : DirIterator(fs::directory_iterator(path));

  visit([&] (auto& directory_iterator) {
    for (const auto &p : directory_iterator) {
      if (p.path().extension() == extension) {
        // cout << " [i] Decrypting file: " << p.path().string() << '\n';
        // bar.set_option(option::PostfixText{ "Decrypting file: " + p.path().string() });

        ifstream file(p.path(), ios::binary);
        if (!file) {
          cerr << " [x] Failed to open file: " << p.path() << endl;
          continue;
        }

        vector<BYTE> encrypted_data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();

        if (DecryptData(key_handle, encrypted_data)) {
          if (!SaveDecryptedDataToFile(p.path(), encrypted_data)) {
            //cout << " [x] Failed to write unencrypted data to file" << endl;
          } else {
            //cout << " [i] Deleting encrypted file" << endl;
            // bar.set_option(option::PostfixText{ "Deleting encrypted file" });
            fs::remove(p);
          }
        }
        //printf(" ----------\n");
      }
    }
  }, iterator);
  
  // Update bar status
  bar.mark_as_completed();
  cout << termcolor::bold << termcolor::green
    << "Files decrypted\n" << termcolor::reset;
  bar.mark_as_completed();
}

int DecryptFiles(string keys_json, string path, string extension, bool recursive) {
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

  // User feedback
  IndeterminateProgressBar bar {
    indicators::option::BarWidth{40},
    indicators::option::Start{"["},
    indicators::option::Fill{"·"},
    indicators::option::Lead{"<==>"},
    indicators::option::End{"]"},
    indicators::option::PostfixText{"Checking for Updates"},
    indicators::option::ForegroundColor{indicators::Color::yellow},
    indicators::option::FontStyles{
        std::vector<indicators::FontStyle>{indicators::FontStyle::bold}}
  };

  show_console_cursor(false);
  std::thread decrypt_files_job(IteratePathDecryptingBar, path, extension, recursive, std::ref(bar), key_handle);
  while (!bar.is_completed()) {
    bar.tick();
    this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  decrypt_files_job.join();
  show_console_cursor(true);

  return 0;
}

int main(int argc, char *argv[]) {
  CLI::App app("Custom Cryptographic Decryptor for AES");
  string keys_json_file = "";
  string decryption_folder = "";
  string encrypted_files_extension = ".enc";
  bool recursive = false;

  app.add_option("-k,--keys", keys_json_file, "JSON file with the key(s)")
  ->required()
  ->check(CLI::ExistingFile);

  app.add_option("-p,--path", decryption_folder, "Path with the files to decrypt")
  ->required()
  ->check(CLI::ExistingDirectory);

  app.add_option("-e,--extension", encrypted_files_extension, "Extension of the encrypted files. It defaults to " + encrypted_files_extension);

  app.add_flag("-r,--recursive", recursive, "Set to perform decryption recursively.");
  // TODO: add an argument for comparing a file with its original, to verify that the key is correct

  CLI11_PARSE(app, argc, argv);

  return DecryptFiles(
    keys_json_file,
    decryption_folder,
    encrypted_files_extension,
    recursive
  );
}