#include <config.h>
#include <iostream>
#include <fstream>
#include <windows.h>

using namespace std;
using namespace error_handling;

Config& Config::Instance() {
  static Config instance;
  return instance;
}

wstring StringToWString(const string& str) {
  if (str.empty()) return wstring();

  int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
  if (size_needed == 0) return wstring();  // Conversion failed

  wstring wstr(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);

  return wstr;
}


bool FileExists(string filename) {
  ifstream file_check(filename);
  if (file_check) return true;
  else return false;
}

ProgramResult Config::Load(const string& filename) {
  if (!FileExists(filename)) return ErrorResult("Could not find config file");

  toml::table config;
  try {
    config = toml::parse_file(filename);
    
  } catch (const toml::parse_error& err) {
    cerr << err << endl;
    return ErrorResult("Failed to parse config file " + filename);
  }

#if _WIN64
  string default_dll = "injectable_server_x64.dll";
#else
  string default_dll = "injectable_server_x86.dll";
#endif
  key_extractor_dll_ = config["Settings"]["key_extractor_dll_path"].value_or(default_dll);
  if (!FileExists(key_extractor_dll_)) {
    cerr << "Could not find a default\n";
    if (!FileExists(default_dll)) return ErrorResult("Could not find a valid DLL");
    cerr << "Specified path to DLL does not exist. Defaulting to " << default_dll << endl;
  }
  
  return OkResult("Configuration successfully loaded");
}

std::wstring Config::GetKeyExtractorDLLPath() const {
  return StringToWString(key_extractor_dll_);
}