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

wstring ExePath() {
  wchar_t buffer[MAX_PATH] = { 0 };
  GetModuleFileNameW(NULL, buffer, MAX_PATH);
  wstring fullPath(buffer);
  wstring::size_type pos = fullPath.find_last_of(L"\\/");
  return fullPath.substr(0, pos);
}

bool FileExists(wstring filename) {
  ifstream file_check(filename);
  if (file_check) return true;
  else return false;
}

ProgramResult Config::Load(const wstring& filename) {
  if (!FileExists(filename)) return ErrorResult("Could not find config file");

  toml::table config;
  try {
    config = toml::parse_file(filename);
    
  } catch (const toml::parse_error& err) {
    wcerr << L"Error while parsing " << filename; 
    cerr << ": " << err << endl;
    return ErrorResult("Failed to parse config file ");
  }

  auto current_path = ExePath();

#if _WIN64
  wstring default_dll = current_path + L"\\injectable_server_x64.dll";
#else
  wstring default_dll = current_path + L"\\injectable_server_x86.dll";
#endif
  key_extractor_dll_ = config["Settings"]["key_extractor_dll_path"].value_or(default_dll);
  if (!FileExists(key_extractor_dll_)) {
    cerr << "Default DLL not set in the config file\n";
    if (!FileExists(default_dll)) return ErrorResult("Could not find a valid DLL");
    wcerr << "Specified path to DLL does not exist. Defaulting to " << default_dll << endl;
  }
  
  return OkResult("Configuration successfully loaded");
}

std::wstring Config::GetKeyExtractorDLLPath() const {
  return key_extractor_dll_;
}