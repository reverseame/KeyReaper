#ifndef CONFIG_H_
#define CONFIG_H_

#include <toml++/toml.hpp>
#include <string>
#include <program_result.h>

class Config {
 public:
  static Config& Instance();  // Singleton accessor

  error_handling::ProgramResult Load(const std::string& filename);

  std::wstring GetKeyExtractorDLLPath() const;

 private:
  Config() = default;  // Private constructor
  ~Config() = default;

  Config(const Config&) = delete;
  Config& operator=(const Config&) = delete;

  std::string key_extractor_dll_;
};

#endif  // CONFIG_H_
