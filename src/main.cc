#include <windows.h>

#include <intsafe.h>
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <stdlib.h>
#include <functional>
#include <filesystem>

#include <CLI/CLI.hpp>
#include <config.h>

#include "process_capturer.h"
#include "program_result.h"
#include "scanners.h"
#include "key_scanner.h"

using namespace process_manipulation;
using namespace key_scanner;
using namespace error_handling;
using namespace std;

namespace fs = std::filesystem;

enum class ActionOptions : int { kPause, kNtPause, kResume, kKill, kDoNothing };
enum class ScannerOptions : int { kCryptoAPIScan, kAESRoundKeyScan };

std::map<std::string, ActionOptions> actions_map {
  {"resume", ActionOptions::kResume },
  {"pause", ActionOptions::kPause},
  {"ntpause", ActionOptions::kNtPause},
  {"kill", ActionOptions::kKill},
  {"nothing", ActionOptions::kDoNothing},
};

std::map<std::string, ScannerOptions> scanners_map {
  {"roundkey", ScannerOptions::kAESRoundKeyScan },
  {"crapi", ScannerOptions::kCryptoAPIScan },
};

template <typename EnumClass>
std::string GetChoices(const std::map<std::string, EnumClass>& options_map, const std::string& description) {
  // Dynamically build the choices string from the map keys
  std::ostringstream choices;
  choices << description << " (";
  for (auto it = options_map.begin(); it != options_map.end(); ++it) {
    choices << it->first;
    if (std::next(it) != options_map.end()) {  // add comma if not the last element
      choices << ", ";
    }
  }
  choices << ")";
  return choices.str();
}

bool LoadConfig() {
  wstring config_file = L"config.toml";
  if (!fs::exists(config_file)) {
    wcout << "[!] Config file not found, creating a new one with the name: " << config_file << endl;
    ofstream empty_file(config_file);
  }
  
  ProgramResult result = Config::Instance().Load(config_file);
  if (result.IsErr()) {
    cerr << result.GetResultInformation() << endl;
    return false;
  }

  return true;
}

int main(int argc, char *argv[]) {
  CLI::App app("@PROGRAM_NAME@: cryptographic key recovery for live processes");

  app.set_version_flag("-v,--version", "@PROGRAM_NAME@ version @PROJECT_VERSION@");

  // CUSTOM PARSERS
  auto actions_transformer = CLI::Transformer(actions_map, CLI::ignore_case)
    .description(GetChoices<ActionOptions>(actions_map, "Actions"));
  auto scanners_transformer = CLI::Transformer(scanners_map, CLI::ignore_case)
    .description(GetChoices<ScannerOptions>(scanners_map, "Scanners"));

  // INPUT VARIABLES
  ActionOptions action_after{ActionOptions::kDoNothing};
  ActionOptions action_before{ActionOptions::kDoNothing};
  std::vector<ScannerOptions> scanners;
  string output_json = "";
  unsigned int pid = 0;
  std::vector<unsigned long> excluded_threads;
  bool output_binary_keys = false;
  bool extended_search_enabled = false;

  // KEY SCANNING
  CLI::App* scan_subcommand = app.add_subcommand("scan", "Scan for keys in the process. It is possible to add more than one at a time");
  app.require_subcommand(1);
  scan_subcommand->add_option("-b,--before", action_before, "Action to perform before the scan over the threads of the process")
    ->transform(actions_transformer);
  scan_subcommand->add_option("-a,--after", action_after, "Action to perform after the scan over the threads of the process")
    ->transform(actions_transformer);

  scan_subcommand->add_option("-o,--output", output_json, 
  "Output file for the keys JSON. If not specified, no file is exported."
  "If a file exists with the same name, it gets overwritten.");

  scan_subcommand->add_option("-p,--pid", pid, "PID of the target process")
    ->required()
    ->check(CLI::NonNegativeNumber);
  
  scan_subcommand->add_flag("-x", extended_search_enabled, "Set this flag to enable improved heap enumeration. Make sure to activate it when working with big heaps (will only work with NT Heaps).")
    ->default_val(false);

  scan_subcommand->add_option("--scanners", scanners, "Scanners to extract keys with")
    ->required()
    ->expected(1, -1)
    ->transform(scanners_transformer);

  scan_subcommand->add_flag("--bin", output_binary_keys, "Set this flag to export all found keys in binary format. Keys are named and enumerated starting by zero");

  // PROCESS SUBCOMMAND
  CLI::App* process_subcommand = app.add_subcommand("proc", "For manipulating all threads of the target process");
  process_subcommand->add_option("-p,--pid", pid, "PID of the target process")
    ->required()
    ->check(CLI::PositiveNumber);
  process_subcommand->add_option("-a,--action", action_before, "Action to perform")
    ->required()
    ->transform(actions_transformer);


  // TODO: THREAD HANDLING
  scan_subcommand->add_option("-e,--exclude-threads", excluded_threads, "Thread IDs to exclude from the pause. Will not work with ntpause")
    ->check(CLI::PositiveNumber);

  process_subcommand->add_option("-e,--exclude-threads", excluded_threads, "Thread IDs to exclude from the pause. Will not work with ntpause")
  ->check(CLI::PositiveNumber);

  // Macro for parsing and error checking (will exit if parsing fails)
  CLI11_PARSE(app, argc, argv);

  if (!LoadConfig()) {
    cerr << "[x] An error happened while loading the configuration\n";
    return 1;
  }

  cout << "[i] Capturing PID: " << pid << endl;
  auto scanner = ScannerFacade(pid, ScannerVector(), OnDestroyAction::kDoNothing);
  if (!scanner.IsProcessAlive()) {
    printf("[x] Process is not alive");
    exit(1);
  }

  // PRE-SCAN ACTIONS
  if (process_subcommand || scan_subcommand) {
    if (action_before != ActionOptions::kDoNothing) {
      ProgramResult pr =
      (action_before == ActionOptions::kResume) ? scanner.ResumeProcess(true) :
      (action_before == ActionOptions::kNtPause) ? scanner.PauseProcess(PauseStrategy::NtPauseProcess) :
      (action_before == ActionOptions::kPause) ? scanner.PauseProcess(PauseStrategy::AllThreadPause, excluded_threads) :
      (action_before == ActionOptions::kKill) ? scanner.KillProcess() :
      ErrorResult("Invalid option");

      cout << pr.GetResultInformation() << endl;
    } else {
      // else: perform no action over the process threads (only extract keys)
      printf(" [i] No action selected, proceeding to scan\n");
    }
  }

  if (action_before == ActionOptions::kKill && scan_subcommand)
    return 0;

  // SCANNING
  if (scan_subcommand) {
    if (scanners.empty()) {
      printf(" [x] No scanner selected\n");
      exit(2);
    }

    auto sb = ScannerBuilder();
    for (auto scanner : scanners) {
      if (scanner == ScannerOptions::kCryptoAPIScan) sb.AddCryptoAPIScan();
      else if (scanner == ScannerOptions::kAESRoundKeyScan) sb.AddRoundKeyScan();
    }

    scanner.AddScanners(sb.GetScanners());

    printf("Starting key scan\n");
    auto keys = scanner.DoScan(extended_search_enabled);

    printf("All found keys: \n");
    unsigned int i = 1;
    for (auto &key : keys) {

      cout << " Key [" << i++ << "/" << keys.size() << "]: " << endl;
      cout << "  * Type: " << key->GetAlgorithm() << endl << "  * Size: " << key->GetSize() << " bytes" << endl << endl;
      ProcessCapturer::PrintMemory(&key->GetKey()[0], key->GetSize());

      printf("---\n\n");
    }

    if (output_json != "") {
      cout << scanner.ExportKeysToJSON(output_json).GetResultInformation() << std::endl;
    }

    if (output_binary_keys) {
      cout << " [i] Exporting keys in binary format\n";
      cout << scanner.ExportKeysToBinary().GetResultInformation() << std::endl;
    }
  }

  // POST-SCAN ACTIONS
  if (scan_subcommand) {
    if (action_after != ActionOptions::kDoNothing) {
      ProgramResult pr =
        (action_after == ActionOptions::kResume) ? scanner.ResumeProcess(true) :
        (action_after == ActionOptions::kNtPause) ? scanner.PauseProcess(PauseStrategy::NtPauseProcess) :
        (action_after == ActionOptions::kPause) ? scanner.PauseProcess(PauseStrategy::AllThreadPause) :
        (action_after == ActionOptions::kKill) ? scanner.KillProcess() :
        ErrorResult("Invalid option");

      cout << pr.GetResultInformation() << endl;
    } else {
      // else: perform no action over the process threads (only extract keys)
      printf(" [i] No post action selected\n");
    }
  }

  getchar();  // TODO: remove (temporary)
  return 0;
}
