#include <windows.h>

#include <intsafe.h>
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <stdlib.h>
#include <functional>

#include <CLI/CLI.hpp>

#include "process_capturer.h"
#include "program_result.h"
#include "scanners.h"
#include "key_scanner.h"

using namespace process_manipulation;
using namespace key_scanner;
using namespace error_handling;
using namespace std;

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

int main(int argc, char *argv[]) {
  CLI::App app("CRAPER: cryptographic key recovery for live processes");

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


  // KEY SCANNING
  CLI::App* scan_subcommand = app.add_subcommand("scan", "Scan for keys in the process. It is possible to add more than one at a time");
  app.require_subcommand(1);
  scan_subcommand->add_option("-b,--before", action_before, "Action to perform before the scan over the threads of the process")
    ->transform(actions_transformer);
  scan_subcommand->add_option("-a,--after", action_after, "Action to perform after the scan over the threads of the process")
    ->transform(actions_transformer);

  scan_subcommand->add_option("-o,--output", output_json, "Output file for the keys JSON. If not specified, no file is exported. If a file exists with the same name, it gets overwritten.")
    ->required();

  scan_subcommand->add_option("-p,--pid", pid, "PID of the target process")
    ->required()
    ->check(CLI::NonNegativeNumber);

  scan_subcommand->add_option("--scanners", scanners, "Scanners to extract keys with")
    ->required()
    ->expected(1, -1)
    ->transform(scanners_transformer);


  // PROCESS SUBCOMMAND
  CLI::App* process_subcommand = app.add_subcommand("proc", "For manipulating all threads of the target process");
  process_subcommand->add_option("-p,--pid", pid, "PID of the target process")
    ->required()
    ->check(CLI::PositiveNumber);
  process_subcommand->add_option("-a,--action", action_before, "Action to perform")
    ->required()
    ->transform(actions_transformer);


  // TODO: THREAD HANDLING

  // Macro for parsing and error checking (will exit if parsing fails)
  CLI11_PARSE(app, argc, argv);

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
      (action_before == ActionOptions::kPause) ? scanner.PauseProcess(PauseStrategy::AllThreadPause) :
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
    auto keys = scanner.DoScan();

    printf("All found keys: \n");
    unsigned int i = 1;
    for (auto &key : keys) {

      cout << " Key [" << i++ << "/" << keys.size() << "]: " << endl;
      cout << "  * Type: " << key.GetAlgorithm() << endl << "  * Size: " << key.GetSize() << " bytes" << endl << endl;
      ProcessCapturer::PrintMemory(&key.GetKey()[0], key.GetSize());

      printf("---\n\n");
    }

    if (output_json != "") {
      scanner.ExportKeysToJSON(output_json);
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
  return 0;
}
