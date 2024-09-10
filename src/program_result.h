#ifndef PROGRAMRESULT_H
#define PROGRAMRESULT_H

#include <string>

#define PROC_NOT_ALIVE_ERR_MSG "Process is not alive"
#define PROC_STILL_RUN_ERR_MSG "Process is still running"
#define PROC_SUSP_ERR_MSG "Process was already suspended"
#define PROC_OPEN_ERR_MSG "Could not open the process"
#define PROC_CLOSE_ERR_MSG "Could not close handle to process"

#define THREAD_OPEN_ERR_MSG "Could not open thread"
#define THEAD_PAUSE_ERR_MSG "Could not suspend thread"
#define THREAD_CLOSE_ERR_MSG "Could not close handle to thread"
#define THREAD_RESUME_ERR_MSG "Failed to resume the thread"
#define THREAD_SNAP_ERR_MSG "Could not create a snapshot of the threads"
#define THREAD_SNAP_FIRST_ERR_MSG "Could not copy the first thread entry"
#define THREAD_SNAP_NO_INFO_ERR_MSG "Did not find any thread information in the snapshot" 

namespace error_handling {

enum class ResultType { kError, kOk };

class ProgramResult {
 public:
  ProgramResult(ResultType type, const std::string info);
  virtual bool IsOk();
  std::string GetResultInformation();

 private:
  ResultType result_type_;
  std::string info_;
};

class ErrorResult : public ProgramResult {
 public:
  ErrorResult(const std::string info) : ProgramResult(ResultType::kError, info) {};
  bool IsOk() override { return false; };
};

class OkResult : public ProgramResult {
 public:
  OkResult(const std::string info) : ProgramResult(ResultType::kOk, info) {};
  bool IsOk() override { return true; };
};

}

#endif
