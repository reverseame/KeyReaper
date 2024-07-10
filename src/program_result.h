#ifndef PROGRAMRESULT_H
#define PROGRAMRESULT_H

#include <string>
using namespace std;

#define MAX_INFO_MSG_SIZE 256

class ProgramResult {
 public:
  enum class ResultType { kError, kWarning, kOk };
  ProgramResult(ResultType type, const string info);
  bool IsOk();
  string GetResultInformation();

 private:
  ResultType result_type_;
  string info_;
};

#endif
