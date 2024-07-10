#include "program_result.h"

ProgramResult::ProgramResult(ResultType type, const string info) 
    : result_type_(type), info_(info) {}

bool ProgramResult::IsOk()
{
    if (result_type_ == ResultType::kOk) {
      return true;
    }
    return false;
}

string ProgramResult::GetResultInformation() {
    return info_;
}

