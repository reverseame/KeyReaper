#include "program_result.h"

namespace error_handling {

ProgramResult::ProgramResult(ResultType type, const std::string info) 
    : result_type_(type), info_(info) {}

bool ProgramResult::IsOk()
{
    if (result_type_ == ResultType::kOk) {
      return true;
    }
    return false;
}

std::string ProgramResult::GetResultInformation() {
    return info_;
}

} // namespace error_handling