#ifndef PROGRAMRESULT_H
#define PROGRAMRESULT_H

class ProgramResult {

 private:
  ResultType type;
  string info;

 public:
  ProgramResult(ResultType type, string info);
};

#endif
