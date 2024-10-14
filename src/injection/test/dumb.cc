#include <stdio.h>
#include <windows.h>

int main() {
  
  DWORD pid = GetCurrentProcessId();
  printf("PID: %u\n", pid);
  while(true) {
    printf("Press a key to continue...");
    getchar();
  }

  return 0;
}