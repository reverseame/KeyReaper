// Compilar con: cl /EHsc /std:c++17 .\cifrar.cpp User32.lib

#include <Windows.h>
#include <iostream>

int main() {
    LPCTSTR message = "Hello, Windows API!";
    LPCTSTR caption = "pwnd";
    MessageBox(NULL, message, caption, MB_OK);
    return 0;
}
