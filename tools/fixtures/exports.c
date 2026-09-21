#include <windows.h>
__declspec(dllexport) int add(int a, int b) { return a + b; }
__declspec(dllexport) int mul(int a, int b) { return a * b; }
BOOL WINAPI DllMain(HINSTANCE i, DWORD reason, LPVOID reserved) { return TRUE; }
