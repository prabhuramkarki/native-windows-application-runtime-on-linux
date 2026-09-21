#include <windows.h>
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {
    MessageBoxA(NULL, "hello", "fixture", MB_OK);
    return 0;
}
