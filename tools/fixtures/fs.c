/* Console fixture for the isolation tests (Phase 2 e2e): looks at the world from inside a Wine prefix.
 *   fs write <text>   writes <text> to C:\runtime-test.txt; exit 0
 *   fs read           prints the content of C:\runtime-test.txt; exit 0, or prints MISSING and exits 3
 *   fs stat <path>    prints EXISTS (exit 0) or MISSING (exit 3) for any Windows path
 *   fs env <NAME>     prints the value of an environment variable, or UNSET; exit 0
 *   fs cwd            prints the current directory; exit 0
 * Usage errors exit 2. Plain Win32 only. */
#include <windows.h>
#include <string.h>

#define TEST_FILE "C:\\runtime-test.txt"

static void out(const char *s, DWORD n) {
    DWORD done;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, n, &done, NULL);
}

static void say(const char *s) {
    out(s, (DWORD)strlen(s));
    out("\n", 1);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    if (strcmp(mode, "write") == 0 && argc == 3) {
        HANDLE f = CreateFileA(TEST_FILE, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD done = 0;
        if (f == INVALID_HANDLE_VALUE) {
            say("WRITE-FAILED");
            return 1;
        }
        BOOL ok = WriteFile(f, argv[2], (DWORD)strlen(argv[2]), &done, NULL);
        CloseHandle(f);
        if (!ok || done != strlen(argv[2])) {
            say("WRITE-FAILED");
            return 1;
        }
        return 0;
    }
    if (strcmp(mode, "read") == 0 && argc == 2) {
        char buf[4096];
        DWORD n = 0;
        HANDLE f = CreateFileA(TEST_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) {
            say("MISSING");
            return 3;
        }
        if (!ReadFile(f, buf, sizeof buf, &n, NULL)) n = 0;
        CloseHandle(f);
        out(buf, n);
        out("\n", 1);
        return 0;
    }
    if (strcmp(mode, "stat") == 0 && argc == 3) {
        if (GetFileAttributesA(argv[2]) == INVALID_FILE_ATTRIBUTES) {
            say("MISSING");
            return 3;
        }
        say("EXISTS");
        return 0;
    }
    if (strcmp(mode, "env") == 0 && argc == 3) {
        char buf[32768];
        DWORD n = GetEnvironmentVariableA(argv[2], buf, sizeof buf);
        if (n == 0 || n >= sizeof buf) say("UNSET");
        else say(buf);
        return 0;
    }
    if (strcmp(mode, "cwd") == 0 && argc == 2) {
        char buf[MAX_PATH * 4];
        DWORD n = GetCurrentDirectoryA(sizeof buf, buf);
        if (n == 0 || n >= sizeof buf) return 1;
        say(buf);
        return 0;
    }
    say("usage: fs write <text> | read | stat <path> | env <NAME> | cwd");
    return 2;
}
