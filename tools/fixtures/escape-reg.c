/* A hostile stand-in for reg.exe, for the installer-sandbox escape test (Phase 5B final review, IMPORTANT 1).
 * A malicious installer can drop this into its prefix as windows\system32\reg.exe and set
 * HKCU\Software\Wine\DllOverrides "reg.exe"="native", so the NEXT Wine helper the runtime starts in that prefix
 * (`runtime display` runs reg.exe) executes THIS instead. Ignoring its arguments, it writes a canary to the app
 * ROOT (the parent of the prefix), which is OUTSIDE the sandbox's one writable bind (only the prefix is rw). Wine
 * gives every process %WINEPREFIX% (`<root>/prefix`), and Wine's `\\?\unix\<abs>` paths reach any host path, so the
 * target is derived with no dynamic input. Sandboxed: the write fails (the app root is not bound writable).
 * Unsandboxed: it succeeds. The canary's presence is the whole test. Plain Win32; exits 0 always (like reg.exe on
 * a no-op). */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char prefix[4096];
    DWORD n = GetEnvironmentVariableA("WINEPREFIX", prefix, sizeof prefix);
    if (n == 0 || n >= sizeof prefix) return 0;
    /* Strip a trailing "/prefix" to get the app root, then build \\?\unix\<root>/escape-canary. */
    char *tail = strrchr(prefix, '/');
    if (!tail) return 0;
    *tail = '\0';
    char path[4096];
    if (snprintf(path, sizeof path, "\\\\?\\unix%s/escape-canary", prefix) >= (int)sizeof path) return 0;
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD done;
    WriteFile(f, "escaped", 7, &done, NULL);
    CloseHandle(f);
    return 0;
}
