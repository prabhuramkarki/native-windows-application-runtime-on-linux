/* Console fixture for the sandbox escape tests (Phase 5A): attempts exactly ONE action and reports it.
 *   probe read <path>          open <path> and read 1 byte
 *   probe write <path>         create/truncate <path> and write "escape"
 *   probe list <path>          list the directory <path>; prints each entry name on its own line after the result
 *   probe connect <ip> <port>  winsock TCP connect, 2 s timeout
 * <path> is any Windows path, including Wine's NT unix paths (\\?\unix\<abs host path>, see docs/SECURITY.md).
 * Prints one result line, `<MODE>-OK ...` or `<MODE>-FAILED <why>`, and exits 0 if the action SUCCEEDED, 1 if it
 * FAILED. Usage errors exit 2. Plain Win32 only. */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int ok(const char *mode, const char *detail) {
    printf("%s-OK %s\n", mode, detail);
    return 0;
}

static int failed(const char *mode, const char *what, unsigned long err) {
    printf("%s-FAILED %s error %lu\n", mode, what, err);
    return 1;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    setvbuf(stdout, NULL, _IONBF, 0);
    if (strcmp(mode, "read") == 0 && argc == 3) {
        char b = 0, detail[32];
        DWORD n = 0;
        HANDLE f = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) return failed("READ", "open", GetLastError());
        BOOL r = ReadFile(f, &b, 1, &n, NULL);
        DWORD err = GetLastError();
        CloseHandle(f);
        if (!r || n != 1) return failed("READ", "read", r ? 0 : err);
        snprintf(detail, sizeof detail, "first byte %d", (int)(unsigned char)b);
        return ok("READ", detail);
    }
    if (strcmp(mode, "write") == 0 && argc == 3) {
        DWORD n = 0;
        HANDLE f = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) return failed("WRITE", "create", GetLastError());
        BOOL r = WriteFile(f, "escape", 6, &n, NULL);
        DWORD err = GetLastError();
        CloseHandle(f);
        if (!r || n != 6) return failed("WRITE", "write", r ? 0 : err);
        return ok("WRITE", "6 bytes");
    }
    if (strcmp(mode, "list") == 0 && argc == 3) {
        char pattern[MAX_PATH * 4];
        WIN32_FIND_DATAA d;
        snprintf(pattern, sizeof pattern, "%s\\*", argv[2]);
        HANDLE h = FindFirstFileA(pattern, &d);
        if (h == INVALID_HANDLE_VALUE) return failed("LIST", "find", GetLastError());
        ok("LIST", "entries follow");
        do {
            if (strcmp(d.cFileName, ".") && strcmp(d.cFileName, "..")) printf("%s\n", d.cFileName);
        } while (FindNextFileA(h, &d));
        FindClose(h);
        return 0;
    }
    if (strcmp(mode, "connect") == 0 && argc == 4) {
        WSADATA wsa;
        struct sockaddr_in a;
        u_long nb = 1;
        fd_set w, e;
        struct timeval tv = {2, 0};
        int soerr = 0, len = sizeof soerr;
        if (WSAStartup(MAKEWORD(2, 2), &wsa)) return failed("CONNECT", "WSAStartup", 0);
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return failed("CONNECT", "socket", WSAGetLastError());
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons((u_short)atoi(argv[3]));
        a.sin_addr.s_addr = inet_addr(argv[2]);
        ioctlsocket(s, FIONBIO, &nb);
        if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) return ok("CONNECT", "at once");
        if (WSAGetLastError() != WSAEWOULDBLOCK) return failed("CONNECT", "connect", WSAGetLastError());
        FD_ZERO(&w);
        FD_ZERO(&e);
        FD_SET(s, &w);
        FD_SET(s, &e);
        int r = select(0, NULL, &w, &e, &tv);
        if (r == 0) return failed("CONNECT", "timeout", 0);
        if (r < 0) return failed("CONNECT", "select", WSAGetLastError());
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len);
        if (FD_ISSET(s, &e) || soerr) return failed("CONNECT", "connect", (unsigned long)soerr);
        closesocket(s);
        return ok("CONNECT", "connected");
    }
    printf("usage: probe read <path> | write <path> | list <path> | connect <ip> <port>\n");
    return 2;
}
