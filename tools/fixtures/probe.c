/* Console fixture for the sandbox escape tests (Phase 5A): attempts exactly ONE action and reports it.
 *   probe read <path>          open <path> and read 1 byte
 *   probe write <path>         create/truncate <path> and write "escape"
 *   probe list <path>          list the directory <path>; prints each entry name on its own line after the result
 *   probe connect <ip> <port>  winsock TCP connect, 2 s timeout
 *   probe status               print the Seccomp and NoNewPrivs lines of the Wine process's /proc/self/status
 *   probe readmem              start a second probe (`probe wait`) and ReadProcessMemory its image header (found
 *                              through its PEB): wineserver reads another process's memory
 *   probe writemem             start a second probe, VirtualAllocEx a page in it, WriteProcessMemory a pattern and
 *                              ReadProcessMemory it back: wineserver writes another process's memory
 *   probe threadctx            Set/GetThreadContext of a suspended thread: an integer register (CONTEXT_INTEGER)
 *   probe dbgregs              Set/GetThreadContext of a suspended thread: a hardware breakpoint (Dr0/Dr7)
 *   probe wait                 sleep 30 s (the target of procmem)
 * <path> is any Windows path, including Wine's NT unix paths (\\?\unix\<abs host path>, see docs/SECURITY.md).
 * Prints one result line, `<MODE>-OK ...` or `<MODE>-FAILED <why>`, and exits 0 if the action SUCCEEDED, 1 if it
 * FAILED. Usage errors exit 2. Plain Win32 only. */
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
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

static DWORD WINAPI parked(void *arg) {
    (void)arg;
    for (;;) Sleep(1000);
    return 0;
}

/* A suspended thread whose context `set` changes and `get` then reads back through `check`. */
static int context_round_trip(const char *mode, DWORD flags, void (*set)(CONTEXT *), int (*check)(const CONTEXT *)) {
    CONTEXT c;
    HANDLE t = CreateThread(NULL, 0, parked, NULL, CREATE_SUSPENDED, NULL);
    if (!t) return failed(mode, "CreateThread", GetLastError());
    memset(&c, 0, sizeof c);
    c.ContextFlags = flags;
    if (!GetThreadContext(t, &c)) return failed(mode, "GetThreadContext", GetLastError());
    set(&c);
    c.ContextFlags = flags;
    if (!SetThreadContext(t, &c)) return failed(mode, "SetThreadContext", GetLastError());
    memset(&c, 0, sizeof c);
    c.ContextFlags = flags;
    if (!GetThreadContext(t, &c)) return failed(mode, "GetThreadContext again", GetLastError());
    if (!check(&c)) return failed(mode, "the context did not keep the new value", 0);
    TerminateThread(t, 0);
    CloseHandle(t);
    return ok(mode, "context set and read back");
}

#ifdef _WIN64
#define REG Rbx
#define DR_ADDR ((DWORD64)(ULONG_PTR)&parked)
#else
#define REG Ebx
#define DR_ADDR ((DWORD)(ULONG_PTR)&parked)
#endif
static void set_reg(CONTEXT *c) { c->REG = 0x1234567; }
static int check_reg(const CONTEXT *c) { return c->REG == 0x1234567; }
static void set_dr(CONTEXT *c) { c->Dr0 = DR_ADDR; c->Dr7 = 1; }
static int check_dr(const CONTEXT *c) { return c->Dr0 == DR_ADDR && (c->Dr7 & 1); }

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
    if (strcmp(mode, "status") == 0 && argc == 2) {
        char buf[4096], *line;
        DWORD n = 0;
        HANDLE f = CreateFileA("\\\\?\\unix\\proc\\self\\status", GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) return failed("STATUS", "open", GetLastError());
        BOOL r = ReadFile(f, buf, sizeof buf - 1, &n, NULL);
        CloseHandle(f);
        if (!r) return failed("STATUS", "read", GetLastError());
        buf[n] = 0;
        ok("STATUS", "lines follow");
        for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n"))
            if (!strncmp(line, "Seccomp:", 8) || !strncmp(line, "NoNewPrivs:", 11)) printf("%s\n", line);
        return 0;
    }
    if (strcmp(mode, "wait") == 0 && argc == 2) {
        Sleep(30000);
        return 0;
    }
    if ((strcmp(mode, "readmem") == 0 || strcmp(mode, "writemem") == 0) && argc == 2) {
        const char *m = mode[0] == 'r' ? "READMEM" : "WRITEMEM";
        char self[MAX_PATH], cmd[MAX_PATH + 16], back[16] = {0};
        const char pattern[16] = "cross-process!!";
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        PROCESS_BASIC_INFORMATION pbi;
        PEB peb;
        SIZE_T n = 0;
        int rc;
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        GetModuleFileNameA(NULL, self, sizeof self);
        snprintf(cmd, sizeof cmd, "\"%s\" wait", self);
        if (!CreateProcessA(self, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
            return failed(m, "CreateProcess", GetLastError());
        Sleep(500);
        if (m[0] == 'R') {
            void *page = NULL;
            if (NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof pbi, NULL))
                rc = failed(m, "NtQueryInformationProcess", 0);
            else if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof peb, &n))
                rc = failed(m, "ReadProcessMemory of the PEB", GetLastError());
            else if (!(page = peb.Reserved3[1]) || !ReadProcessMemory(pi.hProcess, page, back, 2, &n) || n != 2)
                rc = failed(m, "ReadProcessMemory of the image", GetLastError());
            else if (back[0] != 'M' || back[1] != 'Z') rc = failed(m, "the image does not start with MZ", 0);
            else rc = ok(m, "read the other process's image header");
        } else {
            void *page = VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!page) rc = failed(m, "VirtualAllocEx", GetLastError());
            else if (!WriteProcessMemory(pi.hProcess, page, pattern, sizeof pattern, &n) || n != sizeof pattern)
                rc = failed(m, "WriteProcessMemory", GetLastError());
            else if (!ReadProcessMemory(pi.hProcess, page, back, sizeof back, &n) || n != sizeof back)
                rc = failed(m, "ReadProcessMemory", GetLastError());
            else if (memcmp(back, pattern, sizeof back)) rc = failed(m, "the pattern did not come back", 0);
            else rc = ok(m, "written and read back");
        }
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 5000);
        return rc;
    }
    if (strcmp(mode, "threadctx") == 0 && argc == 2)
        return context_round_trip("THREADCTX", CONTEXT_INTEGER, set_reg, check_reg);
    if (strcmp(mode, "dbgregs") == 0 && argc == 2)
        return context_round_trip("DBGREGS", CONTEXT_DEBUG_REGISTERS, set_dr, check_dr);
    printf("usage: probe read <path> | write <path> | list <path> | connect <ip> <port> | status | readmem | writemem | "
           "threadctx | dbgregs | wait\n");
    return 2;
}
