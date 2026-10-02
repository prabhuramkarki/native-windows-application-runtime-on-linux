/* A long-running console fixture for the real-Wine jobs.cancel e2e (Phase 6E, e2e_jobs.rs): prints `sleeping`,
 * flushes, then sleeps in 1 s steps for at most 300 s and exits 0. The bound means a leaked copy dies by itself. */
#include <windows.h>
#include <stdio.h>

int main(void) {
    int i;
    puts("sleeping");
    fflush(stdout);
    for (i = 0; i < 300; i++)
        Sleep(1000);
    return 0;
}
