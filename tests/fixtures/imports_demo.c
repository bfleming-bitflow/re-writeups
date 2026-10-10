/* Benign fixture that references a few interesting symbols for triage tests. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <dlfcn.h>
#endif

int main(void) {
#ifdef _WIN32
    /* Touch APIs that land in suspicion categories without doing anything hostile. */
    (void)GetTickCount();
    (void)IsDebuggerPresent();
    char path[MAX_PATH];
    GetTempPathA(sizeof path, path);
    HANDLE h = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
#else
    (void)getpid();
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (handle) dlclose(handle);
#endif
    puts("imports-demo");
    return 0;
}
