/*
 * Firefly emulation shim (Phase A).
 *
 * LD_PRELOADed into an emulated firmware process so Firefly can observe what it
 * does at runtime without modifying the binary:
 *
 *   - command execution: system(), popen(), execve(), execl*() are logged, so a
 *     service that shells out with (possibly attacker-controlled) input shows up
 *     as a command-injection candidate;
 *   - file access: open()/fopen() targets are logged;
 *   - NVRAM: the firmadyne-style nvram_get/nvram_set/nvram_bufget family is
 *     stubbed so services that read configuration out of NVRAM don't die on
 *     startup inside the emulator.
 *
 * Observations are written as one line per event to the file named by
 * FIREFLY_SHIM_LOG (a path inside the writable tmpfs), prefixed by event type.
 * The shim never blocks the call; it logs and then forwards to the real libc
 * function. It must be cross-compiled for the target architecture; see the
 * Makefile in this directory.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Log one event. This MUST reach the real libc fopen via RTLD_NEXT, not the
 * fopen we interpose below: calling our own fopen here would recurse
 * (ff_log -> fopen -> ff_log -> ...) and blow the stack. A reentrancy guard
 * additionally keeps any interposed call made while logging from re-entering.
 */
static __thread int ff_in_log = 0;

static void ff_log(const char *kind, const char *value) {
    if (ff_in_log) return;
    const char *path = getenv("FIREFLY_SHIM_LOG");
    if (!path || !value) return;
    ff_in_log = 1;
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    if (real_fopen) {
        FILE *fh = real_fopen(path, "a");
        if (fh) {
            fprintf(fh, "%s\t%s\n", kind, value);
            fclose(fh);
        }
    }
    ff_in_log = 0;
}

int system(const char *command) {
    ff_log("CMD", command ? command : "(null)");
    int (*real)(const char *) = dlsym(RTLD_NEXT, "system");
    return real ? real(command) : -1;
}

FILE *popen(const char *command, const char *type) {
    ff_log("CMD", command ? command : "(null)");
    FILE *(*real)(const char *, const char *) = dlsym(RTLD_NEXT, "popen");
    return real ? real(command, type) : NULL;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    ff_log("EXEC", path ? path : "(null)");
    int (*real)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
    return real ? real(path, argv, envp) : -1;
}

int open(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);
    ff_log("OPEN", path ? path : "(null)");
    int (*real)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    return real ? real(path, flags, mode) : -1;
}

FILE *fopen(const char *path, const char *mode) {
    ff_log("OPEN", path ? path : "(null)");
    FILE *(*real)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    return real ? real(path, mode) : NULL;
}

/* --- firmadyne-style NVRAM stubs: just enough to keep services alive. --- */

char *nvram_get(const char *key) {
    ff_log("NVRAM_GET", key ? key : "(null)");
    return strdup("");
}

int nvram_set(const char *key, const char *value) {
    (void)value;
    ff_log("NVRAM_SET", key ? key : "(null)");
    return 0;
}

int nvram_bufget(int idx, const char *key, char *out, size_t len) {
    (void)idx;
    ff_log("NVRAM_GET", key ? key : "(null)");
    if (out && len) out[0] = '\0';
    return 0;
}
