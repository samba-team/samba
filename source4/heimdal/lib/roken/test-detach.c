/***********************************************************************
 * Copyright (c) 2015, Cryptonector LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **********************************************************************/

#include <config.h>

#include <sys/types.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#ifdef WIN32
#include <process.h>
#ifdef getpid
#undef getpid
#endif
#define getpid _getpid
#else
#include <unistd.h>
#endif
#include "roken.h"

int main(int argc, char **argv)
{
/*
 * XXXrcd: let's see how much further the tests get when we disable this
 *         on Windows.
 */
#ifndef WIN32
    char *ends;
    long n;
    int fd = -1;
    pid_t parent = getpid();
    pid_t child;

    if (argc == 2 && strcmp(argv[1], "--reexec") != 0)
        errx(1, "Usage: test-detach [--reexec] [--daemon-child FD]");
    if (argc == 3 || argc == 4) {
        parent = getppid();
        errno = 0;
        n = strtol(argv[2], &ends, 10);
        fd = n;
        if (errno != 0)
	    err(1, "Usage: test-detach [--daemon-child fd]");
        if (n < 0 || ends == NULL || *ends != '\0' || n != fd)
	    errx(1, "Usage: test-detach [--daemon-child fd]");
    } else {
        if (argc == 2)
            /* Make sure we re-exec on the child-side of fork() (not WIN32) */
            putenv("ROKEN_DETACH_USE_EXEC=1");
	fd = roken_detach_prep(argc, argv, "--daemon-child");
        if (fd == -1)
            errx(1, "bad");
    }
    if (parent == getpid())
        errx(1, "detach prep failed");
    child = getpid();
    roken_detach_finish(NULL, fd);
    if (child != getpid())
        errx(1, "detach finish failed");
    /*
     * These printfs will not appear: stderr will have been replaced
     * with /dev/null.
     */
    fprintf(stderr, "Now should be the child: %ld, wrote to parent\n", (long)getpid());
    sleep(5);
    fprintf(stderr, "Daemon child done\n");
    return 0;
#else
    return 0;
#endif
}
