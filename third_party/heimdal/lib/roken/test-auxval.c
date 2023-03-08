/*
 * Copyright (c) 1999 - 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "roken.h"
#include "getauxval.h"

static void
check_secure_getenv(char **env)
{
    size_t i;
    char *v, *p;

    for (i = 0; env[i] != NULL; i++) {
        if ((v = strdup(env[i])) == NULL)
            err(1, "could not allocate copy of %s", env[i]);
        if ((p = strchr(v, '='))) {
            *p = '\0';
            if (issuid() && rk_secure_getenv(v) != NULL)
                err(1, "rk_secure_getenv() returned non-NULL when issuid()!");
            if (!issuid() && rk_secure_getenv(v) == NULL)
                err(1, "rk_secure_getenv() returned NULL when !issuid()");
        }
        free(v);
    }
}

static void
inject_suid(int suid)
{
#if defined(AT_SECURE) || (defined(AT_EUID) && defined(AT_RUID) && defined(AT_EGID) && defined(AT_RGID))
    auxv_t e;
#ifdef AT_SECURE
    unsigned long secure = suid ? 1 : 0;
#endif
#if defined(AT_EUID) && defined(AT_RUID) && defined(AT_EGID) && defined(AT_RGID)
    unsigned long eid = suid ? 0 : 1000;

    /* Inject real UID and GID */
    e.a_un.a_val = 1000;
    e.a_type = AT_UID;
    if ((errno = rk_injectauxv(&e)) != 0)
        err(1, "rk_injectauxv(AT_RUID) failed");
    e.a_type = AT_GID;
    if ((errno = rk_injectauxv(&e)) != 0)
        err(1, "rk_injectauxv(AT_RGID) failed");

    /* Inject effective UID and GID */
    e.a_un.a_val = eid;
    e.a_type = AT_EUID;
    if ((errno = rk_injectauxv(&e)) != 0)
        err(1, "rk_injectauxv(AT_EUID) failed");
    e.a_type = AT_EGID;
    if ((errno = rk_injectauxv(&e)) != 0)
        err(1, "rk_injectauxv(AT_RGID) failed");
#endif

#ifdef AT_SECURE
    e.a_un.a_val = secure;
    e.a_type = AT_SECURE;
    if ((errno = rk_injectauxv(&e)) != 0)
        err(1, "rk_injectauxv(AT_SECURE) failed");
#endif

    return;
#else
    warnx("No ELF auxv types to inject");
#endif
}

static
unsigned long
getprocauxval(unsigned long type)
{
    const auxv_t *e;

    if ((e = rk_getauxv(type)) == NULL) {
        errno = ENOENT;
        return 0;
    }
    return e->a_un.a_val;
}

/* returns 1 if auxval type is handled specially by libc */
static int
is_special_auxv_p(long type)
{
#ifdef AT_HWCAP
    if (type == AT_HWCAP)
	return 1;
#endif
#ifdef AT_HWCAP2
    if (type == AT_HWCAP2)
	return 1;
#endif

    return 0;
}

int
main(int argc, char **argv, char **env)
{
    unsigned long max_t = 0;
    unsigned long a[2];
    unsigned long v;
    ssize_t bytes;
    int am_suid = issuid();
    int fd;

    (void) argc;
    (void) argv;

    if (getuid() == geteuid() && getgid() == getegid()) {
        if (issuid())
            errx(1, "issuid() false positive?  Check AT_SECURE?");
    } else {
        if (!issuid())
            errx(1, "issuid() did not detect set-uid-ness!");
    }

    if ((fd = open("/proc/self/auxv", O_RDONLY)) == -1)
        return 0;

    /*
     * Check that for every ELF auxv entry in /proc/self/auxv we
     * find the correct answer from the rk_get*auxval() functions.
     */
    do {
        bytes = read(fd, a, sizeof(a));
        if (bytes != sizeof(a)) {
            if (bytes == -1)
                err(1, "Error reading from /proc/self/auxv");
            if (bytes == 0)
                warnx("Did not see terminator in /proc/self/auxv");
            else
                warnx("Partial entry in /proc/self/auxv or test interrupted");
            (void) close(fd);
            return 1;
        }
        if (a[0] > max_t)
            max_t = a[0];
        if (a[0] == 0) {
            if (a[1] != 0)
                warnx("AT_NULL with non-zero value %lu?!", a[1]);
            continue;
	} else if (is_special_auxv_p(a[0]))
	    continue;

        errno = EACCES;

        if ((v = rk_getauxval(a[0])) != a[1])
            errx(1, "rk_getauxval(%lu) should have been %lu, was %lu",
                 a[0], a[1], v);
        if (errno != EACCES)
            errx(1, "rk_getauxval(%lu) did not preserve errno", a[0]);

        if ((v = getprocauxval(a[0])) != a[1])
            errx(1, "rk_getauxval(%lu) should have been %lu, was %lu",
                 a[0], a[1], v);
        if (errno != EACCES)
            errx(1, "rk_getauxv(%lu) did not preserve errno", a[0]);

        printf("auxv type %lu -> %lu\n", a[0], a[1]);
    } while (a[0] != 0 || a[1] != 0);

    (void) close(fd);
    if (max_t == 0) {
        warnx("No entries in /proc/self/auxv or it is not available on this "
              "system or this program is linked statically; cannot test "
              "rk_getauxval()");
        return 0;
    }

    errno = EACCES;
    if ((v = rk_getauxval(max_t + 1)) != 0)
        errx(1, "rk_getauxval((max_type_seen = %lu) + 1) should have been "
             "0, was %lu", max_t, v);
    if (errno != ENOENT)
        errx(1, "rk_getauxval((max_type_seen = %lu) + 1) did not set "
             "errno = ENOENT!", max_t);

    errno = EACCES;
    if ((v = getprocauxval(max_t + 1)) != 0)
        errx(1, "rk_getauxv((max_type_seen = %lu) + 1) should have been "
             "0, was %lu", max_t, v);
    if (errno != ENOENT)
        errx(1, "rk_getauxv((max_type_seen = %lu) + 1) did not set "
             "errno = ENOENT!", max_t);

    check_secure_getenv(env);
    inject_suid(!am_suid);
    if ((am_suid && issuid()) || (!am_suid && !issuid()))
        errx(1, "rk_injectprocauxv() failed");
    check_secure_getenv(env);

    return 0;
}
