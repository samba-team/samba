/*
 * Copyright (c) 2016 - 2017 Kungliga Tekniska Högskolan
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

#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif

#if defined(ENABLE_PTHREAD_SUPPORT) && defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include <errno.h>

#include "roken.h"
#include "getauxval.h"

int rk_injected_auxv = 0; /* shared with issuid() for testing */
static int has_proc_auxv = 1;
static int proc_auxv_ret = 0;

#if defined(ENABLE_PTHREAD_SUPPORT) && defined(HAVE_PTHREAD_H)
pthread_once_t readprocauxv_once = PTHREAD_ONCE_INIT;
#endif

/*
 * There's no standard maximum.
 *
 * At the time of this writing we observe some 20 or so auxv entries.
 * If eventually that grows much larger then rk_getprocaux*() will see a
 * truncated auxv.
 */
#define MAX_AUXV_COUNT 128
static auxv_t auxv[MAX_AUXV_COUNT];

static void
do_readprocauxv(void)
{
    char *p = (void *)auxv;
    ssize_t bytes = 0;
    size_t sz = sizeof(auxv) - sizeof(auxv[0]); /* leave terminator */
    int save_errno = errno;
    int fd;

    errno = 0;
    memset(auxv, 0, sizeof(auxv)); /* terminates our copy */
    if ((fd = open("/proc/self/auxv", O_RDONLY)) == -1) {
        if (errno == ENOENT)
            has_proc_auxv = 0;
        goto out;
    }

    do {
        if ((bytes = read(fd, p, sz)) > 0) {
            sz -= bytes;
            p += bytes;
        }
    } while (sz && ((bytes == -1 && errno == EINTR) || bytes > 0));

out:
    proc_auxv_ret = errno;
    if (fd != -1)
        (void) close(fd);
    if (sz == 0 && bytes > 0)
        warnx("/proc/self/auxv has more entries than expected");
    errno = save_errno;
    return;
}

static int
readprocauxv(void)
{
#if defined(ENABLE_PTHREAD_SUPPORT) && defined(HAVE_PTHREAD_H)
    pthread_once(&readprocauxv_once, do_readprocauxv);
#else
    do_readprocauxv();
#endif
    return proc_auxv_ret;
}

/**
 * Looks up an auxv entry in /proc/self/auxv.  Preserves errno.
 *
 * @return a pointer to an auxv_t if found, else NULL.
 */
ROKEN_LIB_FUNCTION const auxv_t * ROKEN_LIB_CALL
rk_getauxv(unsigned long type)
{
    auxv_t *a;

    if (!has_proc_auxv || type > INT_MAX)
        return NULL;

    if (readprocauxv() != 0)
        return NULL;

    for (a = auxv; a - auxv < MAX_AUXV_COUNT; a++) {
        if ((int)a->a_type == (int)type)
            return a;
        if (a->a_type == 0 && a->a_un.a_val == 0)
            break;
    }
    return NULL;
}

#ifdef HAVE_GETAUXVAL
static unsigned long
rk_getprocauxval(unsigned long type)
{
    const auxv_t *a = rk_getauxv(type);

    if (a == NULL) {
        errno = ENOENT;
        return 0;
    }
    return a->a_un.a_val;
}
#endif

/**
 * Like the nearly-standard getauxval().  If the auxval is not found
 * returns zero and always sets errno to ENOENT.  Otherwise if auxval is
 * found it leaves errno as it was, even if the value is zero.
 *
 * @return The value of the ELF auxiliary value for the given type, or
 * zero and sets errno to ENOENT.
 */
ROKEN_LIB_FUNCTION unsigned long ROKEN_LIB_CALL
rk_getauxval(unsigned long type)
{
#ifdef HAVE_GETAUXVAL
#ifdef GETAUXVAL_SETS_ERRNO
    if (rk_injected_auxv)
        return rk_getprocauxval(type);
    return getauxval(type);
#else
    unsigned long ret;
    unsigned long ret2;
    static int getauxval_sets_errno = -1;
    const auxv_t *a;
    int save_errno = errno;

    if (rk_injected_auxv)
        return rk_getprocauxval(type);

    errno = 0;
    ret = getauxval(type);
    if (ret != 0 || errno == ENOENT || getauxval_sets_errno == 1) {
        if (ret != 0)
            errno = save_errno;
        else if (getauxval_sets_errno > 0 && errno == 0)
            errno = save_errno;
        return ret;
    }

    if (getauxval_sets_errno == 0) {
        errno = save_errno;
	a = rk_getauxv(type);
	if (a == NULL) {
            errno = ENOENT;
            return 0;
        }
        return a->a_un.a_val;
    }

    /*
     * We've called getauxval() and it returned 0, but we don't know if
     * getauxval() sets errno = ENOENT when entries are not found.
     *
     * Attempt to detect whether getauxval() sets errno = ENOENT by
     * calling it with what should be a bogus type.
     */

    errno = 0;
    ret2 = getauxval(~type);
    if (ret2 == 0 && errno == ENOENT) {
        getauxval_sets_errno = 1;
        errno = save_errno;
        return ret;
    }

    getauxval_sets_errno = 0;
    errno = save_errno;
    if ((a = rk_getauxv(type)) == NULL) {
        errno = ENOENT;
        return 0;
    }
    return a->a_un.a_val;
#endif
#else
    const auxv_t *a;

    if ((a = rk_getauxv(type)) == NULL) {
        errno = ENOENT;
        return 0;
    }
    return a->a_un.a_val;
#endif
}

/**
 * *Internal* function for testing by injecting or overwriting an ELF
 * auxiliary vector entry.
 *
 * @return zero on success or ENOSPC if there are too many ELF auxiliary
 * entries.
 */
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_injectauxv(auxv_t *e)
{
    size_t i;
    int ret;

    /*
     * This function is racy, but as an internal function never meant to
     * be called in a threaded program, we don't care.
     */

    if ((ret = readprocauxv()) != 0)
        return ret;

    rk_injected_auxv = 1;
    for (i = 0; i < MAX_AUXV_COUNT - 1 && auxv[i].a_type != 0; i++) {
        /* e->a_type == 0 -> truncate auxv, delete all entries */
        if (auxv[i].a_type == e->a_type || e->a_type == 0)
            break;
    }
    if (i == MAX_AUXV_COUNT - 1)
        return ENOSPC;
    auxv[i] = e[0];
    return 0;
}
