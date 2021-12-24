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

#ifndef RK_GETAUXVAL_H
#define RK_GETAUXVAL_H

#include <config.h>

#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif

#ifdef HAVE_SYS_EXEC_ELF_H
#include <sys/exec_elf.h>
#endif

#ifndef HAVE_AUXV_T
/*
 * Illumos defines auxv_t per the ABI standards, but all other OSes seem
 * to use { long; long; } instead, depends on sizeof(long) ==
 * sizeof(void *), and they do not define an auxv_t.
 *
 * sizeof(long) != sizeof(void *) on WIN64, but Windows doesn't have
 * /proc/self/auxv anyways.  Just in case we use uintptr_t.
 */
typedef struct rk_auxv {
    uintptr_t a_type;
    union {
        uintptr_t a_val;
        uintptr_t a_ptr; /* This would be void * */
        uintptr_t a_fnc; /* This would be void (*)(void) */
    } a_un;
} auxv_t;
#endif

#ifdef __linux__
/*
 * Older glibcs have no <sys/auxv.h>, but do nonetheless have an ELF
 * auxiliary vector, and with the values for these types that appear in
 * <sys/auxv.h> in later versions.
 *
 * Note that Travis-CI still uses Ubuntu 14 for its Linux build
 * environment, which has such an older glibc version.
 */
#ifndef AT_UID
#define AT_UID 11
#endif
#ifndef AT_EUID
#define AT_EUID 12
#endif
#ifndef AT_GID
#define AT_GID 13
#endif
#ifndef AT_EGID
#define AT_EGID 14
#endif
#ifndef AT_SECURE
#define AT_SECURE 23
#endif
#endif

#if __sun
#if !defined(AT_UID) && defined(AT_SUN_RUID)
#define AT_UID AT_SUN_RUID
#endif
#if !defined(AT_EUID) && defined(AT_SUN_UID)
#define AT_EUID AT_SUN_UID
#endif
#if !defined(AT_GID) && defined(AT_SUN_RGID)
#define AT_GID AT_SUN_RGID
#endif
#if !defined(AT_EGID) && defined(AT_SUN_GID)
#define AT_EGID AT_SUN_GID
#endif
#endif /* __sun */

/* NetBSD calls AT_UID AT_RUID.  Everyone else calls it AT_UID. */
#if defined(AT_EUID) && defined(AT_RUID) && !defined(AT_UID)
#define AT_UID AT_RUID
#endif
#if defined(AT_EGID) && defined(AT_RGID) && !defined(AT_GID)
#define AT_GID AT_RGID
#endif

#if defined(AT_EUID) && defined(AT_UID) && !defined(AT_RUID)
#define AT_RUID AT_UID
#endif
#if defined(AT_EGID) && defined(AT_GID) && !defined(AT_RGID)
#define AT_RGID AT_GID
#endif


/*
 * There are three different names for the type whose value is the path
 * to the executable being run by the process.
 */
#if defined(AT_EXECFN) && !defined(AT_EXECPATH)
#define AT_EXECPATH AT_EXECFN
#endif
#if defined(AT_EXECFN) && !defined(AT_SUN_EXECNAME)
#define AT_SUN_EXECNAME AT_EXECFN
#endif
#if defined(AT_EXECPATH) && !defined(AT_EXECFN)
#define AT_EXECFN AT_EXECPATH
#endif
#if defined(AT_EXECPATH) && !defined(AT_SUN_EXECNAME)
#define AT_SUN_EXECNAME AT_EXECPATH
#endif
#if defined(AT_SUN_EXECNAME) && !defined(AT_EXECFN)
#define AT_EXECFN AT_SUN_EXECNAME
#endif
#if defined(AT_SUN_EXECNAME) && !defined(AT_EXECPATH)
#define AT_EXECPATH AT_SUN_EXECNAME
#endif

/* We need this for part of the getauxval() brokenness detection below */
#ifdef __GLIBC__
#ifdef __GLIBC_PREREQ
#define HAVE_GLIBC_API_VERSION_SUPPORT(maj, min) __GLIBC_PREREQ(maj, min)
#else
#define HAVE_GLIBC_API_VERSION_SUPPORT(maj, min) \
    ((__GLIBC << 16) + GLIBC_MINOR >= ((maj) << 16) + (min))
#endif

/*
 * Detect whether getauxval() is broken.
 *
 * Do change this check in order to manually test rk_getauxval() for
 * older glibcs.
 */
#if HAVE_GLIBC_API_VERSION_SUPPORT(2, 19)
#define GETAUXVAL_SETS_ERRNO
/* #else it's broken */
#endif
#endif

ROKEN_LIB_FUNCTION const auxv_t * ROKEN_LIB_CALL
    rk_getauxv(unsigned long type);

ROKEN_LIB_FUNCTION unsigned long ROKEN_LIB_CALL
    rk_getauxval(unsigned long);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
    rk_injectauxv(auxv_t *e);

#endif /* RK_GETAUXVAL_H */
