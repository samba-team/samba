/*
 * Copyright (c) 1998 - 2017 Kungliga Tekniska Högskolan
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

#include <errno.h>

#include "roken.h"
#include "getauxval.h"

extern int rk_injected_auxv;

/**
 * Returns non-zero if the caller's process started as set-uid or
 * set-gid (and therefore the environment cannot be trusted).
 *
 * As much as possible this implements the same functionality and
 * semantics as OpenBSD's issetugid() (as opposed to FreeBSD's).
 *
 * Preserves errno.
 *
 * @return Non-zero if the environment is not trusted.
 */
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
issuid(void)
{
#ifdef WIN32
    return 0; /* No set-id programs or anything like it on Windows */
#else
    /*
     * We want to use issetugid(), but issetugid() is not the same on
     * all OSes.
     *
     * On OpenBSD (where issetugid() originated), Illumos derivatives,
     * and Solaris, issetugid() returns true IFF the program exec()ed
     * was set-uid or set-gid.
     *
     * FreeBSD departed from OpenBSD's issetugid() semantics, and other
     * BSDs (NetBSD, DragonFly) and OS X adopted FreeBSD's.
     *
     * FreeBSDs' issetugid() returns true if the program exec()ed was
     * set-uid or set-gid, or if the process has switched UIDs/GIDs or
     * otherwise changed privileges or is a descendant of such a process
     * and has not exec()ed since.
     *
     * The FreeBSD/NetBSD issetugid() does us no good because we _want_
     * to trust the environment when the process started life as
     * non-set-uid root (or otherwise privileged).  There's nothing
     * about _dropping_ privileges (without having gained them first)
     * that taints the environment.  It's not like calling system(),
     * say, might change the environment of the caller.
     *
     * We want OpenBSD's issetugid() semantics.
     *
     * Linux, meanwhile, has no issetugid() (at least glibc doesn't
     * anyways) but has an equivalent: getauxval(AT_SECURE).
     *
     * To be really specific: we want getauxval(AT_SECURE) semantics
     * because there may be ways in which a process might gain privilege
     * at exec time other than by exec'ing a set-id program.
     *
     * Where we use getauxval(), we really use our getauxval(), the one
     * that isn't broken the way glibc's used to be.  Our getauxval()
     * also works on more systems than actually provide one.
     *
     * In order to avoid FreeBSD issetugid() semantics, where available,
     * we use the ELF auxilliary vector to implement OpenBSD semantics
     * before finally falling back on issetugid().
     *
     * All of this is as of April 2017, and might become stale in the
     * future.
     */
    static int we_are_suid = -1; /* Memoize; -1 == dunno */
    int save_errno = errno;
#if defined(AT_EUID) && defined(AT_UID) && defined(AT_EGID) && defined(AT_GID)
    int seen = 0;
#endif

    if (we_are_suid >= 0 && !rk_injected_auxv)
        return we_are_suid;

#ifdef AT_SECURE
    errno = 0;
    if (rk_getauxval(AT_SECURE) != 0) {
        errno = save_errno;
        return we_are_suid = 1;
    } else if (errno == 0) {
        errno = save_errno;
        return we_are_suid = 0;
    }
    /* errno == ENOENT; AT_SECURE not found; fall through */
#endif

#if defined(AT_EUID) && defined(AT_UID) && defined(AT_EGID) && defined(AT_GID)
    {
        unsigned long euid;
        unsigned long uid;

        errno = 0;
        euid = rk_getauxval(AT_EUID);
        if (errno == 0)
            seen |= 1;
        errno = 0;
        uid = rk_getauxval(AT_UID);
        if (errno == 0)
            seen |= 2;
        if (euid != uid) {
            errno = save_errno;
            return we_are_suid = 1;
        }
    }
    /* Check GIDs */
    {
        unsigned long egid;
        unsigned long gid;

        errno = 0;
        egid = rk_getauxval(AT_EGID);
        if (errno == 0)
            seen |= 4;
        errno = 0;
        gid = rk_getauxval(AT_GID);
        if (errno == 0)
            seen |= 8;
        if (egid != gid) {
            errno = save_errno;
            return we_are_suid = 1;
        }
    }
    errno = save_errno;
    if (seen == 15)
        return we_are_suid = 0;
#endif

#if defined(HAVE_ISSETUGID)
    /* If issetugid() == 0 then we're definitely OK then */
    if (issetugid() == 0)
        return we_are_suid = 0;
    /* issetugid() == 1 might have been a false positive; fall through */
#endif

#ifdef AT_EXECFN
    /*
     * There's an auxval by which to find the path of the program this
     * process exec'ed.
     *
     * We can stat() it.  If the program did a chroot() and the chroot
     * has a program with the same path but not set-uid/set-gid, of
     * course, we lose here.  But a) that's a bit of a stretch, b)
     * there's not much more we can do here.
     *
     * Also, this is technically a TOCTOU race, though for set-id
     * programs this is exceedingly unlikely to be an actual TOCTOU
     * race.
     *
     * TODO We should really make sure that none of the path components of the
     *      execpath are symlinks.
     */
    {
        unsigned long p = rk_getauxval(AT_EXECPATH);
        struct stat st;
        
        if (p != 0 && *(const char *)p == '/' &&
            stat((const char *)p, &st) == 0) {
            if ((st.st_mode & S_ISUID) || (st.st_mode & S_ISGID)) {
                errno = save_errno;
                return we_are_suid = 1;
            }
            errno = save_errno;
            return we_are_suid = 0;
        }
    }
    /* Fall through */
#endif

#if defined(HAVE_ISSETUGID)
    errno = save_errno;
    return we_are_suid = 1;
#else
    /*
     * Paranoia: for extra safety we ought to default to returning 1.
     *
     * But who knows what that might break where users link statically
     * (so no auxv), say.
     *
     * We'll check the actual real and effective IDs (as opposed to the
     * ones at main() start time.
     *
     * For now we stick to returning zero by default.  We've been rather
     * heroic above trying to find out if we're suid, and we're running
     * on a rather old or uncool OS if we've gotten here.
     */

#if defined(HAVE_GETRESUID)
    /*
     * If r/e/suid are all the same then chances are very good we did
     * not start as set-uid.  Though this could be a login program that
     * started out as privileged and is calling Heimdal "as the user".
     *
     * Again, such a program would have to be statically linked to get
     * here.
     */
    {
        uid_t r, e, s;
        if (getresuid(&r, &e, &s) == 0) {
            if (r != e || r != s) {
                errno = save_errno;
                return we_are_suid = 1;
            }
        }
    }
#endif
#if defined(HAVE_GETRESGID)
    {
        gid_t r, e, s;
        if (getresgid(&r, &e, &s) == 0) {
            if (r != e || r != s) {
                errno = save_errno;
                return we_are_suid = 1;
            }
        }
    }
#endif
#if defined(HAVE_GETRESUID) && defined(HAVE_GETRESGID)
    errno = save_errno;
    return we_are_suid = 0;

#else /* avoid compiler warnings about dead code */

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
    if (getuid() != geteuid())
	return we_are_suid = 1;
#endif
#if defined(HAVE_GETGID) && defined(HAVE_GETEGID)
    if (getgid() != getegid())
	return we_are_suid = 1;
#endif

    errno = save_errno;
    return we_are_suid = 0;
#endif /* !defined(HAVE_GETRESUID) || !defined(HAVE_GETRESGID) */
#endif /* !defined(HAVE_ISSETUGID) */
#endif /* WIN32 */
}
