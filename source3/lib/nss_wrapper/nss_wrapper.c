/*
 * Copyright (C) Stefan Metzmacher 2007 <metze@samba.org>
 *
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
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef _SAMBA_BUILD_

#define NSS_WRAPPER_NOT_REPLACE
#include "lib/replace/replace.h"
#include "system/passwd.h"
#include "system/filesys.h"

#else /* _SAMBA_BUILD_ */

#error nss_wrapper_only_supported_in_samba_yet

#endif

#ifndef _PUBLIC_
#define _PUBLIC_
#endif

/* LD_PRELOAD doesn't work yet, so REWRITE_CALLS is all we support
 * for now */
#define REWRITE_CALLS

#ifdef REWRITE_CALLS

#define real_getpwnam		getpwnam
#define real_getpwnam_r		getpwnam_r
#define real_getpwuid		getpwuid
#define real_getpwuid_r		getpwuid_r

#define real_setpwent		setpwent
#define real_getpwent		getpwent
#define real_getpwent_r		getpwent_r
#define real_endpwent		endpwent

/*
#define real_getgrlst		getgrlst
#define real_getgrlst_r		getgrlst_r
#define real_initgroups_dyn	initgroups_dyn
*/
#define real_initgroups		initgroups

#define real_getgrnam		getgrnam
#define real_getgrnam_r		getgrnam_r
#define real_getgrgid		getgrgid
#define real_getgrgid_r		getgrgid_r

#define real_setgrent		setgrent
#define real_getgrent		getgrent
#define real_getgrent_r		getgrent_r
#define real_endgrent		endgrent

#endif

/* user functions */
_PUBLIC_ struct passwd *nwrap_getpwnam(const char *name)
{
	return real_getpwnam(name);
}

_PUBLIC_ int nwrap_getpwnam_r(const char *name, struct passwd *pwbuf,
			      char *buf, size_t buflen, struct passwd **pwbufp)
{
	return real_getpwnam_r(name, pwbuf, buf, buflen, pwbufp);
}

_PUBLIC_ struct passwd *nwrap_getpwuid(uid_t uid)
{
	return real_getpwuid(uid);
}

_PUBLIC_ int nwrap_getpwuid_r(uid_t uid, struct passwd *pwbuf,
			      char *buf, size_t buflen, struct passwd **pwbufp)
{
	return real_getpwuid_r(uid, pwbuf, buf, buflen, pwbufp);
}

/* user enum functions */
_PUBLIC_ void nwrap_setpwent(void)
{
	real_setpwent();
}

_PUBLIC_ struct passwd *nwrap_getpwent(void)
{
	return real_getpwent();
}

_PUBLIC_ int nwrap_getpwent_r(struct passwd *pwbuf, char *buf,
			      size_t buflen, struct passwd **pwbufp)
{
	return real_getpwent_r(pwbuf, buf, buflen, pwbufp);
}

_PUBLIC_ void nwrap_endpwent(void)
{
	real_endpwent();
}

/* misc functions */
_PUBLIC_ int nwrap_initgroups(const char *user, gid_t group)
{
	return real_initgroups(user, group);
}

/* group functions */
_PUBLIC_ struct group *nwrap_getgrnam(const char *name)
{
	return real_getgrnam(name);
}

_PUBLIC_ int nwrap_getgrnam_r(const char *name, struct group *gbuf,
			      char *buf, size_t buflen, struct group **gbufp)
{
	return real_getgrnam_r(name, gbuf, buf, buflen, gbufp);
}

_PUBLIC_ struct group *nwrap_getgrgid(gid_t gid)
{
	return real_getgrgid(gid);
}

_PUBLIC_ int nwrap_getgrgid_r(gid_t gid, struct group *gbuf,
			      char *buf, size_t buflen, struct group **gbufp)
{
	return real_getgrgid_r(gid, gbuf, buf, buflen, gbufp);
}

/* group enum functions */
_PUBLIC_ void nwrap_setgrent(void)
{
	real_setgrent();
}

_PUBLIC_ struct group *nwrap_getgrent(void)
{
	return real_getgrent();
}

_PUBLIC_ int nwrap_getgrent_r(struct group *gbuf, char *buf,
			      size_t buflen, struct group **gbufp)
{
	return real_getgrent_r(gbuf, buf, buflen, gbufp);
}

_PUBLIC_ void nwrap_endgrent(void)
{
	real_endgrent();
}
