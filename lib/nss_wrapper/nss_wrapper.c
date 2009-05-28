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
#include "../replace/replace.h"
#include "system/passwd.h"
#include "system/filesys.h"

#else /* _SAMBA_BUILD_ */

#error nss_wrapper_only_supported_in_samba_yet

#endif

#ifndef _PUBLIC_
#define _PUBLIC_
#endif

/* not all systems have _r functions... */
#ifndef HAVE_GETPWNAM_R
#define getpwnam_r(name, pwdst, buf, buflen, pwdstp)	ENOSYS
#endif
#ifndef HAVE_GETPWUID_R
#define getpwuid_r(uid, pwdst, buf, buflen, pwdstp)	ENOSYS
#endif
#ifndef HAVE_GETPWENT_R
#define getpwent_r(pwdst, buf, buflen, pwdstp)		ENOSYS
#endif
#ifndef HAVE_GETGRNAM_R
#define getgrnam_r(name, grdst, buf, buflen, grdstp)	ENOSYS
#endif
#ifndef HAVE_GETGRUID_R
#define getgrgid_r(uid, grdst, buf, buflen, grdstp)	ENOSYS
#endif
#ifndef HAVE_GETGRENT_R
#define getgrent_r(grdst, buf, buflen, grdstp)		ENOSYS
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

#if 0
# ifdef DEBUG
# define NWRAP_ERROR(args)	DEBUG(0, args)
# else
# define NWRAP_ERROR(args)	printf args
# endif
#else
#define NWRAP_ERROR(args)
#endif

#if 0
# ifdef DEBUG
# define NWRAP_DEBUG(args)	DEBUG(0, args)
# else
# define NWRAP_DEBUG(args)	printf args
# endif
#else
#define NWRAP_DEBUG(args)
#endif

#if 0
# ifdef DEBUG
# define NWRAP_VERBOSE(args)	DEBUG(0, args)
# else
# define NWRAP_VERBOSE(args)	printf args
# endif
#else
#define NWRAP_VERBOSE(args)
#endif

struct nwrap_cache {
	const char *path;
	int fd;
	struct stat st;
	uint8_t *buf;
	void *private_data;
	bool (*parse_line)(struct nwrap_cache *, char *line);
	void (*unload)(struct nwrap_cache *);
};

struct nwrap_pw {
	struct nwrap_cache *cache;

	struct passwd *list;
	int num;
	int idx;
};

struct nwrap_cache __nwrap_cache_pw;
struct nwrap_pw nwrap_pw_global;

static bool nwrap_pw_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_pw_unload(struct nwrap_cache *nwrap);

struct nwrap_gr {
	struct nwrap_cache *cache;

	struct group *list;
	int num;
	int idx;
};

struct nwrap_cache __nwrap_cache_gr;
struct nwrap_gr nwrap_gr_global;

static bool nwrap_gr_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_gr_unload(struct nwrap_cache *nwrap);

static void nwrap_init(void)
{
	static bool initialized;

	if (initialized) return;
	initialized = true;

	nwrap_pw_global.cache = &__nwrap_cache_pw;

	nwrap_pw_global.cache->path = getenv("NSS_WRAPPER_PASSWD");
	nwrap_pw_global.cache->fd = -1;
	nwrap_pw_global.cache->private_data = &nwrap_pw_global;
	nwrap_pw_global.cache->parse_line = nwrap_pw_parse_line;
	nwrap_pw_global.cache->unload = nwrap_pw_unload;

	nwrap_gr_global.cache = &__nwrap_cache_gr;

	nwrap_gr_global.cache->path = getenv("NSS_WRAPPER_GROUP");
	nwrap_gr_global.cache->fd = -1;
	nwrap_gr_global.cache->private_data = &nwrap_gr_global;
	nwrap_gr_global.cache->parse_line = nwrap_gr_parse_line;
	nwrap_gr_global.cache->unload = nwrap_gr_unload;
}

static bool nwrap_enabled(void)
{
	nwrap_init();

	if (!nwrap_pw_global.cache->path) {
		return false;
	}
	if (nwrap_pw_global.cache->path[0] == '\0') {
		return false;
	}
	if (!nwrap_gr_global.cache->path) {
		return false;
	}
	if (nwrap_gr_global.cache->path[0] == '\0') {
		return false;
	}

	return true;
}

static bool nwrap_parse_file(struct nwrap_cache *nwrap)
{
	int ret;
	uint8_t *buf = NULL;
	char *nline;

	if (nwrap->st.st_size == 0) {
		NWRAP_DEBUG(("%s: size == 0\n",
			     __location__));
		goto done;
	}

	if (nwrap->st.st_size > INT32_MAX) {
		NWRAP_ERROR(("%s: size[%u] larger than INT32_MAX\n",
			     __location__, (unsigned)nwrap->st.st_size));
		goto failed;
	}

	ret = lseek(nwrap->fd, 0, SEEK_SET);
	if (ret != 0) {
		NWRAP_ERROR(("%s: lseek - %d\n",__location__,ret));
		goto failed;
	}

	buf = (uint8_t *)malloc(nwrap->st.st_size + 1);
	if (!buf) {
		NWRAP_ERROR(("%s: malloc failed\n",__location__));
		goto failed;
	}

	ret = read(nwrap->fd, buf, nwrap->st.st_size);
	if (ret != nwrap->st.st_size) {
		NWRAP_ERROR(("%s: read(%u) gave %d\n",
			     __location__, (unsigned)nwrap->st.st_size, ret));
		goto failed;
	}

	buf[nwrap->st.st_size] = '\0';

	nline = (char *)buf;
	while (nline && nline[0]) {
		char *line;
		char *e;
		bool ok;

		line = nline;
		nline = NULL;

		e = strchr(line, '\n');
		if (e) {
			e[0] = '\0';
			e++;
			if (e[0] == '\r') {
				e[0] = '\0';
				e++;
			}
			nline = e;
		}

		NWRAP_VERBOSE(("%s:'%s'\n",__location__, line));

		if (strlen(line) == 0) {
			continue;
		}

		ok = nwrap->parse_line(nwrap, line);
		if (!ok) {
			goto failed;
		}
	}

done:
	nwrap->buf = buf;
	return true;

failed:
	if (buf) free(buf);
	return false;
}

static void nwrap_cache_unload(struct nwrap_cache *nwrap)
{
	nwrap->unload(nwrap);

	if (nwrap->buf) free(nwrap->buf);

	nwrap->buf = NULL;
}

static void nwrap_cache_reload(struct nwrap_cache *nwrap)
{
	struct stat st;
	int ret;
	bool ok;
	bool retried = false;

reopen:
	if (nwrap->fd < 0) {
		nwrap->fd = open(nwrap->path, O_RDONLY);
		if (nwrap->fd < 0) {
			NWRAP_ERROR(("%s: unable to open '%s' readonly %d:%s\n",
				     __location__,
				     nwrap->path, nwrap->fd,
				     strerror(errno)));
			return;
		}
		NWRAP_VERBOSE(("%s: open '%s'\n", __location__, nwrap->path));
	}

	ret = fstat(nwrap->fd, &st);
	if (ret != 0) {
		NWRAP_ERROR(("%s: fstat(%s) - %d:%s\n",
			     __location__,
			     nwrap->path,
			     ret, strerror(errno)));
		return;
	}

	if (retried == false && st.st_nlink == 0) {
		/* maybe someone has replaced the file... */
		NWRAP_DEBUG(("%s: st_nlink == 0, reopen %s\n",
			     __location__, nwrap->path));
		retried = true;
		memset(&nwrap->st, 0, sizeof(nwrap->st));
		close(nwrap->fd);
		nwrap->fd = -1;
		goto reopen;
	}

	if (st.st_mtime == nwrap->st.st_mtime) {
		NWRAP_VERBOSE(("%s: st_mtime[%u] hasn't changed, skip reload\n",
			       __location__, (unsigned)st.st_mtime));
		return;
	}
	NWRAP_DEBUG(("%s: st_mtime has changed [%u] => [%u], start reload\n",
		     __location__, (unsigned)st.st_mtime,
		     (unsigned)nwrap->st.st_mtime));

	nwrap->st = st;

	nwrap_cache_unload(nwrap);

	ok = nwrap_parse_file(nwrap);
	if (!ok) {
		NWRAP_ERROR(("%s: failed to reload %s\n",
			     __location__, nwrap->path));
		nwrap_cache_unload(nwrap);
	}
	NWRAP_DEBUG(("%s: reloaded %s\n",
		     __location__, nwrap->path));
}

/*
 * the caller has to call nwrap_unload() on failure
 */
static bool nwrap_pw_parse_line(struct nwrap_cache *nwrap, char *line)
{
	struct nwrap_pw *nwrap_pw;
	char *c;
	char *p;
	char *e;
	struct passwd *pw;
	size_t list_size;

	nwrap_pw = (struct nwrap_pw *)nwrap->private_data;

	list_size = sizeof(*nwrap_pw->list) * (nwrap_pw->num+1);
	pw = (struct passwd *)realloc(nwrap_pw->list, list_size);
	if (!pw) {
		NWRAP_ERROR(("%s:realloc(%u) failed\n",
			     __location__, list_size));
		return false;
	}
	nwrap_pw->list = pw;

	pw = &nwrap_pw->list[nwrap_pw->num];

	c = line;

	/* name */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_name = c;
	c = p;

	NWRAP_VERBOSE(("name[%s]\n", pw->pw_name));

	/* password */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_passwd = c;
	c = p;

	NWRAP_VERBOSE(("password[%s]\n", pw->pw_passwd));

	/* uid */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	e = NULL;
	pw->pw_uid = (uid_t)strtoul(c, &e, 10);
	if (c == e) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	if (e == NULL) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	if (e[0] != '\0') {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	c = p;

	NWRAP_VERBOSE(("uid[%u]\n", pw->pw_uid));

	/* gid */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	e = NULL;
	pw->pw_gid = (gid_t)strtoul(c, &e, 10);
	if (c == e) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	if (e == NULL) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	if (e[0] != '\0') {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	c = p;

	NWRAP_VERBOSE(("gid[%u]\n", pw->pw_gid));

	/* gecos */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_gecos = c;
	c = p;

	NWRAP_VERBOSE(("gecos[%s]\n", pw->pw_gecos));

	/* dir */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:'%s'\n",__location__,c));
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_dir = c;
	c = p;

	NWRAP_VERBOSE(("dir[%s]\n", pw->pw_dir));

	/* shell */
	pw->pw_shell = c;
	NWRAP_VERBOSE(("shell[%s]\n", pw->pw_shell));

	NWRAP_DEBUG(("add user[%s:%s:%u:%u:%s:%s:%s]\n",
		     pw->pw_name, pw->pw_passwd,
		     pw->pw_uid, pw->pw_gid,
		     pw->pw_gecos, pw->pw_dir, pw->pw_shell));

	nwrap_pw->num++;
	return true;
}

static void nwrap_pw_unload(struct nwrap_cache *nwrap)
{
	struct nwrap_pw *nwrap_pw;
	nwrap_pw = (struct nwrap_pw *)nwrap->private_data;

	if (nwrap_pw->list) free(nwrap_pw->list);

	nwrap_pw->list = NULL;
	nwrap_pw->num = 0;
	nwrap_pw->idx = 0;
}

static int nwrap_pw_copy_r(const struct passwd *src, struct passwd *dst,
			   char *buf, size_t buflen, struct passwd **dstp)
{
	char *first;
	char *last;
	off_t ofs;

	first = src->pw_name;

	last = src->pw_shell;
	while (*last) last++;

	ofs = PTR_DIFF(last + 1, first);

	if (ofs > buflen) {
		return ERANGE;
	}

	memcpy(buf, first, ofs);

	ofs = PTR_DIFF(src->pw_name, first);
	dst->pw_name = buf + ofs;
	ofs = PTR_DIFF(src->pw_passwd, first);
	dst->pw_passwd = buf + ofs;
	dst->pw_uid = src->pw_uid;
	dst->pw_gid = src->pw_gid;
	ofs = PTR_DIFF(src->pw_gecos, first);
	dst->pw_gecos = buf + ofs;
	ofs = PTR_DIFF(src->pw_dir, first);
	dst->pw_dir = buf + ofs;
	ofs = PTR_DIFF(src->pw_shell, first);
	dst->pw_shell = buf + ofs;

	if (dstp) {
		*dstp = dst;
	}

	return 0;
}

/*
 * the caller has to call nwrap_unload() on failure
 */
static bool nwrap_gr_parse_line(struct nwrap_cache *nwrap, char *line)
{
	struct nwrap_gr *nwrap_gr;
	char *c;
	char *p;
	char *e;
	struct group *gr;
	size_t list_size;
	unsigned nummem;

	nwrap_gr = (struct nwrap_gr *)nwrap->private_data;

	list_size = sizeof(*nwrap_gr->list) * (nwrap_gr->num+1);
	gr = (struct group *)realloc(nwrap_gr->list, list_size);
	if (!gr) {
		NWRAP_ERROR(("%s:realloc failed\n",__location__));
		return false;
	}
	nwrap_gr->list = gr;

	gr = &nwrap_gr->list[nwrap_gr->num];

	c = line;

	/* name */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	gr->gr_name = c;
	c = p;

	NWRAP_VERBOSE(("name[%s]\n", gr->gr_name));

	/* password */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	gr->gr_passwd = c;
	c = p;

	NWRAP_VERBOSE(("password[%s]\n", gr->gr_passwd));

	/* gid */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s'\n",
			     __location__, line, c));
		return false;
	}
	*p = '\0';
	p++;
	e = NULL;
	gr->gr_gid = (gid_t)strtoul(c, &e, 10);
	if (c == e) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	if (e == NULL) {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	if (e[0] != '\0') {
		NWRAP_ERROR(("%s:invalid line[%s]: '%s' - %s\n",
			     __location__, line, c, strerror(errno)));
		return false;
	}
	c = p;

	NWRAP_VERBOSE(("gid[%u]\n", gr->gr_gid));

	/* members */
	gr->gr_mem = (char **)malloc(sizeof(char *));
	if (!gr->gr_mem) {
		NWRAP_ERROR(("%s:calloc failed\n",__location__));
		return false;
	}
	gr->gr_mem[0] = NULL;

	for(nummem=0; p; nummem++) {
		char **m;
		size_t m_size;
		c = p;
		p = strchr(c, ',');
		if (p) {
			*p = '\0';
			p++;
		}

		if (strlen(c) == 0) {
			break;
		}

		m_size = sizeof(char *) * (nummem+2);
		m = (char **)realloc(gr->gr_mem, m_size);
		if (!m) {
			NWRAP_ERROR(("%s:realloc(%u) failed\n",
				      __location__, m_size));
			return false;
		}
		gr->gr_mem = m;
		gr->gr_mem[nummem] = c;
		gr->gr_mem[nummem+1] = NULL;

		NWRAP_VERBOSE(("member[%u]: '%s'\n", nummem, gr->gr_mem[nummem]));
	}

	NWRAP_DEBUG(("add group[%s:%s:%u:] with %u members\n",
		     gr->gr_name, gr->gr_passwd, gr->gr_gid, nummem));

	nwrap_gr->num++;
	return true;
}

static void nwrap_gr_unload(struct nwrap_cache *nwrap)
{
	int i;
	struct nwrap_gr *nwrap_gr;
	nwrap_gr = (struct nwrap_gr *)nwrap->private_data;

	if (nwrap_gr->list) {
		for (i=0; i < nwrap_gr->num; i++) {
			if (nwrap_gr->list[i].gr_mem) {
				free(nwrap_gr->list[i].gr_mem);
			}
		}
		free(nwrap_gr->list);
	}

	nwrap_gr->list = NULL;
	nwrap_gr->num = 0;
	nwrap_gr->idx = 0;
}

static int nwrap_gr_copy_r(const struct group *src, struct group *dst,
			   char *buf, size_t buflen, struct group **dstp)
{
	char *first;
	char **lastm;
	char *last;
	off_t ofsb;
	off_t ofsm;
	off_t ofs;
	unsigned i;

	first = src->gr_name;

	lastm = src->gr_mem;
	while (*lastm) lastm++;

	last = *lastm;
	while (*last) last++;

	ofsb = PTR_DIFF(last + 1, first);
	ofsm = PTR_DIFF(lastm + 1, src->gr_mem);

	if ((ofsb + ofsm) > buflen) {
		return ERANGE;
	}

	memcpy(buf, first, ofsb);
	memcpy(buf + ofsb, src->gr_mem, ofsm);

	ofs = PTR_DIFF(src->gr_name, first);
	dst->gr_name = buf + ofs;
	ofs = PTR_DIFF(src->gr_passwd, first);
	dst->gr_passwd = buf + ofs;
	dst->gr_gid = src->gr_gid;

	dst->gr_mem = (char **)(buf + ofsb);
	for (i=0; src->gr_mem[i]; i++) {
		ofs = PTR_DIFF(src->gr_mem[i], first);
		dst->gr_mem[i] = buf + ofs;
	}

	if (dstp) {
		*dstp = dst;
	}

	return 0;
}

/* user functions */

static struct passwd *nwrap_files_getpwnam(const char *name)
{
	int i;

	nwrap_cache_reload(nwrap_pw_global.cache);

	for (i=0; i<nwrap_pw_global.num; i++) {
		if (strcmp(nwrap_pw_global.list[i].pw_name, name) == 0) {
			NWRAP_DEBUG(("%s: user[%s] found\n",
				     __location__, name));
			return &nwrap_pw_global.list[i];
		}
		NWRAP_VERBOSE(("%s: user[%s] does not match [%s]\n",
			       __location__, name,
			       nwrap_pw_global.list[i].pw_name));
	}

	NWRAP_DEBUG(("%s: user[%s] not found\n", __location__, name));

	errno = ENOENT;
	return NULL;
}

_PUBLIC_ struct passwd *nwrap_getpwnam(const char *name)
{
	if (!nwrap_enabled()) {
		return real_getpwnam(name);
	}

	return nwrap_files_getpwnam(name);
}

static int nwrap_files_getpwnam_r(const char *name, struct passwd *pwdst,
				  char *buf, size_t buflen, struct passwd **pwdstp)
{
	struct passwd *pw;

	pw = nwrap_getpwnam(name);
	if (!pw) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_pw_copy_r(pw, pwdst, buf, buflen, pwdstp);
}

_PUBLIC_ int nwrap_getpwnam_r(const char *name, struct passwd *pwdst,
			      char *buf, size_t buflen, struct passwd **pwdstp)
{
	if (!nwrap_enabled()) {
		return real_getpwnam_r(name, pwdst, buf, buflen, pwdstp);
	}

	return nwrap_files_getpwnam_r(name, pwdst, buf, buflen, pwdstp);
}

static struct passwd *nwrap_files_getpwuid(uid_t uid)
{
	int i;

	nwrap_cache_reload(nwrap_pw_global.cache);

	for (i=0; i<nwrap_pw_global.num; i++) {
		if (nwrap_pw_global.list[i].pw_uid == uid) {
			NWRAP_DEBUG(("%s: uid[%u] found\n",
				     __location__, uid));
			return &nwrap_pw_global.list[i];
		}
		NWRAP_VERBOSE(("%s: uid[%u] does not match [%u]\n",
			       __location__, uid,
			       nwrap_pw_global.list[i].pw_uid));
	}

	NWRAP_DEBUG(("%s: uid[%u] not found\n", __location__, uid));

	errno = ENOENT;
	return NULL;
}

_PUBLIC_ struct passwd *nwrap_getpwuid(uid_t uid)
{
	if (!nwrap_enabled()) {
		return real_getpwuid(uid);
	}

	return nwrap_files_getpwuid(uid);
}

static int nwrap_files_getpwuid_r(uid_t uid, struct passwd *pwdst,
				  char *buf, size_t buflen, struct passwd **pwdstp)
{
	struct passwd *pw;

	pw = nwrap_getpwuid(uid);
	if (!pw) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_pw_copy_r(pw, pwdst, buf, buflen, pwdstp);
}

_PUBLIC_ int nwrap_getpwuid_r(uid_t uid, struct passwd *pwdst,
			      char *buf, size_t buflen, struct passwd **pwdstp)
{
	if (!nwrap_enabled()) {
		return real_getpwuid_r(uid, pwdst, buf, buflen, pwdstp);
	}

	return nwrap_files_getpwuid_r(uid, pwdst, buf, buflen, pwdstp);
}

/* user enum functions */
static void nwrap_files_setpwent(void)
{
	nwrap_pw_global.idx = 0;
}

_PUBLIC_ void nwrap_setpwent(void)
{
	if (!nwrap_enabled()) {
		real_setpwent();
	}

	nwrap_files_setpwent();
}

static struct passwd *nwrap_files_getpwent(void)
{
	struct passwd *pw;

	if (nwrap_pw_global.idx == 0) {
		nwrap_cache_reload(nwrap_pw_global.cache);
	}

	if (nwrap_pw_global.idx >= nwrap_pw_global.num) {
		errno = ENOENT;
		return NULL;
	}

	pw = &nwrap_pw_global.list[nwrap_pw_global.idx++];

	NWRAP_VERBOSE(("%s: return user[%s] uid[%u]\n",
		       __location__, pw->pw_name, pw->pw_uid));

	return pw;
}

_PUBLIC_ struct passwd *nwrap_getpwent(void)
{
	if (!nwrap_enabled()) {
		return real_getpwent();
	}

	return nwrap_files_getpwent();
}

static int nwrap_files_getpwent_r(struct passwd *pwdst, char *buf,
				  size_t buflen, struct passwd **pwdstp)
{
	struct passwd *pw;

	pw = nwrap_getpwent();
	if (!pw) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_pw_copy_r(pw, pwdst, buf, buflen, pwdstp);
}

_PUBLIC_ int nwrap_getpwent_r(struct passwd *pwdst, char *buf,
			      size_t buflen, struct passwd **pwdstp)
{
	if (!nwrap_enabled()) {
#ifdef SOLARIS_GETPWENT_R
		struct passwd *pw;
		pw = real_getpwent_r(pwdst, buf, buflen);
		if (!pw) {
			if (errno == 0) {
				return ENOENT;
			}
			return errno;
		}
		if (pwdstp) {
			*pwdstp = pw;
		}
		return 0;
#else
		return real_getpwent_r(pwdst, buf, buflen, pwdstp);
#endif
	}

	return nwrap_files_getpwent_r(pwdst, buf, buflen, pwdstp);
}

static void nwrap_files_endpwent(void)
{
	nwrap_pw_global.idx = 0;
}

_PUBLIC_ void nwrap_endpwent(void)
{
	if (!nwrap_enabled()) {
		real_endpwent();
	}

	nwrap_files_endpwent();
}

/* misc functions */
static int nwrap_files_initgroups(const char *user, gid_t group)
{
	/* TODO: maybe we should also fake this... */
	return EPERM;
}

_PUBLIC_ int nwrap_initgroups(const char *user, gid_t group)
{
	if (!nwrap_enabled()) {
		return real_initgroups(user, group);
	}

	return nwrap_files_initgroups(user, group);
}

/* group functions */
static struct group *nwrap_files_getgrnam(const char *name)
{
	int i;

	nwrap_cache_reload(nwrap_gr_global.cache);

	for (i=0; i<nwrap_gr_global.num; i++) {
		if (strcmp(nwrap_gr_global.list[i].gr_name, name) == 0) {
			NWRAP_DEBUG(("%s: group[%s] found\n",
				     __location__, name));
			return &nwrap_gr_global.list[i];
		}
		NWRAP_VERBOSE(("%s: group[%s] does not match [%s]\n",
			       __location__, name,
			       nwrap_gr_global.list[i].gr_name));
	}

	NWRAP_DEBUG(("%s: group[%s] not found\n", __location__, name));

	errno = ENOENT;
	return NULL;
}

_PUBLIC_ struct group *nwrap_getgrnam(const char *name)
{
	if (!nwrap_enabled()) {
		return real_getgrnam(name);
	}

	return nwrap_files_getgrnam(name);
}

static int nwrap_files_getgrnam_r(const char *name, struct group *grdst,
				  char *buf, size_t buflen, struct group **grdstp)
{
	struct group *gr;

	gr = nwrap_getgrnam(name);
	if (!gr) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_gr_copy_r(gr, grdst, buf, buflen, grdstp);
}

_PUBLIC_ int nwrap_getgrnam_r(const char *name, struct group *grdst,
			      char *buf, size_t buflen, struct group **grdstp)
{
	if (!nwrap_enabled()) {
		return real_getgrnam_r(name, grdst, buf, buflen, grdstp);
	}

	return nwrap_files_getgrnam_r(name, grdst, buf, buflen, grdstp);
}

static struct group *nwrap_files_getgrgid(gid_t gid)
{
	int i;

	nwrap_cache_reload(nwrap_gr_global.cache);

	for (i=0; i<nwrap_gr_global.num; i++) {
		if (nwrap_gr_global.list[i].gr_gid == gid) {
			NWRAP_DEBUG(("%s: gid[%u] found\n",
				     __location__, gid));
			return &nwrap_gr_global.list[i];
		}
		NWRAP_VERBOSE(("%s: gid[%u] does not match [%u]\n",
			       __location__, gid,
			       nwrap_gr_global.list[i].gr_gid));
	}

	NWRAP_DEBUG(("%s: gid[%u] not found\n", __location__, gid));

	errno = ENOENT;
	return NULL;
}

_PUBLIC_ struct group *nwrap_getgrgid(gid_t gid)
{
	if (!nwrap_enabled()) {
		return real_getgrgid(gid);
	}

	return nwrap_files_getgrgid(gid);
}

static int nwrap_files_getgrgid_r(gid_t gid, struct group *grdst,
				  char *buf, size_t buflen, struct group **grdstp)
{
	struct group *gr;

	gr = nwrap_getgrgid(gid);
	if (!gr) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_gr_copy_r(gr, grdst, buf, buflen, grdstp);

	return ENOENT;
}

_PUBLIC_ int nwrap_getgrgid_r(gid_t gid, struct group *grdst,
			      char *buf, size_t buflen, struct group **grdstp)
{
	if (!nwrap_enabled()) {
		return real_getgrgid_r(gid, grdst, buf, buflen, grdstp);
	}

	return nwrap_files_getgrgid_r(gid, grdst, buf, buflen, grdstp);
}

/* group enum functions */
static void nwrap_files_setgrent(void)
{
	nwrap_gr_global.idx = 0;
}

_PUBLIC_ void nwrap_setgrent(void)
{
	if (!nwrap_enabled()) {
		real_setgrent();
	}

	nwrap_files_setgrent();
}

static struct group *nwrap_files_getgrent(void)
{
	struct group *gr;

	if (nwrap_gr_global.idx == 0) {
		nwrap_cache_reload(nwrap_gr_global.cache);
	}

	if (nwrap_gr_global.idx >= nwrap_gr_global.num) {
		errno = ENOENT;
		return NULL;
	}

	gr = &nwrap_gr_global.list[nwrap_gr_global.idx++];

	NWRAP_VERBOSE(("%s: return group[%s] gid[%u]\n",
		       __location__, gr->gr_name, gr->gr_gid));

	return gr;
}

_PUBLIC_ struct group *nwrap_getgrent(void)
{
	if (!nwrap_enabled()) {
		return real_getgrent();
	}

	return nwrap_files_getgrent();
}

static int nwrap_files_getgrent_r(struct group *grdst, char *buf,
				  size_t buflen, struct group **grdstp)
{
	struct group *gr;

	gr = nwrap_getgrent();
	if (!gr) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_gr_copy_r(gr, grdst, buf, buflen, grdstp);
}

_PUBLIC_ int nwrap_getgrent_r(struct group *grdst, char *buf,
			      size_t buflen, struct group **grdstp)
{
	if (!nwrap_enabled()) {
#ifdef SOLARIS_GETGRENT_R
		struct group *gr;
		gr = real_getgrent_r(grdst, buf, buflen);
		if (!gr) {
			if (errno == 0) {
				return ENOENT;
			}
			return errno;
		}
		if (grdstp) {
			*grdstp = gr;
		}
		return 0;
#else
		return real_getgrent_r(grdst, buf, buflen, grdstp);
#endif
	}

	return nwrap_files_getgrent_r(grdst, buf, buflen, grdstp);
}

static void nwrap_files_endgrent(void)
{
	nwrap_gr_global.idx = 0;
}

_PUBLIC_ void nwrap_endgrent(void)
{
	if (!nwrap_enabled()) {
		real_endgrent();
	}

	nwrap_files_endgrent();
}
