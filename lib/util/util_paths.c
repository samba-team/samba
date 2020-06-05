/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2007
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) James Peach 2006
   Copyright (c) 2020      Andreas Schneider <asn@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "dynconfig/dynconfig.h"
#include "lib/util/util_paths.h"
#include "system/passwd.h"

/**
 * @brief Returns an absolute path to a file in the Samba modules directory.
 *
 * @param name File to find, relative to MODULESDIR.
 *
 * @retval Pointer to a string containing the full path.
 **/

char *modules_path(TALLOC_CTX *mem_ctx, const char *name)
{
	return talloc_asprintf(mem_ctx, "%s/%s", get_dyn_MODULESDIR(), name);
}

/**
 * @brief Returns an absolute path to a file in the Samba data directory.
 *
 * @param name File to find, relative to CODEPAGEDIR.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

char *data_path(TALLOC_CTX *mem_ctx, const char *name)
{
	return talloc_asprintf(mem_ctx, "%s/%s", get_dyn_CODEPAGEDIR(), name);
}

/**
 * @brief Returns the platform specific shared library extension.
 *
 * @retval Pointer to a const char * containing the extension.
 **/

const char *shlib_ext(void)
{
	return get_dyn_SHLIBEXT();
}

static char *get_user_home_dir(TALLOC_CTX *mem_ctx)
{
	struct passwd pwd = {0};
	struct passwd *pwdbuf = NULL;
	char *buf = NULL;
	char *out = NULL;
	long int initlen;
	size_t len;
	int rc;

	initlen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (initlen == -1) {
		len = 1024;
	} else {
		len = (size_t)initlen;
	}
	buf = talloc_size(mem_ctx, len);
	if (buf == NULL) {
		return NULL;
	}

	rc = getpwuid_r(getuid(), &pwd, buf, len, &pwdbuf);
	while (rc == ERANGE) {
		size_t newlen = 2 * len;
		if (newlen < len) {
			/* Overflow */
			goto done;
		}
		len = newlen;
		buf = talloc_realloc_size(mem_ctx, buf, len);
		if (buf == NULL) {
			goto done;
		}
		rc = getpwuid_r(getuid(), &pwd, buf, len, &pwdbuf);
	}
	if (rc != 0 || pwdbuf == NULL ) {
		const char *szPath = getenv("HOME");
		if (szPath == NULL) {
			goto done;
		}
		len = strnlen(szPath, PATH_MAX);
		if (len >= PATH_MAX) {
			return NULL;
		}
		out = talloc_strdup(mem_ctx, szPath);
		goto done;
	}

	out = talloc_strdup(mem_ctx, pwd.pw_dir);
done:
	TALLOC_FREE(buf);
	return out;
}

char *path_expand_tilde(TALLOC_CTX *mem_ctx, const char *d)
{
	char *h = NULL, *r = NULL;
	const char *p = NULL;
	struct stat sb = {0};
	int rc;

	if (d[0] != '~') {
		return talloc_strdup(mem_ctx, d);
	}
	d++;

	/* handle ~user/path */
	p = strchr(d, '/');
	if (p != NULL && p > d) {
		struct passwd *pw;
		size_t s = p - d;
		char u[128];

		if (s >= sizeof(u)) {
			return NULL;
		}
		memcpy(u, d, s);
		u[s] = '\0';

		pw = getpwnam(u);
		if (pw == NULL) {
			return NULL;
		}
		h = talloc_strdup(mem_ctx, pw->pw_dir);
	} else {
		p = d;
		h = get_user_home_dir(mem_ctx);
	}
	if (h == NULL) {
		return NULL;
	}

	rc = stat(h, &sb);
	if (rc != 0) {
		TALLOC_FREE(h);
		return NULL;
	}

	r = talloc_asprintf(mem_ctx, "%s%s", h, p);
	TALLOC_FREE(h);

	return r;
}
