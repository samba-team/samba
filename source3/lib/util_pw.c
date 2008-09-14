/* 
   Unix SMB/CIFS implementation.

   Safe versions of getpw* calls

   Copyright (C) Andrew Bartlett 2002
   
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

struct passwd *tcopy_passwd(TALLOC_CTX *mem_ctx, const struct passwd *from) 
{
	struct passwd *ret = TALLOC_P(mem_ctx, struct passwd);
	if (!ret) {
		return NULL;
	}
	ret->pw_name = talloc_strdup(ret, from->pw_name);
	ret->pw_passwd = talloc_strdup(ret, from->pw_passwd);
	ret->pw_uid = from->pw_uid;
	ret->pw_gid = from->pw_gid;
	ret->pw_gecos = talloc_strdup(ret, from->pw_gecos);
	ret->pw_dir = talloc_strdup(ret, from->pw_dir);
	ret->pw_shell = talloc_strdup(ret, from->pw_shell);
	return ret;
}

void flush_pwnam_cache(void)
{
	memcache_flush(NULL, GETPWNAM_CACHE);
}

struct passwd *getpwnam_alloc(TALLOC_CTX *mem_ctx, const char *name)
{
	struct passwd *temp, *cached;

	temp = (struct passwd *)memcache_lookup_talloc(
		NULL, GETPWNAM_CACHE, data_blob_string_const(name));
	if (temp != NULL) {
		return tcopy_passwd(mem_ctx, temp);
	}

	temp = sys_getpwnam(name);
	if (temp == NULL) {
		return NULL;
	}

	cached = tcopy_passwd(NULL, temp);
	if (cached == NULL) {
		/*
		 * Just don't add this into the cache, ignore the failure
		 */
		return temp;
	}

	memcache_add_talloc(NULL, GETPWNAM_CACHE, data_blob_string_const(name),
			    cached);
	return tcopy_passwd(mem_ctx, temp);
}

struct passwd *getpwuid_alloc(TALLOC_CTX *mem_ctx, uid_t uid) 
{
	struct passwd *temp;

	temp = sys_getpwuid(uid);
	
	if (!temp) {
#if 0
		if (errno == ENOMEM) {
			/* what now? */
		}
#endif
		return NULL;
	}

	return tcopy_passwd(mem_ctx, temp);
}
