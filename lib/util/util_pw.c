/* 
   Unix SMB/CIFS implementation.

   Safe versions of getpw* calls

   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison  1998-2005
   Copyright (C) Andrew Bartlett 2002
   Copyright (C) Timur Bakeyev        2005
   Copyright (C) Bjoern Jacke    2006-2007

   
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

#include "replace.h"
#include <talloc.h>
#include "system/passwd.h"
#include "lib/util/util_pw.h"

struct passwd *tcopy_passwd(TALLOC_CTX *mem_ctx,
			    const struct passwd *from)
{
	struct passwd *ret;
	size_t len = 0;

	len += strlen(from->pw_name)+1;
	len += strlen(from->pw_passwd)+1;
	len += strlen(from->pw_gecos)+1;
	len += strlen(from->pw_dir)+1;
	len += strlen(from->pw_shell)+1;

	ret = talloc_pooled_object(mem_ctx, struct passwd, 5, len);

	if (ret == NULL) {
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

struct passwd *getpwnam_alloc(TALLOC_CTX *mem_ctx, const char *name)
{
	struct passwd *temp;

	temp = getpwnam(name);
	
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

/****************************************************************************
 talloc'ed version of getpwuid.
****************************************************************************/

struct passwd *getpwuid_alloc(TALLOC_CTX *mem_ctx, uid_t uid)
{
	struct passwd *temp;

	temp = getpwuid(uid);
	
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
