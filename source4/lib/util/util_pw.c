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

static struct passwd *alloc_copy_passwd(const struct passwd *from) 
{
	struct passwd *ret = smb_xmalloc_p(struct passwd);
	ZERO_STRUCTP(ret);
	ret->pw_name = smb_xstrdup(from->pw_name);
	ret->pw_passwd = smb_xstrdup(from->pw_passwd);
	ret->pw_uid = from->pw_uid;
	ret->pw_gid = from->pw_gid;
	ret->pw_gecos = smb_xstrdup(from->pw_gecos);
	ret->pw_dir = smb_xstrdup(from->pw_dir);
	ret->pw_shell = smb_xstrdup(from->pw_shell);
	return ret;
}

void passwd_free (struct passwd **buf)
{
	if (!*buf) {
		DEBUG(0, ("attempted double-free of allocated passwd\n"));
		return;
	}

	SAFE_FREE((*buf)->pw_name);
	SAFE_FREE((*buf)->pw_passwd);
	SAFE_FREE((*buf)->pw_gecos);
	SAFE_FREE((*buf)->pw_dir);
	SAFE_FREE((*buf)->pw_shell);

	SAFE_FREE(*buf);
}

struct passwd *getpwnam_alloc(const char *name) 
{
	struct passwd *temp;

	temp = sys_getpwnam(name);
	
	if (!temp) {
#if 0
		if (errno == ENOMEM) {
			/* what now? */
		}
#endif
		return NULL;
	}

	return alloc_copy_passwd(temp);
}

struct passwd *getpwuid_alloc(uid_t uid) 
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

	return alloc_copy_passwd(temp);
}
