/* 
   Unix SMB/CIFS implementation.

   Safe versions of getpw* calls

   Copyright (C) Andrew Bartlett 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

struct passwd *make_modifyable_passwd(const struct passwd *from)
{
	struct passwd *ret = smb_xmalloc(sizeof(*ret));
/*  This is the assumed shape of the members by certain parts of the code...
	fstring 	pw_name;
	fstring 	pw_passwd;
	fstring		pw_gecos;
	pstring		pw_dir;
	pstring		pw_shell;
*/
	char *pw_name = smb_xmalloc(sizeof(fstring));
	char *pw_passwd = smb_xmalloc(sizeof(fstring));
	char *pw_gecos = smb_xmalloc(sizeof(fstring));
	char *pw_dir = smb_xmalloc(sizeof(pstring));
	char *pw_shell = smb_xmalloc(sizeof(pstring));

	ZERO_STRUCTP(ret);

	/* 
	 * Now point the struct's members as the 
	 * newly allocated buffers:
	 */

	ret->pw_name = pw_name;
	fstrcpy(ret->pw_name, from->pw_name);

	ret->pw_passwd = pw_passwd;
	fstrcpy(ret->pw_passwd, from->pw_passwd);

	ret->pw_uid = from->pw_uid;
	ret->pw_gid = from->pw_gid;

	ret->pw_gecos = pw_gecos;
	fstrcpy(ret->pw_gecos, from->pw_gecos);

	ret->pw_dir = pw_dir;
	pstrcpy(ret->pw_dir, from->pw_dir);

	ret->pw_shell = pw_shell;
	pstrcpy(ret->pw_shell, from->pw_shell);

	return ret;
}

static struct passwd *alloc_copy_passwd(const struct passwd *from) 
{
	struct passwd *ret = smb_xmalloc(sizeof(struct passwd));
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

	temp = getpwnam(name);
	
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

	temp = getpwuid(uid);
	
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
