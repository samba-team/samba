/* 
   Unix SMB/CIFS implementation.
   string substitution functions
   Copyright (C) Andrew Tridgell 1992-2000
   
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
#include "smb_server/smb_server.h"

/* oh bugger - I realy didn't want to have a top-level context
   anywhere, but until we change all lp_*() calls to take a context
   argument this is needed */
static struct substitute_context *sub;

void sub_set_context(struct substitute_context *subptr)
{
	sub = subptr;
}

/*
  setup a string in the negotiate structure, using alpha_strcpy with SAFE_NETBIOS_CHARS
*/
static void setup_string(char **dest, const char *str)
{
#define SAFE_NETBIOS_CHARS ". -_"
	char *s;

	s = strdup(str);
	if (!s) {
		return;
	}

	alpha_strcpy(s, str, SAFE_NETBIOS_CHARS, strlen(s)+1);

	trim_string(s," "," ");
	strlower(s);

	SAFE_FREE(*dest);
	(*dest) = s;
}

void sub_set_remote_proto(const char *str)
{
	if (!sub) return;
	setup_string(&sub->remote_proto, str);
}

void sub_set_remote_arch(const char *str)
{
	if (!sub) return;
	setup_string(&sub->remote_arch, str);
}

/*
  setup the string used by %U substitution 
*/
void sub_set_user_name(const char *name)
{
	if (!sub) return;
	setup_string(&sub->user_name, name);
}

/****************************************************************************
FOO
****************************************************************************/
void standard_sub_basic(char *str,size_t len)
{
}

/****************************************************************************
 Do some standard substitutions in a string.
 This function will return an allocated string that have to be freed.
****************************************************************************/
char *talloc_sub_basic(TALLOC_CTX *mem_ctx, const char *smb_name, const char *str)
{
	return talloc_strdup(mem_ctx, str);
}

char *alloc_sub_basic(const char *smb_name, const char *str)
{
	return strdup(str);
}

/****************************************************************************
 Do some specific substitutions in a string.
 This function will return an allocated string that have to be freed.
****************************************************************************/

char *talloc_sub_specified(TALLOC_CTX *mem_ctx,
			const char *input_string,
			const char *username,
			const char *domain,
			uid_t uid,
			gid_t gid)
{
	return talloc_strdup(mem_ctx, input_string);
}

char *alloc_sub_specified(const char *input_string,
			const char *username,
			const char *domain,
			uid_t uid,
			gid_t gid)
{
	return strdup(input_string);
}

char *talloc_sub_advanced(TALLOC_CTX *mem_ctx,
			int snum,
			const char *user,
			const char *connectpath,
			gid_t gid,
			const char *smb_name,
			char *str)
{
	return talloc_strdup(mem_ctx, str);
}

char *alloc_sub_advanced(int snum, const char *user, 
				  const char *connectpath, gid_t gid, 
				  const char *smb_name, char *str)
{
	return strdup(str);
}

/****************************************************************************
 Do some standard substitutions in a string.
****************************************************************************/

void standard_sub_tcon(struct smbsrv_tcon *tcon, char *str, size_t len)
{
}

char *talloc_sub_tcon(TALLOC_CTX *mem_ctx, struct smbsrv_tcon *tcon, char *str)
{
	return talloc_strdup(mem_ctx, str);
}

char *alloc_sub_tcon(struct smbsrv_tcon *tcon, char *str)
{
	return strdup(str);
}

/****************************************************************************
 Like standard_sub but by snum.
****************************************************************************/

void standard_sub_snum(int snum, char *str, size_t len)
{
}
