/*
   Unix SMB/CIFS implementation.
   Samba utility functions, used in smbd only
   Copyright (C) Andrew Tridgell 2002

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

/* 
   This function requires sys_getgrouplist - which is only
   available in smbd due to it's use of become_root() in a 
   legacy systems hack.
*/

/*
  return a full list of groups for a user

  returns the number of groups the user is a member of. The return will include the
  users primary group.

  remember to free the resulting gid_t array

  NOTE! uses become_root() to gain correct priviages on systems
  that lack a native getgroups() call (uses initgroups and getgroups)
*/
int getgroups_user(const char *user, gid_t **groups)
{
	struct passwd *pwd;
	int ngrp, max_grp;

	pwd = getpwnam_alloc(user);
	if (!pwd) return -1;

	max_grp = groups_max();
	(*groups) = (gid_t *)malloc(sizeof(gid_t) * max_grp);
	if (! *groups) {
		passwd_free(&pwd);
		errno = ENOMEM;
		return -1;
	}

	ngrp = sys_getgrouplist(user, pwd->pw_gid, *groups, &max_grp);
	if (ngrp <= 0) {
		passwd_free(&pwd);
		free(*groups);
		return ngrp;
	}

	passwd_free(&pwd);
	return ngrp;
}

BOOL mask_match_smbd(const char *string, char *pattern,
		     BOOL is_case_sensitive)
{
	extern int Protocol;
	fstring p2, s2;

	if (strcmp(string,"..") == 0)
		string = ".";
	if (strcmp(pattern,".") == 0)
		return False;
	
	if (is_case_sensitive)
		return ms_fnmatch(pattern, string, Protocol) == 0;

	fstrcpy(p2, pattern);
	fstrcpy(s2, string);
	strlower(p2); 
	strlower(s2);
	return ms_fnmatch(p2, s2, Protocol) == 0;
}

void srv_set_signing_negotiated(void)
{
	DEBUG(0, ("TODO: server signing implementation\n"));
}

BOOL srv_signing_started(void)
{
	DEBUG(0, ("TODO: server signing implementation\n"));
	return False;
}

BOOL srv_check_sign_mac(char *inbuf, BOOL must_be_ok)
{
	DEBUG(1, ("TODO: server signing implementation\n"));
	return True;
}

void srv_signing_trans_start(uint16 mid)
{
	DEBUG(1, ("TODO: server signing implementation\n"));
}

void srv_signing_trans_stop(void)
{
	DEBUG(1, ("TODO: server signing implementation\n"));
}

void srv_defer_sign_response(uint16 mid)
{
	DEBUG(1, ("TODO: server signing implementation\n"));
}
	
/****************************************************************************
interprets an nt time into a unix time_t
****************************************************************************/
time_t interpret_long_date(char *p)
{
	NTTIME nt = BVAL(p, 0);
	return nt_time_to_unix(&nt);
}

/****************************************************************************
take a Unix time and convert to an NTTIME structure and place in buffer 
pointed to by p.
****************************************************************************/
void put_long_date(char *p,time_t t)
{
	NTTIME nt;
	unix_to_nt_time(&nt, t);
	SBVAL(p, 0, nt);
}

time_t get_create_time(SMB_STRUCT_STAT *st,BOOL fake_dirs)
{
	time_t ret, ret1;

	if(S_ISDIR(st->st_mode) && fake_dirs)
		return (time_t)315493200L;          /* 1/1/1980 */
    
	ret = MIN(st->st_ctime, st->st_mtime);
	ret1 = MIN(ret, st->st_atime);

	if(ret1 != (time_t)0)
		return ret1;

	/*
	 * One of ctime, mtime or atime was zero (probably atime).
	 * Just return MIN(ctime, mtime).
	 */
	return ret;
}

/****************************************************************************
 Map standard UNIX permissions onto wire representations.
****************************************************************************/

uint32  unix_perms_to_wire(mode_t perms)
{
        unsigned int ret = 0;

        ret |= ((perms & S_IXOTH) ?  UNIX_X_OTH : 0);
        ret |= ((perms & S_IWOTH) ?  UNIX_W_OTH : 0);
        ret |= ((perms & S_IROTH) ?  UNIX_R_OTH : 0);
        ret |= ((perms & S_IXGRP) ?  UNIX_X_GRP : 0);
        ret |= ((perms & S_IWGRP) ?  UNIX_W_GRP : 0);
        ret |= ((perms & S_IRGRP) ?  UNIX_R_GRP : 0);
        ret |= ((perms & S_IXUSR) ?  UNIX_X_USR : 0);
        ret |= ((perms & S_IWUSR) ?  UNIX_W_USR : 0);
        ret |= ((perms & S_IRUSR) ?  UNIX_R_USR : 0);
#ifdef S_ISVTX
        ret |= ((perms & S_ISVTX) ?  UNIX_STICKY : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & S_ISGID) ?  UNIX_SET_GID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & S_ISUID) ?  UNIX_SET_UID : 0);
#endif
        return ret;
}

/*******************************************************************
  create a unix date (int GMT) from a dos date (which is actually in
  localtime)
********************************************************************/
time_t make_unix_date(void *date_ptr)
{
	uint32 dos_date=0;
	struct tm t;
	time_t ret;

	dos_date = IVAL(date_ptr,0);

	if (dos_date == 0) return(0);
  
	interpret_dos_date(dos_date,&t.tm_year,&t.tm_mon,
			   &t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec);
	t.tm_isdst = -1;
  
	/* mktime() also does the local to GMT time conversion for us */
	ret = mktime(&t);

	return(ret);
}

/*******************************************************************
like make_unix_date() but the words are reversed
********************************************************************/
time_t make_unix_date2(void *date_ptr)
{
	uint32 x,x2;

	x = IVAL(date_ptr,0);
	x2 = ((x&0xFFFF)<<16) | ((x&0xFFFF0000)>>16);
	SIVAL(&x,0,x2);

	return(make_unix_date((void *)&x));
}
