/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * Copyright (C) Benny Holmgren 1998 <bigfoot@astrakan.hgs.se> 
 * Copyright (C) Luke Kenneth Casson Leighton 1996-1998.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef NISPLUS

#include "includes.h"

extern int      DEBUGLEVEL;

#include <rpcsvc/nis.h>


static int gotalarm;

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig(void)
{
  gotalarm = 1;
}

/***************************************************************
 Start to enumerate the nisplus passwd list. Returns a void pointer
 to ensure no modification outside this module.

 do not call this function directly.  use passdb.c instead.

 ****************************************************************/
void *startnisppwent(BOOL update)
{
}

/***************************************************************
 End enumeration of the nisplus passwd list.
****************************************************************/
void endnisppwent(void *vp)
{
}

/*************************************************************************
 Routine to return the next entry in the nisplus passwd list.
 this function is a nice, messy combination of reading:
 - the nisplus passwd file
 - the unix password database
 - nisp.conf options (not done at present).

 do not call this function directly.  use passdb.c instead.

 *************************************************************************/
struct sam_passwd *getnisp21pwent(void *vp)
{
}

/*************************************************************************
 Routine to return the next entry in the nisplus passwd list.

 do not call this function directly.  use passdb.c instead.

 *************************************************************************/
struct smb_passwd *getnisppwent(void *vp)
{
	DEBUG(5,("getnisppwent: end of file reached.\n"));
	return NULL;
}

/*************************************************************************
 Return the current position in the nisplus passwd list as an unsigned long.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
unsigned long getnisppwpos(void *vp)
{
	return 0;
}

/*************************************************************************
 Set the current position in the nisplus passwd list from unsigned long.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
BOOL setnisppwpos(void *vp, unsigned long tok)
{
	return False;
}

/************************************************************************
 Routine to add an entry to the nisplus passwd file.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
BOOL add_nisppwd_entry(struct smb_passwd *newpwd)
{
	return False;
}

/************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username.
 and then modify its password entry. We can't use the startnisppwent()/
 getnisppwent()/endnisppwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS

 do not call this function directly.  use passdb.c instead.

************************************************************************/
BOOL mod_nisppwd_entry(struct smb_passwd* pwd, BOOL override)
{
	return False;
}
 
/************************************************************************
 makes a struct smb_passwd from a NIS+ result.
 ************************************************************************/
BOOL make_smb_from_nisp(struct smb_passwd *pw_buf, nis_result *result)
{
	int uidval;
	static pstring  user_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];

	if (pw_buf == NULL || result == NULL) return False;

	bzero(pw_buf, sizeof(*pw_buf));

	if (result->status != NIS_SUCCESS)
	{
		DEBUG(0, ("make_smb_from_nisp: %s: NIS+ lookup failure: %s\n",
		           nisname, nis_sperrno(result->status)));
		return False;
	}

	/* User not found. */
	if (NIS_RES_NUMOBJ(result) <= 0)
	{
		DEBUG(10, ("make_smb_from_nisp: %s not found in NIS+\n", nisname));
		return False;
	}

	if (NIS_RES_NUMOBJ(result) > 1)
	{
		DEBUG(10, ("make_smb_from_nisp: WARNING: Multiple entries for %s in NIS+ table!\n", nisname));
	}

	/* Grab the first hit. */
	obj = &NIS_RES_OBJECT(result)[0];

	/* Check the lanman password column. */
	p = (uchar *)ENTRY_VAL(obj, 2);
	if (strlen((char *)p) != 32 || !gethexpwd((char *)p, (char *)smbpwd))
	{
		DEBUG(0, ("make_smb_from_nisp: malformed LM pwd entry.\n"));
		return False;
	}

	/* Check the NT password column. */
	p = (uchar *)ENTRY_VAL(obj, 3);
	if (strlen((char *)p) != 32 || !gethexpwd((char *)p, (char *)smbntpwd))
	{
		DEBUG(0, ("make_smb_from_nisp: malformed NT pwd entry\n"));
		return False;
	}

	strncpy(user_name, ENTRY_VAL(obj, 0), sizeof(user_name));
	uidval = atoi(ENTRY_VAL(obj, 1));

	pw_buf->smb_name      = user_name;
	pw_buf->smb_userid    = uidval;		
	pw_buf->smb_passwd    = smbpwd;
	pw_buf->smb_nt_passwd = smbntpwd;

	return True;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
struct smb_passwd *getnisppwnam(char *name)
{
	/* Static buffers we will return. */
	static struct smb_passwd pw_buf;
	char            linebuf[256];
	char            readbuf[16 * 1024];
	unsigned char   c;
	unsigned char  *p;
	long            uidval;
	long            linebuf_len;
	FILE           *fp;
	int             lockfd;
	char           *pfile = lp_smb_passwd_file();
	nis_result *result;
	nis_object *obj;
	char *nisname, *nisnamefmt;
	BOOL ret;

	if (!*pfile)
	{
		DEBUG(0, ("No SMB password file set\n"));
		return (NULL);
	}

	DEBUG(10, ("getnisppwnam: search by name: %s\n", name));
	DEBUG(10, ("getnisppwnam: using NIS+ table %s\n", pfile));

	nisnamefmt = "[name=%s],%s";
	nisname = (char *)malloc(strlen(nisnamefmt) + strlen(pfile) + strlen(name));

	if (!nisname)
	{
		DEBUG(0,("getnisppwnam: Can't allocate nisname"));
		return NULL;
	}

	safe_sprintf(nisname, nisnamefmt, name, pfile);

	/* Search the table. */
	gotalarm = 0;
	signal(SIGALRM, SIGNAL_CAST gotalarm_sig);
	alarm(5);

	result = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);
	free(nisname);

	alarm(0);
	signal(SIGALRM, SIGNAL_CAST SIG_DFL);

	if (gotalarm)
	{
		DEBUG(0,("getnisppwnam: NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	}

	ret = make_smb_from_nisp(&pw_buf, result);
	nis_freeresult(result);

	return ret ? &pw_buf : NULL;
}

/*************************************************************************
 Routine to search the nisplus passwd file for an entry matching the username
 *************************************************************************/
struct smb_passwd *getnisppwnam(int uid)
{
	/* Static buffers we will return. */
	static struct smb_passwd pw_buf;
	char            linebuf[256];
	char            readbuf[16 * 1024];
	unsigned char   c;
	unsigned char  *p;
	long            linebuf_len;
	FILE           *fp;
	int             lockfd;
	char           *pfile = lp_smb_passwd_file();
	nis_result *result;
	nis_object *obj;
	char *nisname, *nisnamefmt;

	if (!*pfile)
	{
		DEBUG(0, ("No SMB password file set\n"));
		return NULL;
	}

	DEBUG(10, ("getnisppwuid: search by uid: %d\n", uid));
	DEBUG(10, ("getnisppwuid: using NIS+ table %s\n", pfile));

	nisnamefmt = "[uid=%d],%s";
	nisname = (char *)malloc(strlen(nisnamefmt) + strlen(pfile)+ sizeof(smb_userid));

	if (!nisname)
	{
		DEBUG(0,("getnisppwuid: Can't allocate nisname"));
		return NULL;
	}

	safe_sprintf(nisname, nisnamefmt, smb_userid, pfile);

	/* Search the table. */
	gotalarm = 0;
	signal(SIGALRM, SIGNAL_CAST gotalarm_sig);
	alarm(5);

	result = nis_list(nisname, FOLLOW_PATH | EXPAND_NAME | HARD_LOOKUP, NULL, NULL);
	free(nisname);

	alarm(0);
	signal(SIGALRM, SIGNAL_CAST SIG_DFL);

	if (gotalarm)
	{
		DEBUG(0,("getnisppwuid: NIS+ lookup time out\n"));
		nis_freeresult(result);
		return NULL;
	}

	ret = make_smb_from_nisp(&pw_buf, result);
	nis_freeresult(result);

	return ret ? &pw_buf : NULL;
}

#else
static void dummy_function(void) { } /* stop some compilers complaining */
#endif /* NISPLUS */
