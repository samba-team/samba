/* 
   Unix SMB/CIFS implementation.
   client utility routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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
/*******************************************************************
 Functions nicked from lib/util.c needed by client.
*******************************************************************/

/*******************************************************************
 A wrapper that handles case sensitivity and the special handling
 of the ".." name.
*******************************************************************/

BOOL mask_match(struct smbcli_state *cli, const char *string, char *pattern, BOOL is_case_sensitive)
{
	fstring p2, s2;

	if (strcmp(string,"..") == 0)
		string = ".";
	if (strcmp(pattern,".") == 0)
		return False;
	
	if (is_case_sensitive)
		return ms_fnmatch(pattern, string, 
				  cli->transport->negotiate.protocol) == 0;

	fstrcpy(p2, pattern);
	fstrcpy(s2, string);
	strlower(p2); 
	strlower(s2);
	return ms_fnmatch(p2, s2, cli->transport->negotiate.protocol) == 0;
}

/****************************************************************************
 Put up a yes/no prompt.
****************************************************************************/

BOOL yesno(char *p)
{
	pstring ans;
	printf("%s",p);

	if (!fgets(ans,sizeof(ans)-1,stdin))
		return(False);

	if (*ans == 'y' || *ans == 'Y')
		return(True);

	return(False);
}

/*******************************************************************
  A readdir wrapper which just returns the file name.
 ********************************************************************/

const char *readdirname(DIR *p)
{
	struct smb_dirent *ptr;
	char *dname;

	if (!p)
		return(NULL);
  
	ptr = (struct smb_dirent *)sys_readdir(p);
	if (!ptr)
		return(NULL);

	dname = ptr->d_name;

#ifdef NEXT2
	if (telldir(p) < 0)
		return(NULL);
#endif

#ifdef HAVE_BROKEN_READDIR
	/* using /usr/ucb/cc is BAD */
	dname = dname - 2;
#endif

	{
		static pstring buf;
		int len = NAMLEN(ptr);
		memcpy(buf, dname, len);
		buf[len] = 0;
		dname = buf;
	}

	return(dname);
}
