/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
      
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
#include "nterr.h"

extern int DEBUGLEVEL;

/*
 * NOTE. All these functions are abstracted into a structure
 * that points to the correct function for the selected database. JRA.
 *
 * the API does NOT fill in the gaps if you set an API function
 * to NULL: it will deliberately attempt to call the NULL function.
 *
 */

static struct passgrp_ops *pwgrp_ops = NULL;

/***************************************************************
 Initialise the passgrp operations.
***************************************************************/

BOOL initialise_passgrp_db(void)
{
  if (pwgrp_ops)
  {
    return True;
  }

#ifdef WITH_NISPLUS
  pwgrp_ops =  nisplus_initialise_password_grp();
#elif defined(WITH_NT5LDAP)
  pwgrp_ops = nt5ldap_initialise_password_grp();
#elif defined(WITH_LDAP)
  pwgrp_ops = ldap_initialise_password_grp();
#elif defined(USE_SMBUNIX_DB)
  pwgrp_ops = unix_initialise_password_grp();
#elif defined(USE_SMBPASS_DB)
  pwgrp_ops = file_initialise_password_grp();
#endif 

  return (pwgrp_ops != NULL);
}

/*
 * Functions that return/manipulate a struct smb_passwd.
 */

/************************************************************************
 Utility function to search smb passwd by rid.  
*************************************************************************/

struct smb_passwd *iterate_getsmbgrprid(uint32 user_rid,
		uint32 **grps, int *num_grps,
		uint32 **alss, int *num_alss)
{
	struct smb_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by user_rid: 0x%x\n", user_rid));

	/* Open the smb password database - not for update. */
	fp = startsmbgrpent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open smb passgrp database.\n"));
		return NULL;
	}

	while ((pwd = getsmbgrpent(fp, grps, num_grps, alss, num_alss)) != NULL && pwd->user_rid != user_rid)
      ;

	if (pwd != NULL)
	{
		DEBUG(10, ("found by user_rid: 0x%x\n", user_rid));
	}

	endsmbgrpent(fp);
	return pwd;
}

/************************************************************************
 Utility function to search smb passwd by uid.  use this if your database
 does not have search facilities.
*************************************************************************/

struct smb_passwd *iterate_getsmbgrpuid(uid_t unix_uid,
		uint32 **grps, int *num_grps,
		uint32 **alss, int *num_alss)
{
	struct smb_passwd *pwd = NULL;
	void *fp = NULL;

	DEBUG(10, ("search by unix_uid: %x\n", (int)unix_uid));

	/* Open the smb password database - not for update. */
	fp = startsmbgrpent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open smb passgrp database.\n"));
		return NULL;
	}

	while ((pwd = getsmbgrpent(fp, grps, num_grps, alss, num_alss)) != NULL && pwd->unix_uid != unix_uid)
      ;

	if (pwd != NULL)
	{
		DEBUG(10, ("found by unix_uid: %x\n", (int)unix_uid));
	}

	endsmbgrpent(fp);
	return pwd;
}

/************************************************************************
 Utility function to search smb passwd by name.  use this if your database
 does not have search facilities.
*************************************************************************/

struct smb_passwd *iterate_getsmbgrpntnam(const char *nt_name,
		uint32 **grps, int *num_grps,
		uint32 **alss, int *num_alss)
{
	struct smb_passwd *pwd = NULL;
	fstring name;
	void *fp = NULL;
	fstrcpy(name, nt_name);

	DEBUG(10, ("search by name: %s\n", name));

	/* Open the passgrp file - not for update. */
	fp = startsmbgrpent(False);

	if (fp == NULL)
	{
		DEBUG(0, ("unable to open smb passgrp database.\n"));
		return NULL;
	}

	while ((pwd = getsmbgrpent(fp, grps, num_grps, alss, num_alss)) != NULL && !strequal(pwd->nt_name, name))
      ;

	if (pwd != NULL)
	{
		DEBUG(10, ("found by name: %s\n", name));
	}

	endsmbgrpent(fp);
	return pwd;
}

/***************************************************************
 Start to enumerate the smb or sam passwd list. Returns a void pointer
 to ensure no modification outside this module.

 Note that currently it is being assumed that a pointer returned
 from this function may be used to enumerate struct sam_passwd
 entries as well as struct smb_passwd entries. This may need
 to change. JRA.

****************************************************************/

void *startsmbgrpent(BOOL update)
{
  return pwgrp_ops->startsmbgrpent(update);
}

/***************************************************************
 End enumeration of the smb or sam passwd list.

 Note that currently it is being assumed that a pointer returned
 from this function may be used to enumerate struct sam_passwd
 entries as well as struct smb_passwd entries. This may need
 to change. JRA.

****************************************************************/

void endsmbgrpent(void *vp)
{
  pwgrp_ops->endsmbgrpent(vp);
}

/*************************************************************************
 Routine to return the next entry in the smb passwd list.
 *************************************************************************/

struct smb_passwd *getsmbgrpent(void *vp,
		uint32 **grps, int *num_grps,
		uint32 **alss, int *num_alss)
{
	return pwgrp_ops->getsmbgrpent(vp, grps, num_grps, alss, num_alss);
}

/************************************************************************
 Routine to search smb passwd by name.
*************************************************************************/

struct smb_passwd *getsmbgrpntnam(char *name,
		uint32 **grps, int *num_grps,
		uint32 **alss, int *num_alss)
{
	return pwgrp_ops->getsmbgrpntnam(name, grps, num_grps, alss, num_alss);
}

/************************************************************************
 Routine to search smb passwd by user rid.
*************************************************************************/

struct smb_passwd *getsmbgrprid(uint32 user_rid,
		uint32 **grps, int *num_grps,
		uint32 **alss, int *num_alss)
{
	return pwgrp_ops->getsmbgrprid(user_rid, grps, num_grps, alss, num_alss);
}

/************************************************************************
 Routine to search smb passwd by uid.
*************************************************************************/

struct smb_passwd *getsmbgrpuid(uid_t unix_uid,
		uint32 **grps, int *num_grps,
		uint32 **alss, int *num_alss)
{
	return pwgrp_ops->getsmbgrpuid(unix_uid, grps, num_grps, alss, num_alss);
}

