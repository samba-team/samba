
/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP passgrp database for SAMBA
   Copyright (C) Matthew Chapman 1998

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

#ifdef WITH_NT5LDAP

#include <lber.h>
#include <ldap.h>
#include "ldapdb.h"

extern int DEBUGLEVEL;

/***************************************************************
  Begin/end smbgrp enumeration.
 ****************************************************************/

static void *
nt5ldappassgrp_enumfirst (BOOL update)
{
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_search (hds, NULL, "(objectclass=User)", NULL, LDAP_NO_LIMIT))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	return hds;
}

static void 
nt5ldappassgrp_enumclose (void *vp)
{
	LDAPDB *hds = (LDAPDB *) vp;

	ldapdb_close (&hds);

	return;
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT 
nt5ldappassgrp_getdbpos (void *vp)
{
	return 0;
}

static BOOL 
nt5ldappassgrp_setdbpos (void *vp, SMB_BIG_UINT tok)
{
	return False;
}


/*************************************************************************
  Return limited smb_passwd information, and group membership.
 *************************************************************************/

static struct smb_passwd *
nt5ldappassgrp_getpwbynam (const char *name,
			   uint32 ** grp_rids, int *num_grps,
			   uint32 ** als_rids, int *num_alss)
{
	struct smb_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);
	char *dn;

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_posix_name (hds, name) ||
	    !ldapdb_get_dn (hds, &dn))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsmb_getent (hds);

	(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_GLOBAL_GROUP);
	(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP);

	free (dn);
	ldapdb_close (&hds);

	return ret;
}

static struct smb_passwd *
nt5ldappassgrp_getpwbyuid (uid_t userid,
			   uint32 ** grp_rids, int *num_grps,
			   uint32 ** als_rids, int *num_alss)
{
	struct smb_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);
	char *dn;

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_posix_uid (hds, userid) ||
	    !ldapdb_get_dn (hds, &dn))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsmb_getent (hds);

	(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_GLOBAL_GROUP);
	(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP);

	free (dn);
	ldapdb_close (&hds);

	return ret;
}

static struct smb_passwd *
nt5ldappassgrp_getpwbyrid (uint32 user_rid,
			   uint32 ** grp_rids, int *num_grps,
			   uint32 ** als_rids, int *num_alss)
{
	struct smb_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);
	char *dn;

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_rid (hds, user_rid) ||
	    !ldapdb_get_dn (hds, &dn))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsmb_getent (hds);

	(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_GLOBAL_GROUP);
	(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP);

	free (dn);
	ldapdb_close (&hds);

	return ret;
}

static struct smb_passwd *
nt5ldappassgrp_getcurrentpw (void *vp,
			     uint32 ** grp_rids, int *num_grps,
			     uint32 ** als_rids, int *num_alss)
{
	struct smb_passwd *ret = NULL;
	LDAPDB_DECLARE_HANDLE (hds);
	char *dn = NULL;

	hds = (LDAPDB *) vp;

	do
	{
		if (dn != NULL)
			free (dn);

		if (	ldapdb_peek (hds) == True &&
			ldapdb_get_dn (hds, &dn) == True &&
			((ret = nt5ldapsmb_getent (hds)) != NULL))
		{
			/* Got the entry */
			(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_GLOBAL_GROUP);
			(void) nt5ldap_make_group_rids (hds, dn, grp_rids, num_grps, NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP);
			break;
		}
	}
	while (ldapdb_seq(hds) == True);

	return ret;
}



static struct passgrp_ops nt5ldappassgrp_ops =
{
	nt5ldappassgrp_enumfirst,
	nt5ldappassgrp_enumclose,
	nt5ldappassgrp_getdbpos,
	nt5ldappassgrp_setdbpos,

	nt5ldappassgrp_getpwbynam,
	nt5ldappassgrp_getpwbyuid,
	nt5ldappassgrp_getpwbyrid,
	nt5ldappassgrp_getcurrentpw,
};

struct passgrp_ops *
nt5ldap_initialise_password_grp (void)
{
	return &nt5ldappassgrp_ops;
}

#else
void passgrpnt5ldap_dummy_function (void);
void 
passgrpnt5ldap_dummy_function (void)
{
}				/* stop some compilers complaining */
#endif
