
/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP builtin group database for SAMBA
   Copyright (C) Matthew Chapman 1998
   Copyright (C) Luke Howard 2000

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
#include "sids.h"

extern int DEBUGLEVEL;

/* Static structure filled for requests */
static LOCAL_GRP localgrp;


/***************************************************************
  Begin/end smbgrp enumeration.
 ****************************************************************/

static void *
nt5ldapbuiltin_enumfirst (BOOL update)
{
	LDAPDB_DECLARE_HANDLE (hds);
	fstring filter;

	if (lp_server_role () == ROLE_DOMAIN_NONE)
		return NULL;

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	slprintf (filter, sizeof (filter) - 1, "(&(objectClass=Group)(groupType=%d))",
		  NTDS_GROUP_TYPE_BUILTIN_GROUP | NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, LDAP_NO_LIMIT))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	return hds;
}

static void 
nt5ldapbuiltin_enumclose (void *vp)
{
	LDAPDB *hds = (LDAPDB *) vp;

	ldapdb_close (&hds);
	return;
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT 
nt5ldapbuiltin_getdbpos (void *vp)
{
	return 0;
}

static BOOL 
nt5ldapbuiltin_setdbpos (void *vp, SMB_BIG_UINT tok)
{
	return False;
}


/*************************************************************************
  Return limited smb_passwd information, and group membership.
 *************************************************************************/

static LOCAL_GRP *
nt5ldapbuiltin_getgrpbynam (const char *name,
			    LOCAL_GRP_MEMBER ** members, int *num_membs)
{
	fstring filter;
	BOOL ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return (NULL);
	}

	slprintf (filter, sizeof (filter) - 1,
	    "(&(objectClass=Group)(sAMAccountName=%s)(groupType=%d))", name,
		  NTDS_GROUP_TYPE_BUILTIN_GROUP | NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, 1))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldap_make_local_grp (hds, &localgrp, members, num_membs, NTDS_GROUP_TYPE_BUILTIN_GROUP);

	ldapdb_close (&hds);

	return ret ? &localgrp : NULL;
}

static LOCAL_GRP *
nt5ldapbuiltin_getgrpbygid (gid_t grp_id,
			    LOCAL_GRP_MEMBER ** members, int *num_membs)
{
	fstring filter;
	BOOL ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return (NULL);
	}

	slprintf (filter, sizeof (filter) - 1,
	       "(&(objectClass=Group)(gidNumber=%d)(groupType=%d))", grp_id,
		  NTDS_GROUP_TYPE_BUILTIN_GROUP | NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, 1))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldap_make_local_grp (hds, &localgrp, members, num_membs, NTDS_GROUP_TYPE_BUILTIN_GROUP);

	ldapdb_close (&hds);

	return ret ? &localgrp : NULL;
}

static LOCAL_GRP *
nt5ldapbuiltin_getgrpbyrid (uint32 grp_rid,
			    LOCAL_GRP_MEMBER ** members, int *num_membs)
{
	fstring filter;
	fstring sidfilter;
	BOOL ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_make_rid_filter ("objectSid", grp_rid, sidfilter))
	{
		return NULL;
	}

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	slprintf (filter, sizeof (filter) - 1,
		  "(&(objectClass=Group)(%s)(groupType=%d))", sidfilter,
		  NTDS_GROUP_TYPE_BUILTIN_GROUP | NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, 1))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldap_make_local_grp (hds, &localgrp, members, num_membs, NTDS_GROUP_TYPE_BUILTIN_GROUP);

	ldapdb_close (&hds);

	return ret ? &localgrp : NULL;
}

static LOCAL_GRP *
nt5ldapbuiltin_getcurrentgrp (void *vp,
			      LOCAL_GRP_MEMBER ** members, int *num_membs)
{
	BOOL ret = False;

	do
	{
		if ((ret = nt5ldap_make_local_grp ((LDAPDB *)vp, &localgrp, members, num_membs, NTDS_GROUP_TYPE_BUILTIN_GROUP)))
			break;
	}
	while (ldapdb_seq((LDAPDB *)vp) == True);

	return ret ? &localgrp : NULL;
}


/*************************************************************************
  Add/modify/delete builtin aliases.
 *************************************************************************/

static BOOL 
nt5ldapbuiltin_addgrp (LOCAL_GRP * group)
{
	LDAPMod **mods = NULL;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!ldapdb_allocate_rid (hds, &group->rid))
	{
		DEBUG (0, ("RID generation failed\n"));
		return False;
	}

	if (!nt5ldap_local_grp_mods (group, &mods, LDAP_MOD_ADD, NTDS_GROUP_TYPE_BUILTIN_GROUP))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_update (hds, lp_ldap_builtin_subcontext (), "cn", group->name, mods, True);
	}

	ldapdb_close (&hds);

	return ret;
}

static BOOL 
nt5ldapbuiltin_modgrp (LOCAL_GRP * group)
{
	LDAPMod **mods = NULL;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!nt5ldap_local_grp_mods (group, &mods, LDAP_MOD_REPLACE, NTDS_GROUP_TYPE_BUILTIN_GROUP))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_update (hds, lp_ldap_builtin_subcontext (), "cn", group->name, mods, False);
	}

	ldapdb_close (&hds);

	return ret;
}

static BOOL 
nt5ldapbuiltin_delgrp (uint32 grp_rid)
{
	pstring dn;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!ldapdb_rid_to_dn (hds, grp_rid, dn))
	{
		ldapdb_close (&hds);
		return False;
	}

	ret = ldapdb_delete (hds, dn);

	ldapdb_close (&hds);

	return ret;
}


/*************************************************************************
  Add users to/remove users from aliases.
 *************************************************************************/

static BOOL 
nt5ldapbuiltin_addmem (uint32 grp_rid, const DOM_SID * user_sid)
{
	LDAPMod **mods = NULL;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;
	pstring userdn, groupdn;

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!ldapdb_rid_to_dn (hds, grp_rid, groupdn))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (!nt5ldap_local_grp_member_mods (user_sid, &mods, LDAP_MOD_ADD, userdn))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_commit (hds, groupdn, mods, False);
	}

	if (ret == True)
	{
		mods = NULL;
		ret = ldapdb_queue_mod (&mods, LDAP_MOD_ADD, "memberOf", groupdn) &&
			ldapdb_commit (hds, userdn, mods, False);
	}

	ldapdb_close (&hds);

	return ret;
}

static BOOL 
nt5ldapbuiltin_delmem (uint32 grp_rid, const DOM_SID * user_sid)
{
	LDAPMod **mods = NULL;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;
	pstring userdn, groupdn;

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!ldapdb_rid_to_dn (hds, grp_rid, groupdn))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (!nt5ldap_local_grp_member_mods (user_sid, &mods, LDAP_MOD_DELETE, userdn))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_commit (hds, groupdn, mods, False);
	}

	if (ret == True)
	{
		mods = NULL;
		ret = ldapdb_queue_mod (&mods, LDAP_MOD_DELETE, "memberOf", groupdn) &&
			ldapdb_commit (hds, userdn, mods, False);
	}

	ldapdb_close (&hds);

	return ret;
}


/*************************************************************************
  Return builtin aliases that a user is in.
 *************************************************************************/

static BOOL 
nt5ldapbuiltin_getusergroups (const char *name, LOCAL_GRP ** groups,
			      int *num_grps)
{
	LOCAL_GRP *grouplist;
	fstring filter;
	int i, ngroups;
	pstring dn;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!ldapdb_ntname_to_dn (hds, name, dn))
	{
		ldapdb_close (&hds);
		return False;
	}

	slprintf (filter, sizeof (pstring) - 1, "(&(objectclass=Group)(member=%s)(groupType=%d))", dn,
		  NTDS_GROUP_TYPE_BUILTIN_GROUP | NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);

	(void) ldapdb_set_synchronous (hds, True);
	if (!ldapdb_search (hds, NULL, filter, NULL, LDAP_NO_LIMIT))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (!ldapdb_count_entries (hds, &ngroups))
	{
		ldapdb_close (&hds);
		return False;
	}

	grouplist = calloc (ngroups, sizeof (LOCAL_GRP));
	if (grouplist == NULL)
	{
		ldapdb_close (&hds);
		return False;
	}

	*num_grps = 0;

	for (i = 0; i < ngroups; i++)
	{
		if (nt5ldap_make_local_grp (hds, &grouplist[*num_grps], NULL, NULL, NTDS_GROUP_TYPE_BUILTIN_GROUP))
		{
			(*num_grps)++;
		}
		if (!ldapdb_seq (hds))
		{
			break;
		}
	}

	ldapdb_close (&hds);

	*groups = grouplist;

	return True;
}


static struct aliasdb_ops nt5ldapbuiltin_ops =
{
	nt5ldapbuiltin_enumfirst,
	nt5ldapbuiltin_enumclose,
	nt5ldapbuiltin_getdbpos,
	nt5ldapbuiltin_setdbpos,

	nt5ldapbuiltin_getgrpbynam,
	nt5ldapbuiltin_getgrpbygid,
	nt5ldapbuiltin_getgrpbyrid,
	nt5ldapbuiltin_getcurrentgrp,

	nt5ldapbuiltin_addgrp,
	nt5ldapbuiltin_modgrp,
	nt5ldapbuiltin_delgrp,

	nt5ldapbuiltin_addmem,
	nt5ldapbuiltin_delmem,

	nt5ldapbuiltin_getusergroups
};

struct aliasdb_ops *
nt5ldap_initialise_builtin_db (void)
{
	return &nt5ldapbuiltin_ops;
}

#else
void builtinnt5ldap_dummy_function (void);
void 
builtinnt5ldap_dummy_function (void)
{
}				/* stop some compilers complaining */
#endif
