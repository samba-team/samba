
/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP domain group database for SAMBA
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
#include "sids.h"

extern int DEBUGLEVEL;

/* Static structure filled for requests */
static DOMAIN_GRP domgrp;

/***************************************************************
  Begin/end domain group enumeration.
 ****************************************************************/

static void *
nt5ldapgroup_enumfirst (BOOL update)
{
	fstring filter;
	int server_role = lp_server_role ();
	LDAPDB_DECLARE_HANDLE (hds);

	if (server_role == ROLE_DOMAIN_NONE ||
	    server_role == ROLE_DOMAIN_MEMBER)
	{
		return NULL;
	}

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	slprintf (filter, sizeof (filter) - 1, "(&(objectClass=Group)(groupType=%d))",
	   NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, LDAP_NO_LIMIT))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	return hds;
}

static void 
nt5ldapgroup_enumclose (void *vp)
{
	LDAPDB *hds = (LDAPDB *) vp;

	ldapdb_close (&hds);

	return;
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT 
nt5ldapgroup_getdbpos (void *vp)
{
	return 0;
}

static BOOL 
nt5ldapgroup_setdbpos (void *vp, SMB_BIG_UINT tok)
{
	return False;
}


/*************************************************************************
  Return information about domain groups and their members.
 *************************************************************************/

static DOMAIN_GRP *
nt5ldapgroup_getgrpbynam (const char *name,
			  DOMAIN_GRP_MEMBER ** members, int *num_membs)
{
	fstring filter;
	BOOL ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	slprintf (filter, sizeof (filter) - 1,
	    "(&(objectClass=Group)(sAMAccountName=%s)(groupType=%d))", name,
	   NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, 1))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldap_make_domain_grp (hds, &domgrp, members, num_membs);

	ldapdb_close (&hds);

	return ret ? &domgrp : NULL;
}

static DOMAIN_GRP *
nt5ldapgroup_getgrpbygid (gid_t grp_id,
			  DOMAIN_GRP_MEMBER ** members, int *num_membs)
{
	fstring filter;
	BOOL ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	slprintf (filter, sizeof (filter) - 1,
	       "(&(objectClass=Group)(gidNumber=%d)(groupType=%d))", grp_id,
	   NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, 1))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldap_make_domain_grp (hds, &domgrp, members, num_membs);

	ldapdb_close (&hds);

	return ret ? &domgrp : NULL;
}

static DOMAIN_GRP *
nt5ldapgroup_getgrpbyrid (uint32 grp_rid,
			  DOMAIN_GRP_MEMBER ** members, int *num_membs)
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
	   NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	if (!ldapdb_search (hds, NULL, filter, NULL, 1))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldap_make_domain_grp (hds, &domgrp, members, num_membs);

	ldapdb_close (&hds);

	return ret ? &domgrp : NULL;
}

static DOMAIN_GRP *
nt5ldapgroup_getcurrentgrp (void *vp,
			    DOMAIN_GRP_MEMBER ** members, int *num_membs)
{
	BOOL ret = False;

	do
	{
		if ((ret = nt5ldap_make_domain_grp ((LDAPDB *)vp, &domgrp, members, num_membs)))
			break;
	}
	while (ldapdb_seq((LDAPDB *)vp) == True);

	return ret ? &domgrp : NULL;
}


/*************************************************************************
  Add/modify/delete domain groups.
 *************************************************************************/

static BOOL 
nt5ldapgroup_addgrp (DOMAIN_GRP * group)
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
		ldapdb_close (&hds);
		return False;
	}

	if (!nt5ldap_domain_grp_mods (group, &mods, LDAP_MOD_ADD))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_update (hds, lp_ldap_users_subcontext (), "cn", group->name, mods, True);
	}

	ldapdb_close (&hds);

	return ret;
}

static BOOL 
nt5ldapgroup_modgrp (DOMAIN_GRP * group)
{
	LDAPMod **mods = NULL;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!nt5ldap_domain_grp_mods (group, &mods, LDAP_MOD_REPLACE))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_update (hds, lp_ldap_users_subcontext (), "cn", group->name, mods, False);
	}

	ldapdb_close (&hds);

	return ret;
}

static BOOL 
nt5ldapgroup_delgrp (uint32 grp_rid)
{
	LDAPDB_DECLARE_HANDLE (hds);
	pstring dn;
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
  Add users to/remove users from groups.
 *************************************************************************/

static BOOL 
nt5ldapgroup_addmem (uint32 grp_rid, uint32 user_rid)
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

	if (!nt5ldap_domain_grp_member_mods (user_rid, &mods, LDAP_MOD_ADD, userdn))
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
nt5ldapgroup_delmem (uint32 grp_rid, uint32 user_rid)
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

	if (!nt5ldap_domain_grp_member_mods (user_rid, &mods, LDAP_MOD_DELETE, userdn))
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
		ret = ldapdb_lookup_by_rid (hds, user_rid) &&
			ldapdb_queue_mod (&mods, LDAP_MOD_DELETE, "memberOf", groupdn) &&
			ldapdb_commit (hds, userdn, mods, False);
	}

	ldapdb_close (&hds);

	return ret;
}


/*************************************************************************
  Return domain groups that a user is in.
 *************************************************************************/

static BOOL 
nt5ldapgroup_getusergroups (const char *name, DOMAIN_GRP ** groups,
			    int *num_grps)
{
	DOMAIN_GRP *grouplist;
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

	slprintf (filter, sizeof (pstring) - 1, "(&(objectClass=Group)(member=%s)(groupType=%d))",
	dn, NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
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

	grouplist = calloc (ngroups, sizeof (DOMAIN_GRP));
	if (grouplist == NULL)
	{
		ldapdb_close (&hds);
		return False;
	}
	*num_grps = 0;

	for (i = 0; i < ngroups; i++)
	{
		if (nt5ldap_make_domain_grp (hds, &grouplist[*num_grps], NULL, NULL))
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

static struct groupdb_ops nt5ldapgroup_ops =
{
	nt5ldapgroup_enumfirst,
	nt5ldapgroup_enumclose,
	nt5ldapgroup_getdbpos,
	nt5ldapgroup_setdbpos,

	nt5ldapgroup_getgrpbynam,
	nt5ldapgroup_getgrpbygid,
	nt5ldapgroup_getgrpbyrid,
	nt5ldapgroup_getcurrentgrp,

	nt5ldapgroup_addgrp,
	nt5ldapgroup_modgrp,
	nt5ldapgroup_delgrp,

	nt5ldapgroup_addmem,
	nt5ldapgroup_delmem,

	nt5ldapgroup_getusergroups
};

struct groupdb_ops *
nt5ldap_initialise_group_db (void)
{
	return &nt5ldapgroup_ops;
}

#else
void groupldap_dummy_function (void);
void 
groupldap_dummy_function (void)
{
}				/* stop some compilers complaining */
#endif
