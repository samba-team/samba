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

#ifdef WITH_LDAP

#include <lber.h>
#include <ldap.h>

extern int DEBUGLEVEL;

/* Internal state */
extern LDAP *ldap_struct;
extern LDAPMessage *ldap_results;
extern LDAPMessage *ldap_entry;

/* Static structure filled for requests */
static DOMAIN_GRP domgrp;


/***************************************************************
  Get group and membership information.
 ****************************************************************/

static DOMAIN_GRP *ldapgroup_getgrp(DOMAIN_GRP *group,
			     DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	fstring temp;
	char **values;
	DOMAIN_GRP_MEMBER *memblist;
	int i;

	if(!ldap_entry)
		return NULL;

	if(!ldap_get_attribute("cn", group->name)) {
		DEBUG(0, ("Missing cn\n"));
                return NULL; }

	DEBUG(2,("Retrieving group [%s]\n", group->name));

        if(ldap_get_attribute("rid", temp)) {
		group->rid = atoi(temp);
	} else {
		DEBUG(0, ("Missing rid\n"));
		return NULL;
	}

	if(!ldap_get_attribute("description", group->comment))
		group->comment[0] = 0;

	group->attr = 0x7;

	if(!members || !num_membs) {
		ldap_entry = ldap_next_entry(ldap_struct, ldap_entry);
		return group;
	}

	if(values = ldap_get_values(ldap_struct, ldap_entry, "uidMember")) {

		DEBUG(0, ("Need to return NT names here\n"));

		*num_membs = i = ldap_count_values(values);
		*members = memblist = malloc(i * sizeof(DOMAIN_GRP_MEMBER));

		do {
			fstrcpy(memblist[--i].name, values[i]);
			memblist[i].attr = 0x7;
		} while(i > 0);

		ldap_value_free(values);

	} else {
		*num_membs = 0;
		*members = NULL;
	}

	ldap_entry = ldap_next_entry(ldap_struct, ldap_entry);
	return group;
}


/************************************************************************
  Queues the necessary modifications to save a DOMAIN_GRP structure
 ************************************************************************/

static void ldapgroup_grpmods(DOMAIN_GRP *group, LDAPMod ***mods,
			      int operation)
{
	fstring temp;

	*mods = NULL;

	if(operation == LDAP_MOD_ADD) { /* immutable attributes */
		ldap_make_mod(mods, LDAP_MOD_ADD, "objectClass", "sambaGroup");
		ldap_make_mod(mods, LDAP_MOD_ADD, "cn", group->name);

		slprintf(temp, sizeof(temp)-1, "%d", (gid_t)(-1));
		ldap_make_mod(mods, LDAP_MOD_ADD, "gidNumber", temp);

		slprintf(temp, sizeof(temp)-1, "%d", group->rid);
		ldap_make_mod(mods, LDAP_MOD_ADD, "rid", temp);
	}

	ldap_make_mod(mods, operation, "description", group->comment);
}


/***************************************************************
  Begin/end domain group enumeration.
 ****************************************************************/

static void *ldapgroup_enumfirst(BOOL update)
{
	int server_role = lp_server_role();

        if (server_role == ROLE_DOMAIN_NONE ||
			server_role == ROLE_DOMAIN_MEMBER)
                return NULL;

	if (!ldap_open_connection(False))
		return NULL;

	ldap_search_for("objectclass=sambaGroup");

	return ldap_struct;
}

static void ldapgroup_enumclose(void *vp)
{
	ldap_close_connection();
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT ldapgroup_getdbpos(void *vp)
{
	return (SMB_BIG_UINT)((ulong)ldap_entry);
}

static BOOL ldapgroup_setdbpos(void *vp, SMB_BIG_UINT tok)
{
	ldap_entry = (LDAPMessage *)((ulong)tok);
	return (True);
}


/*************************************************************************
  Return information about domain groups and their members.
 *************************************************************************/

static DOMAIN_GRP *ldapgroup_getgrpbynam(const char *name,
	       DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	DOMAIN_GRP *ret;

	if(!ldap_open_connection(False))
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(cn=%s)(objectClass=sambaGroup))", name);
	ldap_search_for(filter);

	ret = ldapgroup_getgrp(&domgrp, members, num_membs);

	ldap_close_connection();
	return ret;
}

static DOMAIN_GRP *ldapgroup_getgrpbygid(gid_t grp_id,
	       DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	DOMAIN_GRP *ret;

	if(!ldap_open_connection(False))
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(gidNumber=%d)(objectClass=sambaGroup))", grp_id);
	ldap_search_for(filter);

	ret = ldapgroup_getgrp(&domgrp, members, num_membs);

	ldap_close_connection();
	return ret;
}

static DOMAIN_GRP *ldapgroup_getgrpbyrid(uint32 grp_rid,
	       DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	DOMAIN_GRP *ret;

	if(!ldap_open_connection(False))
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(rid=%d)(objectClass=sambaGroup))", grp_rid);
	ldap_search_for(filter);

	ret = ldapgroup_getgrp(&domgrp, members, num_membs);

	ldap_close_connection();
	return ret;
}

static DOMAIN_GRP *ldapgroup_getcurrentgrp(void *vp,
	       DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	return ldapgroup_getgrp(&domgrp, members, num_membs);
}


/*************************************************************************
  Add/modify domain groups.
 *************************************************************************/

static BOOL ldapgroup_addgrp(DOMAIN_GRP *group)
{
	LDAPMod **mods;

	ldapgroup_grpmods(group, &mods, LDAP_MOD_ADD); 
	return ldap_makemods("cn", group->name, mods, True);
}

static BOOL ldapgroup_modgrp(DOMAIN_GRP *group)
{
	LDAPMod **mods;

	ldapgroup_grpmods(group, &mods, LDAP_MOD_REPLACE);
	return ldap_makemods("cn", group->name, mods, False);
}


/*************************************************************************
  Return domain groups that a user is in.
 *************************************************************************/

static BOOL ldapgroup_getusergroups(const char *name, DOMAIN_GRP **groups,
				    int *num_grps)
{
	DOMAIN_GRP *grouplist;
	fstring filter;
	int i;

	slprintf(filter, sizeof(pstring)-1,
		 "(&(uidMember=%s)(objectclass=sambaGroup))", name);
	ldap_search_for(filter);

	*num_grps = i = ldap_count_entries(ldap_struct, ldap_results);

	if(!i) {
		*groups = NULL;
		return (True);
	}

	*groups = grouplist = malloc(i * sizeof(DOMAIN_GRP));
	do {
		i--;
	} while(ldapgroup_getgrp(&grouplist[i], NULL, NULL) && (i > 0));

	return (True);
}


static struct groupdb_ops ldapgroup_ops =
{
	ldapgroup_enumfirst,
	ldapgroup_enumclose,
	ldapgroup_getdbpos,
	ldapgroup_setdbpos,

	ldapgroup_getgrpbynam,
	ldapgroup_getgrpbygid,
	ldapgroup_getgrpbyrid,
	ldapgroup_getcurrentgrp,

	ldapgroup_addgrp,
	ldapgroup_modgrp,

	ldapgroup_getusergroups
};

struct groupdb_ops *ldap_initialise_group_db(void)
{
	return &ldapgroup_ops;
}

#else
 void groupldap_dummy_function(void);
 void groupldap_dummy_function(void) { } /* stop some compilers complaining */
#endif

