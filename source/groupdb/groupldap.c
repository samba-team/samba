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
#include "sids.h"

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
	char *value, *sep;
	int i;

	if(!ldap_entry)
		return NULL;

	if(!ldap_get_attribute("cn", group->name)) {
		DEBUG(0, ("Missing cn\n"));
                return NULL; }

	DEBUG(2,("Retrieving group [%s]\n", group->name));

        if(ldap_get_attribute("rid", temp)) {
		group->rid = strtol(temp, NULL, 16);
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

	if(values = ldap_get_values(ldap_struct, ldap_entry, "member")) {

		*num_membs = i = ldap_count_values(values);
		*members = memblist = malloc(i * sizeof(DOMAIN_GRP_MEMBER));

		do {
                        value = values[--i];
                
                        if(!(sep = strchr(value, ','))) {
                                DEBUG(0, ("Malformed group member\n"));
                                return NULL;
                        }
                        *(sep++) = 0;
                        fstrcpy(memblist[i].name, value);   

                        if(!(value = strchr(sep, ','))) {
                                DEBUG(0, ("Malformed group member\n"));
                                return NULL;
                        }
                        memblist[i].rid = strtol(sep, &value, 16);

                        if((memblist[i].sid_use = atoi(value+1))
                                        >= SID_NAME_UNKNOWN)
                                DEBUG(0, ("Invalid SID use in group"));

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

		slprintf(temp, sizeof(temp)-1, "%x", group->rid);
		ldap_make_mod(mods, LDAP_MOD_ADD, "rid", temp);
	}

	ldap_make_mod(mods, operation, "description", group->comment);
}


/************************************************************************
  Create a group member entry
 ************************************************************************/

static BOOL ldapgroup_memmods(uint32 user_rid, LDAPMod ***mods, int operation)
{
	pstring member;
	fstring name;
	DOM_SID sid;
	uint8 type;

	sid_copy(&sid, &global_sam_sid);
	sid_append_rid(&sid, user_rid);
	if (lookup_sid(&sid, name, &type))
		return (False);

	slprintf(member, sizeof(member)-1, "%s,%x,%d", name, user_rid, type);

	*mods = NULL;
	ldap_make_mod(mods, operation, "member", member);
	return True;
}


/***************************************************************
  Begin/end domain group enumeration.
 ****************************************************************/

static void *ldapgroup_enumfirst(BOOL update)
{
	int server_role = lp_server_role();

        if (server_role == ROLE_STANDALONE || server_role == ROLE_DOMAIN_MEMBER)
                return NULL;

	if (!ldap_connect())
		return NULL;

	ldap_search_for("objectclass=sambaGroup");

	return ldap_struct;
}

static void ldapgroup_enumclose(void *vp)
{
	ldap_disconnect();
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

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(cn=%s*)(objectClass=sambaGroup))", name);
	ldap_search_for(filter);

	ret = ldapgroup_getgrp(&domgrp, members, num_membs);

	ldap_disconnect();
	return ret;
}

static DOMAIN_GRP *ldapgroup_getgrpbygid(gid_t grp_id,
	       DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	DOMAIN_GRP *ret;

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(gidNumber=%d)(objectClass=sambaGroup))", grp_id);
	ldap_search_for(filter);

	ret = ldapgroup_getgrp(&domgrp, members, num_membs);

	ldap_disconnect();
	return ret;
}

static DOMAIN_GRP *ldapgroup_getgrpbyrid(uint32 grp_rid,
	       DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	DOMAIN_GRP *ret;

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(rid=%x)(objectClass=sambaGroup))", grp_rid);
	ldap_search_for(filter);

	ret = ldapgroup_getgrp(&domgrp, members, num_membs);

	ldap_disconnect();
	return ret;
}

static DOMAIN_GRP *ldapgroup_getcurrentgrp(void *vp,
	       DOMAIN_GRP_MEMBER **members, int *num_membs)
{
	return ldapgroup_getgrp(&domgrp, members, num_membs);
}


/*************************************************************************
  Add/modify/delete domain groups.
 *************************************************************************/

static BOOL ldapgroup_addgrp(DOMAIN_GRP *group)
{
	LDAPMod **mods;

	if (!ldap_allocaterid(&group->rid))
	{
	    DEBUG(0,("RID generation failed\n"));
	    return (False);
	}

	ldapgroup_grpmods(group, &mods, LDAP_MOD_ADD); 
	return ldap_makemods("cn", group->name, mods, True);
}

static BOOL ldapgroup_modgrp(DOMAIN_GRP *group)
{
	LDAPMod **mods;

	ldapgroup_grpmods(group, &mods, LDAP_MOD_REPLACE);
	return ldap_makemods("cn", group->name, mods, False);
}

static BOOL ldapgroup_delgrp(uint32 grp_rid)
{
	fstring filter;
	char *dn;
	int err;

	if (!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(rid=%x)(objectClass=sambaGroup))", grp_rid);
	ldap_search_for(filter);

	if (!ldap_entry || !(dn = ldap_get_dn(ldap_struct, ldap_entry)))
	{
		ldap_disconnect();
		return (False);
	}

	err = ldap_delete_s(ldap_struct, dn);
	free(dn);
	ldap_disconnect();

	if (err != LDAP_SUCCESS)
	{
		DEBUG(0, ("delete: %s\n", ldap_err2string(err)));
		return (False);
	}

	return True;
}


/*************************************************************************
  Add users to/remove users from groups.
 *************************************************************************/

static BOOL ldapgroup_addmem(uint32 grp_rid, uint32 user_rid)
{
	LDAPMod **mods;
        fstring rid_str;

	slprintf(rid_str, sizeof(rid_str)-1, "%x", grp_rid);

	if(!ldapgroup_memmods(user_rid, &mods, LDAP_MOD_ADD))
		return (False);

	return ldap_makemods("rid", rid_str, mods, False);
}

static BOOL ldapgroup_delmem(uint32 grp_rid, uint32 user_rid)
{
	LDAPMod **mods;
        fstring rid_str;

	slprintf(rid_str, sizeof(rid_str)-1, "%x", grp_rid);

	if(!ldapgroup_memmods(user_rid, &mods, LDAP_MOD_DELETE))
		return (False);

	return ldap_makemods("rid", rid_str, mods, False);
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

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(pstring)-1,
		 "(&(member=%s,*)(objectclass=sambaGroup))", name);
	ldap_search_for(filter);

	*num_grps = i = ldap_count_entries(ldap_struct, ldap_results);

	if(!i) {
		*groups = NULL;
		ldap_disconnect();
		return (True);
	}

	*groups = grouplist = malloc(i * sizeof(DOMAIN_GRP));
	do {
		i--;
	} while(ldapgroup_getgrp(&grouplist[i], NULL, NULL) && (i > 0));

	ldap_disconnect();
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
	ldapgroup_delgrp,

	ldapgroup_addmem,
	ldapgroup_delmem,

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

