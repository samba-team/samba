/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP local group database for SAMBA
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
static LOCAL_GRP localgrp;


/***************************************************************
  Get group and membership information.
 ****************************************************************/

static LOCAL_GRP *ldapalias_getgrp(LOCAL_GRP *group,
		     LOCAL_GRP_MEMBER **members, int *num_membs)
{
	fstring temp;
	char **values;
	LOCAL_GRP_MEMBER *memblist;
	char *value, *sep;
	int i;

	if(!ldap_entry)
		return NULL;

	if(!ldap_get_attribute("cn", group->name)) {
		DEBUG(0, ("Missing cn\n"));
                return NULL; }
	
	DEBUG(2,("Retrieving alias [%s]\n", group->name));

        if(ldap_get_attribute("rid", temp)) {
		group->rid = strtol(temp, NULL, 16);
	} else {
		DEBUG(0, ("Missing rid\n"));
		return NULL;
	}

	if(!ldap_get_attribute("description", group->comment))
		group->comment[0] = 0;

	if(!members || !num_membs) {
		ldap_entry = ldap_next_entry(ldap_struct, ldap_entry);
		return group;
	}

	if(values = ldap_get_values(ldap_struct, ldap_entry, "member")) {

		*num_membs = i = ldap_count_values(values);
		*members = memblist = malloc(i * sizeof(LOCAL_GRP_MEMBER));

		do {
			value = values[--i];

		        if(!(sep = strchr(value, ','))) {
				DEBUG(0, ("Malformed alias member\n"));
				return NULL;
			}
			*(sep++) = 0;
			fstrcpy(memblist[i].name, value);

			if(!(value = strchr(sep, ','))) {
				DEBUG(0, ("Malformed alias member\n"));
				return NULL;
			}
			*(value++) = 0;
			string_to_sid(&memblist[i].sid, sep);

			if((memblist[i].sid_use = atoi(value))
					>= SID_NAME_UNKNOWN)
				DEBUG(0, ("Invalid SID use in alias"));

		} while(i > 0);

		ldap_value_free(values);

	} else {
		*num_membs = 0;
		*members = NULL;
	}

	return group;
}


/************************************************************************
  Queues the necessary modifications to save a LOCAL_GRP structure
 ************************************************************************/

static void ldapalias_grpmods(LOCAL_GRP *group, LDAPMod ***mods, int operation)
{
	fstring temp;

	*mods = NULL;

	if(operation == LDAP_MOD_ADD) { /* immutable attributes */
		ldap_make_mod(mods, LDAP_MOD_ADD, "objectClass", "sambaAlias");
		ldap_make_mod(mods, LDAP_MOD_ADD, "cn", group->name);

		slprintf(temp, sizeof(temp)-1, "%x", group->rid);
		ldap_make_mod(mods, LDAP_MOD_ADD, "rid", temp);
	}

	ldap_make_mod(mods, operation, "description", group->comment);
}


/************************************************************************
  Create a alias member entry
 ************************************************************************/

static BOOL ldapalias_memmods(DOM_SID *user_sid, LDAPMod ***mods,
			      int operation)
{
	pstring member;
	pstring sid_str;
	fstring name;
	uint8 type;

	if (lookup_sid(user_sid, name, &type))
		return (False);
	sid_to_string(sid_str, user_sid);

	slprintf(member, sizeof(member)-1, "%s,%s,%d", name, sid_str, type);

	*mods = NULL;
	ldap_make_mod(mods, operation, "member", member);
	return True;
}


/***************************************************************
  Begin/end smbgrp enumeration.
 ****************************************************************/

static void *ldapalias_enumfirst(BOOL update)
{
	if (!ldap_connect())
		return NULL;

	ldap_search_for("objectClass=sambaAlias");

	return ldap_struct;
}

static void ldapalias_enumclose(void *vp)
{
	ldap_disconnect();
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT ldapalias_getdbpos(void *vp)
{
	return (SMB_BIG_UINT)((ulong)ldap_entry);
}

static BOOL ldapalias_setdbpos(void *vp, SMB_BIG_UINT tok)
{
	ldap_entry = (LDAPMessage *)((ulong)tok);
	return (True);
}


/*************************************************************************
  Return limited smb_passwd information, and group membership.
 *************************************************************************/

static LOCAL_GRP *ldapalias_getgrpbynam(const char *name,
	       LOCAL_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	LOCAL_GRP *ret;

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(cn=%s)(objectClass=sambaAlias))", name);
	ldap_search_for(filter);

	ret = ldapalias_getgrp(&localgrp, members, num_membs);

	ldap_disconnect();
	return ret;
}

static LOCAL_GRP *ldapalias_getgrpbygid(gid_t grp_id,
	       LOCAL_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	LOCAL_GRP *ret;

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(gidNumber=%d)(objectClass=sambaAlias))", grp_id);
	ldap_search_for(filter);
	ret = ldapalias_getgrp(&localgrp, members, num_membs);

	ldap_disconnect();
	return ret;
}

static LOCAL_GRP *ldapalias_getgrpbyrid(uint32 grp_rid,
	       LOCAL_GRP_MEMBER **members, int *num_membs)
{
	fstring filter;
	LOCAL_GRP *ret;

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(rid=%x)(objectClass=sambaAlias))", grp_rid);
	ldap_search_for(filter);
	ret = ldapalias_getgrp(&localgrp, members, num_membs);

	ldap_disconnect();
	return ret;
}

static LOCAL_GRP *ldapalias_getcurrentgrp(void *vp,
	       LOCAL_GRP_MEMBER **members, int *num_membs)
{
	return ldapalias_getgrp(&localgrp, members, num_membs);
}


/*************************************************************************
  Add/modify/delete aliases.
 *************************************************************************/

static BOOL ldapalias_addgrp(LOCAL_GRP *group)
{
	LDAPMod **mods;

	if (!ldap_allocaterid(&group->rid))
	{
		DEBUG(0,("RID generation failed\n"));
		return (False);
	}

	ldapalias_grpmods(group, &mods, LDAP_MOD_ADD); 
	return ldap_makemods("cn", group->name, mods, True);
}

static BOOL ldapalias_modgrp(LOCAL_GRP *group)
{
	LDAPMod **mods;

	ldapalias_grpmods(group, &mods, LDAP_MOD_REPLACE);
	return ldap_makemods("cn", group->name, mods, False);
}

static BOOL ldapalias_delgrp(uint32 grp_rid)
{
	fstring filter;
	char *dn;
	int err;

	if (!ldap_connect())
		return (False);

	slprintf(filter, sizeof(filter)-1,
		 "(&(rid=%x)(objectClass=sambaAlias))", grp_rid);
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
  Add users to/remove users from aliases.
 *************************************************************************/

static BOOL ldapalias_addmem(uint32 grp_rid, DOM_SID *user_sid)
{
	LDAPMod **mods;
        fstring rid_str;

	slprintf(rid_str, sizeof(rid_str)-1, "%x", grp_rid);

	if(!ldapalias_memmods(user_sid, &mods, LDAP_MOD_ADD))
		return (False);

	return ldap_makemods("rid", rid_str, mods, False);
}

static BOOL ldapalias_delmem(uint32 grp_rid, DOM_SID *user_sid)
{
	LDAPMod **mods;
        fstring rid_str;

	slprintf(rid_str, sizeof(rid_str)-1, "%x", grp_rid);

	if(!ldapalias_memmods(user_sid, &mods, LDAP_MOD_DELETE))
		return (False);

	return ldap_makemods("rid", rid_str, mods, False);
}


/*************************************************************************
  Return aliases that a user is in.
 *************************************************************************/

static BOOL ldapalias_getusergroups(const char *name, LOCAL_GRP **groups,
				    int *num_grps)
{
	LOCAL_GRP *grouplist;
	fstring filter;
	int i;

	if(!ldap_connect())
		return (False);

	slprintf(filter, sizeof(pstring)-1,
		 "(&(member=%s,*)(objectclass=sambaAlias))", name);
	ldap_search_for(filter);

	*num_grps = i = ldap_count_entries(ldap_struct, ldap_results);

	if(!i) {
		*groups = NULL;
		ldap_disconnect();
		return (True);
	}

	*groups = grouplist = malloc(i * sizeof(LOCAL_GRP));
	do {
		i--;
	} while(ldapalias_getgrp(&grouplist[i], NULL, NULL) && (i > 0));

	ldap_disconnect();
	return (True);
}


static struct aliasdb_ops ldapalias_ops =
{
	ldapalias_enumfirst,
	ldapalias_enumclose,
	ldapalias_getdbpos,
	ldapalias_setdbpos,

	ldapalias_getgrpbynam,
	ldapalias_getgrpbygid,
	ldapalias_getgrpbyrid,
	ldapalias_getcurrentgrp,

	ldapalias_addgrp,
	ldapalias_modgrp,
	ldapalias_delgrp,

	ldapalias_addmem,
	ldapalias_delmem,

	ldapalias_getusergroups
};

struct aliasdb_ops *ldap_initialise_alias_db(void)
{
	return &ldapalias_ops;
}

#else
 void aliasldap_dummy_function(void);
 void aliasldap_dummy_function(void) { } /* stop some compilers complaining */
#endif

