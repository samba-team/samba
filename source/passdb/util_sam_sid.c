/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Caseson Leighton 1998-1999
   Copyright (C) Jeremy Allison  1999
   
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

#define MAX_SID_NAMES	7

typedef struct _known_sid_users {
	uint32 rid;
	enum SID_NAME_USE sid_name_use;
	const char *known_user_name;
} known_sid_users;

static struct sid_name_map_info
{
	DOM_SID *sid;
	const char *name;
	const known_sid_users *known_users;
} sid_name_map[MAX_SID_NAMES];

extern DOM_SID global_sid_Builtin; 				/* Local well-known domain */
extern DOM_SID global_sid_World_Domain;	    	/* Everyone domain */
extern DOM_SID global_sid_Creator_Owner_Domain;    /* Creator Owner domain */
extern DOM_SID global_sid_NT_Authority;    		/* NT Authority */


static BOOL sid_name_map_initialized = False;
/* static known_sid_users no_users[] = {{0, 0, NULL}}; */

static const known_sid_users everyone_users[] = {
	{ 0, SID_NAME_WKN_GRP, "Everyone" },
	{0, (enum SID_NAME_USE)0, NULL}};

static const known_sid_users creator_owner_users[] = {
	{ 0, SID_NAME_WKN_GRP, "Creator Owner" },
	{ 1, SID_NAME_WKN_GRP, "Creator Group" },
	{0, (enum SID_NAME_USE)0, NULL}};

static const known_sid_users nt_authority_users[] = {
	{  1, SID_NAME_ALIAS, "Dialup" },
	{  2, SID_NAME_ALIAS, "Network"},
	{  3, SID_NAME_ALIAS, "Batch"},
	{  4, SID_NAME_ALIAS, "Interactive"},
	{  6, SID_NAME_ALIAS, "Service"},
	{  7, SID_NAME_ALIAS, "AnonymousLogon"},
	{  8, SID_NAME_ALIAS, "Proxy"},
	{  9, SID_NAME_ALIAS, "ServerLogon"},
	{ 11, SID_NAME_ALIAS, "Authenticated Users"},
	{ 18, SID_NAME_ALIAS, "SYSTEM"},
	{  0, (enum SID_NAME_USE)0, NULL}};

static const known_sid_users builtin_groups[] = {
	{ BUILTIN_ALIAS_RID_ADMINS, SID_NAME_ALIAS, "Administrators" },
	{ BUILTIN_ALIAS_RID_USERS, SID_NAME_ALIAS, "Users" },
	{ BUILTIN_ALIAS_RID_GUESTS, SID_NAME_ALIAS, "Guests" },
	{ BUILTIN_ALIAS_RID_POWER_USERS, SID_NAME_ALIAS, "Power Users" },
	{ BUILTIN_ALIAS_RID_ACCOUNT_OPS, SID_NAME_ALIAS, "Account Operators" },
	{ BUILTIN_ALIAS_RID_SYSTEM_OPS, SID_NAME_ALIAS, "Server Operators" },
	{ BUILTIN_ALIAS_RID_PRINT_OPS, SID_NAME_ALIAS, "Print Operators" },
	{ BUILTIN_ALIAS_RID_BACKUP_OPS, SID_NAME_ALIAS, "Backup Operators" },
	{ BUILTIN_ALIAS_RID_REPLICATOR, SID_NAME_ALIAS, "Replicator" },
	{ BUILTIN_ALIAS_RID_RAS_SERVERS, SID_NAME_ALIAS, "RAS Servers" },
	{ BUILTIN_ALIAS_RID_PRE_2K_ACCESS, SID_NAME_ALIAS, "Pre-Windows 2000 Compatible Access" },
	{  0, (enum SID_NAME_USE)0, NULL}};

/**************************************************************************
 Quick init function.
*************************************************************************/

static void init_sid_name_map (void)
{
	int i = 0;
	
	if (sid_name_map_initialized) return;

	generate_wellknown_sids();

	if ((lp_security() == SEC_USER) && lp_domain_logons()) {
		sid_name_map[i].sid = get_global_sam_sid();
		/* This is not lp_workgroup() for good reason:
		   it must stay around longer than the lp_*() 
		   strings do */
		sid_name_map[i].name = strdup(lp_workgroup());
		sid_name_map[i].known_users = NULL;
		i++;
		sid_name_map[i].sid = get_global_sam_sid();
		sid_name_map[i].name = strdup(global_myname());
		sid_name_map[i].known_users = NULL;
		i++;
	} else {
		sid_name_map[i].sid = get_global_sam_sid();
		sid_name_map[i].name = strdup(global_myname());
		sid_name_map[i].known_users = NULL;
		i++;
	}

	sid_name_map[i].sid = &global_sid_Builtin;
	sid_name_map[i].name = "BUILTIN";
	sid_name_map[i].known_users = &builtin_groups[0];
	i++;
	
	sid_name_map[i].sid = &global_sid_World_Domain;
	sid_name_map[i].name = "";
	sid_name_map[i].known_users = &everyone_users[0];
	i++;

	sid_name_map[i].sid = &global_sid_Creator_Owner_Domain;
	sid_name_map[i].name = "";
	sid_name_map[i].known_users = &creator_owner_users[0];
	i++;
		
	sid_name_map[i].sid = &global_sid_NT_Authority;
	sid_name_map[i].name = "NT Authority";
	sid_name_map[i].known_users = &nt_authority_users[0];
	i++;
		
	/* End of array. */
	sid_name_map[i].sid = NULL;
	sid_name_map[i].name = NULL;
	sid_name_map[i].known_users = NULL;
	
	sid_name_map_initialized = True;
		
	return;
}

/**************************************************************************
 Turns a domain SID into a name, returned in the nt_domain argument.
***************************************************************************/

BOOL map_domain_sid_to_name(DOM_SID *sid, fstring nt_domain)
{
	fstring sid_str;
	int i = 0;
	
	sid_to_string(sid_str, sid);

	if (!sid_name_map_initialized) 
		init_sid_name_map();

	DEBUG(5,("map_domain_sid_to_name: %s\n", sid_str));

	if (nt_domain == NULL)
		return False;

	while (sid_name_map[i].sid != NULL) {
		sid_to_string(sid_str, sid_name_map[i].sid);
		DEBUG(5,("map_domain_sid_to_name: compare: %s\n", sid_str));
		if (sid_equal(sid_name_map[i].sid, sid)) {		
			fstrcpy(nt_domain, sid_name_map[i].name);
			DEBUG(5,("map_domain_sid_to_name: found '%s'\n", nt_domain));
			return True;
		}
		i++;
	}

	DEBUG(5,("map_domain_sid_to_name: mapping for %s not found\n", sid_str));

    return False;
}

/**************************************************************************
 Looks up a known username from one of the known domains.
***************************************************************************/

BOOL lookup_known_rid(DOM_SID *sid, uint32 rid, char *name, enum SID_NAME_USE *psid_name_use)
{
	int i = 0;
	struct sid_name_map_info *psnm;

	if (!sid_name_map_initialized) 
		init_sid_name_map();

	for(i = 0; sid_name_map[i].sid != NULL; i++) {
		psnm = &sid_name_map[i];
		if(sid_equal(psnm->sid, sid)) {
			int j;
			for(j = 0; psnm->known_users && psnm->known_users[j].known_user_name != NULL; j++) {
				if(rid == psnm->known_users[j].rid) {
					DEBUG(5,("lookup_builtin_rid: rid = %u, domain = '%s', user = '%s'\n",
						(unsigned int)rid, psnm->name, psnm->known_users[j].known_user_name ));
					fstrcpy( name, psnm->known_users[j].known_user_name);
					*psid_name_use = psnm->known_users[j].sid_name_use;
					return True;
				}
			}
		}
	}

	return False;
}

/**************************************************************************
 Turns a domain name into a SID.
 *** side-effect: if the domain name is NULL, it is set to our domain ***
***************************************************************************/

BOOL map_domain_name_to_sid(DOM_SID *sid, char *nt_domain)
{
	int i = 0;

	if (nt_domain == NULL) {
		DEBUG(5,("map_domain_name_to_sid: mapping NULL domain to our SID.\n"));
		sid_copy(sid, get_global_sam_sid());
		return True;
	}

	if (nt_domain[0] == 0) {
		fstrcpy(nt_domain, global_myname());
		DEBUG(5,("map_domain_name_to_sid: overriding blank name to %s\n", nt_domain));
		sid_copy(sid, get_global_sam_sid());
		return True;
	}

	DEBUG(5,("map_domain_name_to_sid: %s\n", nt_domain));

	if (!sid_name_map_initialized) 
		init_sid_name_map();

	while (sid_name_map[i].name != NULL) {
		DEBUG(5,("map_domain_name_to_sid: compare: %s\n", sid_name_map[i].name));
		if (strequal(sid_name_map[i].name, nt_domain)) {
			fstring sid_str;
			sid_copy(sid, sid_name_map[i].sid);
			sid_to_string(sid_str, sid_name_map[i].sid);
			DEBUG(5,("map_domain_name_to_sid: found %s\n", sid_str));
			return True;
		}
		i++;
	}

	DEBUG(0,("map_domain_name_to_sid: mapping to %s not found.\n", nt_domain));
	return False;
}

/*****************************************************************
 Check if the SID is our domain SID (S-1-5-21-x-y-z).
*****************************************************************/  

BOOL sid_check_is_domain(const DOM_SID *sid)
{
	return sid_equal(sid, get_global_sam_sid());
}

/*****************************************************************
 Check if the SID is our domain SID (S-1-5-21-x-y-z).
*****************************************************************/  

BOOL sid_check_is_in_our_domain(const DOM_SID *sid)
{
	DOM_SID dom_sid;
	uint32 rid;

	sid_copy(&dom_sid, sid);
	sid_split_rid(&dom_sid, &rid);
	
	return sid_equal(&dom_sid, get_global_sam_sid());
}

/**************************************************************************
 Try and map a name to one of the well known SIDs.
***************************************************************************/

BOOL map_name_to_wellknown_sid(DOM_SID *sid, enum SID_NAME_USE *use, const char *name)
{
	int i, j;

	if (!sid_name_map_initialized)
		init_sid_name_map();

	for (i=0; sid_name_map[i].sid != NULL; i++) {
		const known_sid_users *users = sid_name_map[i].known_users;

		if (users == NULL)
			continue;

		for (j=0; users[j].known_user_name != NULL; j++) {
			if ( strequal(users[j].known_user_name, name) ) {
				sid_copy(sid, sid_name_map[i].sid);
				sid_append_rid(sid, users[j].rid);
				*use = users[j].sid_name_use;
				return True;
			}
		}
	}

	return False;
}

void add_sid_to_array(const DOM_SID *sid, DOM_SID **sids, int *num)
{
	*sids = Realloc(*sids, ((*num)+1) * sizeof(DOM_SID));

	if (*sids == NULL)
		return;

	sid_copy(&((*sids)[*num]), sid);
	*num += 1;

	return;
}
