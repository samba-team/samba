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

struct sid_name_map_info
{
	const DOM_SID *sid;
	const char *name;
	const known_sid_users *known_users;
};

static const known_sid_users everyone_users[] = {
	{ 0, SID_NAME_WKN_GRP, "Everyone" },
	{0, (enum SID_NAME_USE)0, NULL}};

static const known_sid_users creator_owner_users[] = {
	{ 0, SID_NAME_WKN_GRP, "Creator Owner" },
	{ 1, SID_NAME_WKN_GRP, "Creator Group" },
	{0, (enum SID_NAME_USE)0, NULL}};

static const known_sid_users nt_authority_users[] = {
	{  1, SID_NAME_WKN_GRP, "Dialup" },
	{  2, SID_NAME_WKN_GRP, "Network"},
	{  3, SID_NAME_WKN_GRP, "Batch"},
	{  4, SID_NAME_WKN_GRP, "Interactive"},
	{  6, SID_NAME_WKN_GRP, "Service"},
	{  7, SID_NAME_WKN_GRP, "AnonymousLogon"},
	{  8, SID_NAME_WKN_GRP, "Proxy"},
	{  9, SID_NAME_WKN_GRP, "ServerLogon"},
	{ 10, SID_NAME_WKN_GRP, "Self"},
	{ 11, SID_NAME_WKN_GRP, "Authenticated Users"},
	{ 12, SID_NAME_WKN_GRP, "Restricted"},
	{ 13, SID_NAME_WKN_GRP, "Terminal Server User"},
	{ 14, SID_NAME_WKN_GRP, "Remote Interactive Logon"},
	{ 15, SID_NAME_WKN_GRP, "This Organization"},
	{ 18, SID_NAME_WKN_GRP, "SYSTEM"},
	{ 19, SID_NAME_WKN_GRP, "Local Service"},
	{ 20, SID_NAME_WKN_GRP, "Network Service"},
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

static struct sid_name_map_info special_domains[] = {
	{ &global_sid_Builtin, "BUILTIN", builtin_groups },
	{ &global_sid_World_Domain, "", everyone_users },
	{ &global_sid_Creator_Owner_Domain, "", creator_owner_users },
	{ &global_sid_NT_Authority, "NT Authority", nt_authority_users },
	{ NULL, NULL, NULL }};

/**************************************************************************
 Turns a domain SID into a name, returned in the nt_domain argument.
***************************************************************************/

BOOL map_domain_sid_to_name(const DOM_SID *sid, fstring nt_domain)
{
	fstring sid_str;
	int i = 0;
	
	sid_to_string(sid_str, sid);

	DEBUG(5,("map_domain_sid_to_name: %s\n", sid_str));

	while (special_domains[i].sid != NULL) {
		DEBUG(5,("map_domain_sid_to_name: compare: %s\n",
			 sid_string_static(special_domains[i].sid)));
		if (sid_equal(special_domains[i].sid, sid)) {		
			fstrcpy(nt_domain, special_domains[i].name);
			DEBUG(5,("map_domain_sid_to_name: found '%s'\n",
				 nt_domain));
			return True;
		}
		i++;
	}

	DEBUG(5,("map_domain_sid_to_name: mapping for %s not found\n",
		 sid_string_static(sid)));

	return False;
}

const char *builtin_domain_name(void)
{
	return "BUILTIN";
}

/**************************************************************************
 Looks up a known username from one of the known domains.
***************************************************************************/

BOOL lookup_special_sid(const DOM_SID *sid, const char **domain,
			const char **name, enum SID_NAME_USE *type)
{
	int i;
	DOM_SID dom_sid;
	uint32 rid;
	const known_sid_users *users = NULL;

	sid_copy(&dom_sid, sid);
	if (!sid_split_rid(&dom_sid, &rid)) {
		DEBUG(2, ("Could not split rid from SID\n"));
		return False;
	}

	for (i=0; special_domains[i].sid != NULL; i++) {
		if (sid_equal(&dom_sid, special_domains[i].sid)) {
			*domain = special_domains[i].name;
			users = special_domains[i].known_users;
			break;
		}
	}

	if (users == NULL) {
		DEBUG(10, ("SID %s is no special sid\n",
			   sid_string_static(sid)));
		return False;
	}

	for (i=0; users[i].known_user_name != NULL; i++) {
		if (rid == users[i].rid) {
			*name = users[i].known_user_name;
			*type = users[i].sid_name_use;
			return True;
		}
	}

	DEBUG(10, ("RID of special SID %s not found\n",
		   sid_string_static(sid)));

	return False;
}

/*******************************************************************
 Look up a rid in the BUILTIN domain
 ********************************************************************/
BOOL lookup_builtin_rid(uint32 rid, fstring name)
{
	const known_sid_users *aliases = builtin_groups;
	int i;

	for (i=0; aliases[i].known_user_name != NULL; i++) {
		if (rid == aliases[i].rid) {
			fstrcpy(name, aliases[i].known_user_name);
			return True;
		}
	}

	return False;
}

/*******************************************************************
 Look up a name in the BUILTIN domain
 ********************************************************************/
BOOL lookup_builtin_name(const char *name, uint32 *rid)
{
	const known_sid_users *aliases = builtin_groups;
	int i;

	for (i=0; aliases[i].known_user_name != NULL; i++) {
		if (strequal(name, aliases[i].known_user_name)) {
			*rid = aliases[i].rid;
			return True;
		}
	}

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

	DEBUG(10,("map_name_to_wellknown_sid: looking up %s\n", name));

	for (i=0; special_domains[i].sid != NULL; i++) {
		const known_sid_users *users = special_domains[i].known_users;

		if (users == NULL)
			continue;

		for (j=0; users[j].known_user_name != NULL; j++) {
			if ( strequal(users[j].known_user_name, name) ) {
				sid_copy(sid, special_domains[i].sid);
				sid_append_rid(sid, users[j].rid);
				*use = users[j].sid_name_use;
				return True;
			}
		}
	}

	return False;
}


