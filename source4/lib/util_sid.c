/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 		1992-1998
   Copyright (C) Luke Kenneth Caseson Leighton 	1998-1999
   Copyright (C) Jeremy Allison  		1999
   Copyright (C) Stefan (metze) Metzmacher 	2002
   Copyright (C) Simo Sorce 			2002
      
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

/*
 * Some useful sids
 */

struct dom_sid *global_sid_World_Domain;	    	/* Everyone domain */
struct dom_sid *global_sid_World;    				/* Everyone */
struct dom_sid *global_sid_Creator_Owner_Domain;    /* Creator Owner domain */
struct dom_sid *global_sid_NT_Authority;    		/* NT Authority */
struct dom_sid *global_sid_System;    		/* System */
struct dom_sid *global_sid_NULL;            		/* NULL sid */
struct dom_sid *global_sid_Authenticated_Users;		/* All authenticated rids */
struct dom_sid *global_sid_Network;			/* Network rids */

struct dom_sid *global_sid_Creator_Owner;	/* Creator Owner */
struct dom_sid *global_sid_Creator_Group;	/* Creator Group */
struct dom_sid *global_sid_Anonymous;		/* Anonymous login */

struct dom_sid *global_sid_Builtin; 			/* Local well-known domain */
struct dom_sid *global_sid_Builtin_Administrators;	/* Builtin administrators */
struct dom_sid *global_sid_Builtin_Users;		/* Builtin users */
struct dom_sid *global_sid_Builtin_Guests;		/* Builtin guest users */
struct dom_sid *global_sid_Builtin_Power_Users;		/* Builtin power users */
struct dom_sid *global_sid_Builtin_Account_Operators;	/* Builtin account operators */
struct dom_sid *global_sid_Builtin_Server_Operators;	/* Builtin server operators */
struct dom_sid *global_sid_Builtin_Print_Operators;	/* Builtin print operators */
struct dom_sid *global_sid_Builtin_Backup_Operators;	/* Builtin backup operators */
struct dom_sid *global_sid_Builtin_Replicator;		/* Builtin replicator */

#define SECURITY_NULL_SID_AUTHORITY    0
#define SECURITY_WORLD_SID_AUTHORITY   1
#define SECURITY_LOCAL_SID_AUTHORITY   2
#define SECURITY_CREATOR_SID_AUTHORITY 3
#define SECURITY_NT_AUTHORITY          5

/****************************************************************************
 Lookup string names for SID types.
****************************************************************************/

static const struct {
	enum SID_NAME_USE sid_type;
	const char *string;
} sid_name_type[] = {
	{SID_NAME_USER, "User"},
	{SID_NAME_DOM_GRP, "Domain Group"},
	{SID_NAME_DOMAIN, "Domain"},
	{SID_NAME_ALIAS, "Local Group"},
	{SID_NAME_WKN_GRP, "Well-known Group"},
	{SID_NAME_DELETED, "Deleted Account"},
	{SID_NAME_INVALID, "Invalid Account"},
	{SID_NAME_UNKNOWN, "UNKNOWN"},

 	{SID_NAME_USE_NONE, NULL}
};

const char *sid_type_lookup(uint32_t sid_type) 
{
	int i = 0;

	/* Look through list */
	while(sid_name_type[i].sid_type != 0) {
		if (sid_name_type[i].sid_type == sid_type)
			return sid_name_type[i].string;
		i++;
	}

	/* Default return */
	return "SID *TYPE* is INVALID";
}

/****************************************************************************
 Creates some useful well known sids
****************************************************************************/

void generate_wellknown_sids(void)
{
	static BOOL initialised = False;
	static TALLOC_CTX *mem_ctx;

	if (initialised) 
		return;

	mem_ctx = talloc_init("Well known groups, global static context");
	if (!mem_ctx)
		return;

	/* SECURITY_NULL_SID_AUTHORITY */
	global_sid_NULL = dom_sid_parse_talloc(mem_ctx, "S-1-0-0");

	/* SECURITY_WORLD_SID_AUTHORITY */
	global_sid_World_Domain = dom_sid_parse_talloc(mem_ctx, "S-1-1");
	global_sid_World = dom_sid_parse_talloc(mem_ctx, "S-1-1-0");

	/* SECURITY_CREATOR_SID_AUTHORITY */
	global_sid_Creator_Owner_Domain = dom_sid_parse_talloc(mem_ctx, "S-1-3");
	global_sid_Creator_Owner = dom_sid_parse_talloc(mem_ctx, "S-1-3-0");
	global_sid_Creator_Group = dom_sid_parse_talloc(mem_ctx, "S-1-3-1");

	/* SECURITY_NT_AUTHORITY */
	global_sid_NT_Authority = dom_sid_parse_talloc(mem_ctx, "S-1-5");
	global_sid_Network = dom_sid_parse_talloc(mem_ctx, "S-1-5-2");
	global_sid_Anonymous = dom_sid_parse_talloc(mem_ctx, "S-1-5-7");
	global_sid_Authenticated_Users = dom_sid_parse_talloc(mem_ctx, "S-1-5-11");
	global_sid_System = dom_sid_parse_talloc(mem_ctx, "S-1-5-18");

	/* SECURITY_BUILTIN_DOMAIN_RID */
	global_sid_Builtin = dom_sid_parse_talloc(mem_ctx, "S-1-5-32");
	global_sid_Builtin_Administrators = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-544");
	global_sid_Builtin_Users = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-545");
	global_sid_Builtin_Guests = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-546");
	global_sid_Builtin_Power_Users = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-547");
	global_sid_Builtin_Account_Operators = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-548");
	global_sid_Builtin_Server_Operators = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-549");
	global_sid_Builtin_Print_Operators = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-550");
	global_sid_Builtin_Backup_Operators = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-551");
	global_sid_Builtin_Replicator = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-552");

	initialised = True;
}

/*****************************************************************
 Return the last rid from the end of a sid
*****************************************************************/  

BOOL sid_peek_rid(const struct dom_sid *sid, uint32_t *rid)
{
	if (!sid || !rid)
		return False;		
	
	if (sid->num_auths > 0) {
		*rid = sid->sub_auths[sid->num_auths - 1];
		return True;
	}
	return False;
}

/*****************************************************************
 Return the last rid from the end of a sid
 and check the sid against the exp_dom_sid  
*****************************************************************/  

BOOL sid_peek_check_rid(const struct dom_sid *exp_dom_sid, const struct dom_sid *sid, uint32_t *rid)
{
	if (!exp_dom_sid || !sid || !rid)
		return False;
			

	if (sid_compare_domain(exp_dom_sid, sid)!=0){
		*rid=(-1);
		return False;
	}
	
	return sid_peek_rid(sid, rid);
}

/*****************************************************************
 Compare the auth portion of two sids.
*****************************************************************/  

static int sid_compare_auth(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
	int i;

	if (sid1 == sid2)
		return 0;
	if (!sid1)
		return -1;
	if (!sid2)
		return 1;

	if (sid1->sid_rev_num != sid2->sid_rev_num)
		return sid1->sid_rev_num - sid2->sid_rev_num;

	for (i = 0; i < 6; i++)
		if (sid1->id_auth[i] != sid2->id_auth[i])
			return sid1->id_auth[i] - sid2->id_auth[i];

	return 0;
}

/*****************************************************************
 Compare two sids.
*****************************************************************/  

int sid_compare(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
	int i;

	if (sid1 == sid2)
		return 0;
	if (!sid1)
		return -1;
	if (!sid2)
		return 1;

	/* Compare most likely different rids, first: i.e start at end */
	if (sid1->num_auths != sid2->num_auths)
		return sid1->num_auths - sid2->num_auths;

	for (i = sid1->num_auths-1; i >= 0; --i)
		if (sid1->sub_auths[i] != sid2->sub_auths[i])
			return sid1->sub_auths[i] - sid2->sub_auths[i];

	return sid_compare_auth(sid1, sid2);
}

/*****************************************************************
 See if 2 SIDs are in the same domain
 this just compares the leading sub-auths
*****************************************************************/  

int sid_compare_domain(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
	int n, i;

	n = MIN(sid1->num_auths, sid2->num_auths);

	for (i = n-1; i >= 0; --i)
		if (sid1->sub_auths[i] != sid2->sub_auths[i])
			return sid1->sub_auths[i] - sid2->sub_auths[i];

	return sid_compare_auth(sid1, sid2);
}

/*****************************************************************
 Compare two sids.
*****************************************************************/  

BOOL sid_equal(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
	return sid_compare(sid1, sid2) == 0;
}
/*****************************************************************
 Write a sid out into on-the-wire format.
*****************************************************************/  

BOOL sid_linearize(char *outbuf, size_t len, const struct dom_sid *sid)
{
	size_t i;

	if (len < sid_size(sid))
		return False;

	SCVAL(outbuf,0,sid->sid_rev_num);
	SCVAL(outbuf,1,sid->num_auths);
	memcpy(&outbuf[2], sid->id_auth, 6);
	for(i = 0; i < sid->num_auths; i++)
		SIVAL(outbuf, 8 + (i*4), sid->sub_auths[i]);

	return True;
}


/*****************************************************************
 Calculates size of a sid.
*****************************************************************/  

size_t sid_size(const struct dom_sid *sid)
{
	if (sid == NULL)
		return 0;

	return sid->num_auths * sizeof(uint32_t) + 8;
}

/*****************************************************************
 Return the binary string representation of a struct dom_sid.
 Caller must free.
*****************************************************************/

char *sid_binstring(const struct dom_sid *sid)
{
	char *buf, *s;
	int len = sid_size(sid);
	buf = malloc(len);
	if (!buf)
		return NULL;
	sid_linearize(buf, len, sid);
	s = binary_string(buf, len);
	free(buf);
	return s;
}

/*******************************************************************
 Check if ACE has OBJECT type.
********************************************************************/
BOOL sec_ace_object(uint8_t type)
{
	if (type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT ||
            type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT ||
            type == SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT ||
            type == SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT) {
		return True;
	}
	return False;
}
