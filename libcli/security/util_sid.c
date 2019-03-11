/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 		1992-1998
   Copyright (C) Luke Kenneth Caseson Leighton 	1998-1999
   Copyright (C) Jeremy Allison  		1999
   Copyright (C) Stefan (metze) Metzmacher 	2002
   Copyright (C) Simo Sorce 			2002
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2005
   Copyright (C) Andrew Bartlett                2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"

/*
 * Some useful sids, more well known sids can be found at
 * http://support.microsoft.com/kb/243330/EN-US/
 */


/* S-1-1 */
const struct dom_sid global_sid_World_Domain =               /* Everyone domain */
{ 1, 0, {0,0,0,0,0,1}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-1-0 */
const struct dom_sid global_sid_World =                      /* Everyone */
{ 1, 1, {0,0,0,0,0,1}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-2 */
const struct dom_sid global_sid_Local_Authority =            /* Local Authority */
{ 1, 0, {0,0,0,0,0,2}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-3 */
const struct dom_sid global_sid_Creator_Owner_Domain =       /* Creator Owner domain */
{ 1, 0, {0,0,0,0,0,3}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5 */
const struct dom_sid global_sid_NT_Authority =    		/* NT Authority */
{ 1, 0, {0,0,0,0,0,5}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-18 */
const struct dom_sid global_sid_System =			/* System */
{ 1, 1, {0,0,0,0,0,5}, {18,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-0-0 */
const struct dom_sid global_sid_NULL =            		/* NULL sid */
{ 1, 1, {0,0,0,0,0,0}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-11 */
const struct dom_sid global_sid_Authenticated_Users =	/* All authenticated rids */
{ 1, 1, {0,0,0,0,0,5}, {11,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
#if 0
/* for documentation S-1-5-12 */
const struct dom_sid global_sid_Restriced =			/* Restriced Code */
{ 1, 1, {0,0,0,0,0,5}, {12,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
#endif

/* S-1-18 */
const struct dom_sid global_sid_Asserted_Identity =       /* Asserted Identity */
{ 1, 0, {0,0,0,0,0,18}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-18-1 */
const struct dom_sid global_sid_Asserted_Identity_Service =	/* Asserted Identity Service */
{ 1, 1, {0,0,0,0,0,18}, {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-18-2 */
const struct dom_sid global_sid_Asserted_Identity_Authentication_Authority =	/* Asserted Identity Authentication Authority */
{ 1, 1, {0,0,0,0,0,18}, {2,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};

/* S-1-5-2 */
const struct dom_sid global_sid_Network =			/* Network rids */
{ 1, 1, {0,0,0,0,0,5}, {2,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};

/* S-1-3 */
const struct dom_sid global_sid_Creator_Owner =		/* Creator Owner */
{ 1, 1, {0,0,0,0,0,3}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-3-1 */
const struct dom_sid global_sid_Creator_Group =		/* Creator Group */
{ 1, 1, {0,0,0,0,0,3}, {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-3-4 */
const struct dom_sid global_sid_Owner_Rights =		/* Owner Rights */
{ 1, 1, {0,0,0,0,0,3}, {4,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-7 */
const struct dom_sid global_sid_Anonymous =			/* Anonymous login */
{ 1, 1, {0,0,0,0,0,5}, {7,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-9 */
const struct dom_sid global_sid_Enterprise_DCs =		/* Enterprise DCs */
{ 1, 1, {0,0,0,0,0,5}, {9,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32 */
const struct dom_sid global_sid_Builtin = 			/* Local well-known domain */
{ 1, 1, {0,0,0,0,0,5}, {32,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-544 */
const struct dom_sid global_sid_Builtin_Administrators =	/* Builtin administrators */
{ 1, 2, {0,0,0,0,0,5}, {32,544,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-545 */
const struct dom_sid global_sid_Builtin_Users =		/* Builtin users */
{ 1, 2, {0,0,0,0,0,5}, {32,545,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-546 */
const struct dom_sid global_sid_Builtin_Guests =		/* Builtin guest users */
{ 1, 2, {0,0,0,0,0,5}, {32,546,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-547 */
const struct dom_sid global_sid_Builtin_Power_Users =	/* Builtin power users */
{ 1, 2, {0,0,0,0,0,5}, {32,547,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-548 */
const struct dom_sid global_sid_Builtin_Account_Operators =	/* Builtin account operators */
{ 1, 2, {0,0,0,0,0,5}, {32,548,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-549 */
const struct dom_sid global_sid_Builtin_Server_Operators =	/* Builtin server operators */
{ 1, 2, {0,0,0,0,0,5}, {32,549,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-550 */
const struct dom_sid global_sid_Builtin_Print_Operators =	/* Builtin print operators */
{ 1, 2, {0,0,0,0,0,5}, {32,550,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-551 */
const struct dom_sid global_sid_Builtin_Backup_Operators =	/* Builtin backup operators */
{ 1, 2, {0,0,0,0,0,5}, {32,551,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-552 */
const struct dom_sid global_sid_Builtin_Replicator =		/* Builtin replicator */
{ 1, 2, {0,0,0,0,0,5}, {32,552,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-32-554 */
const struct dom_sid global_sid_Builtin_PreWin2kAccess =	/* Builtin pre win2k access */
{ 1, 2, {0,0,0,0,0,5}, {32,554,0,0,0,0,0,0,0,0,0,0,0,0,0}};

/* S-1-22-1 */
const struct dom_sid global_sid_Unix_Users =			/* Unmapped Unix users */
{ 1, 1, {0,0,0,0,0,22}, {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-22-2 */
const struct dom_sid global_sid_Unix_Groups =			/* Unmapped Unix groups */
{ 1, 1, {0,0,0,0,0,22}, {2,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};

/*
 * http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */
/* S-1-5-88 */
const struct dom_sid global_sid_Unix_NFS =             /* MS NFS and Apple style */
{ 1, 1, {0,0,0,0,0,5}, {88,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-88-1 */
const struct dom_sid global_sid_Unix_NFS_Users =		/* Unix uid, MS NFS and Apple style */
{ 1, 2, {0,0,0,0,0,5}, {88,1,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-88-2 */
const struct dom_sid global_sid_Unix_NFS_Groups =		/* Unix gid, MS NFS and Apple style */
{ 1, 2, {0,0,0,0,0,5}, {88,2,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* S-1-5-88-3 */
const struct dom_sid global_sid_Unix_NFS_Mode =			/* Unix mode */
{ 1, 2, {0,0,0,0,0,5}, {88,3,0,0,0,0,0,0,0,0,0,0,0,0,0}};
/* Unused, left here for documentary purposes */
#if 0
const struct dom_sid global_sid_Unix_NFS_Other =		/* Unix other, MS NFS and Apple style */
{ 1, 2, {0,0,0,0,0,5}, {88,4,0,0,0,0,0,0,0,0,0,0,0,0,0}};
#endif

/* Unused, left here for documentary purposes */
#if 0
#define SECURITY_NULL_SID_AUTHORITY    0
#define SECURITY_WORLD_SID_AUTHORITY   1
#define SECURITY_LOCAL_SID_AUTHORITY   2
#define SECURITY_CREATOR_SID_AUTHORITY 3
#define SECURITY_NT_AUTHORITY          5
#endif

static struct dom_sid system_sid_array[1] =
{ { 1, 1, {0,0,0,0,0,5}, {18,0,0,0,0,0,0,0,0,0,0,0,0,0,0}} };
static const struct security_token system_token = {
	.num_sids       = ARRAY_SIZE(system_sid_array),
	.sids           = system_sid_array,
	.privilege_mask = SE_ALL_PRIVS
};

/****************************************************************************
 Lookup string names for SID types.
****************************************************************************/

static const struct {
	enum lsa_SidType sid_type;
	const char *string;
} sid_name_type[] = {
	{SID_NAME_USE_NONE, "None"},
	{SID_NAME_USER, "User"},
	{SID_NAME_DOM_GRP, "Domain Group"},
	{SID_NAME_DOMAIN, "Domain"},
	{SID_NAME_ALIAS, "Local Group"},
	{SID_NAME_WKN_GRP, "Well-known Group"},
	{SID_NAME_DELETED, "Deleted Account"},
	{SID_NAME_INVALID, "Invalid Account"},
	{SID_NAME_UNKNOWN, "UNKNOWN"},
	{SID_NAME_COMPUTER, "Computer"},
	{SID_NAME_LABEL, "Mandatory Label"}
};

const char *sid_type_lookup(uint32_t sid_type)
{
	size_t i;

	/* Look through list */
	for (i=0; i < ARRAY_SIZE(sid_name_type); i++) {
		if (sid_name_type[i].sid_type == sid_type) {
			return sid_name_type[i].string;
		}
	}

	/* Default return */
	return "SID *TYPE* is INVALID";
}

/**************************************************************************
 Create the SYSTEM token.
***************************************************************************/

const struct security_token *get_system_token(void)
{
	return &system_token;
}

bool sid_compose(struct dom_sid *dst, const struct dom_sid *domain_sid, uint32_t rid)
{
	sid_copy(dst, domain_sid);
	return sid_append_rid(dst, rid);
}

/*****************************************************************
 Removes the last rid from the end of a sid
*****************************************************************/

bool sid_split_rid(struct dom_sid *sid, uint32_t *rid)
{
	if (sid->num_auths > 0) {
		sid->num_auths--;
		if (rid != NULL) {
			*rid = sid->sub_auths[sid->num_auths];
		}
		return true;
	}
	return false;
}

/*****************************************************************
 Return the last rid from the end of a sid
*****************************************************************/

bool sid_peek_rid(const struct dom_sid *sid, uint32_t *rid)
{
	if (!sid || !rid)
		return false;

	if (sid->num_auths > 0) {
		*rid = sid->sub_auths[sid->num_auths - 1];
		return true;
	}
	return false;
}

/*****************************************************************
 Return the last rid from the end of a sid
 and check the sid against the exp_dom_sid
*****************************************************************/

bool sid_peek_check_rid(const struct dom_sid *exp_dom_sid, const struct dom_sid *sid, uint32_t *rid)
{
	if (!exp_dom_sid || !sid || !rid)
		return false;

	if (sid->num_auths != (exp_dom_sid->num_auths+1)) {
		return false;
	}

	if (sid_compare_domain(exp_dom_sid, sid)!=0){
		*rid=(-1);
		return false;
	}

	return sid_peek_rid(sid, rid);
}

/*****************************************************************
 Copies a sid
*****************************************************************/

void sid_copy(struct dom_sid *dst, const struct dom_sid *src)
{
	int i;

	*dst = (struct dom_sid) {
		.sid_rev_num = src->sid_rev_num,
		.num_auths = src->num_auths,
	};

	memcpy(&dst->id_auth[0], &src->id_auth[0], sizeof(src->id_auth));

	for (i = 0; i < src->num_auths; i++)
		dst->sub_auths[i] = src->sub_auths[i];
}

/*****************************************************************
 Parse a on-the-wire SID to a struct dom_sid.
*****************************************************************/

ssize_t sid_parse(const uint8_t *inbuf, size_t len, struct dom_sid *sid)
{
	DATA_BLOB in = data_blob_const(inbuf, len);
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob_all(
		&in, NULL, sid, (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}
	return ndr_size_dom_sid(sid, 0);
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

	return dom_sid_compare_auth(sid1, sid2);
}

/********************************************************************
 Add SID to an array SIDs
********************************************************************/

NTSTATUS add_sid_to_array(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			  struct dom_sid **sids, uint32_t *num)
{
	struct dom_sid *tmp;

	if ((*num) == UINT32_MAX) {
		return NT_STATUS_INTEGER_OVERFLOW;
	}

	tmp = talloc_realloc(mem_ctx, *sids, struct dom_sid, (*num)+1);
	if (tmp == NULL) {
		*num = 0;
		return NT_STATUS_NO_MEMORY;
	}
	*sids = tmp;

	sid_copy(&((*sids)[*num]), sid);
	*num += 1;

	return NT_STATUS_OK;
}


/********************************************************************
 Add SID to an array SIDs ensuring that it is not already there
********************************************************************/

NTSTATUS add_sid_to_array_unique(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
				 struct dom_sid **sids, uint32_t *num_sids)
{
	uint32_t i;

	for (i=0; i<(*num_sids); i++) {
		if (dom_sid_equal(sid, &(*sids)[i])) {
			return NT_STATUS_OK;
		}
	}

	return add_sid_to_array(mem_ctx, sid, sids, num_sids);
}

/********************************************************************
 Remove SID from an array
********************************************************************/

void del_sid_from_array(const struct dom_sid *sid, struct dom_sid **sids,
			uint32_t *num)
{
	struct dom_sid *sid_list = *sids;
	uint32_t i;

	for ( i=0; i<*num; i++ ) {

		/* if we find the SID, then decrement the count
		   and break out of the loop */

		if (dom_sid_equal(sid, &sid_list[i])) {
			*num -= 1;
			break;
		}
	}

	/* This loop will copy the remainder of the array
	   if i < num of sids in the array */

	for ( ; i<*num; i++ ) {
		sid_copy( &sid_list[i], &sid_list[i+1] );
	}

	return;
}

bool add_rid_to_array_unique(TALLOC_CTX *mem_ctx,
			     uint32_t rid, uint32_t **pp_rids, size_t *p_num)
{
	size_t i;

	for (i=0; i<*p_num; i++) {
		if ((*pp_rids)[i] == rid)
			return true;
	}

	*pp_rids = talloc_realloc(mem_ctx, *pp_rids, uint32_t, *p_num+1);

	if (*pp_rids == NULL) {
		*p_num = 0;
		return false;
	}

	(*pp_rids)[*p_num] = rid;
	*p_num += 1;
	return true;
}

bool is_null_sid(const struct dom_sid *sid)
{
	const struct dom_sid null_sid = {0};
	return dom_sid_equal(sid, &null_sid);
}

/*
 * See [MS-LSAT] 3.1.1.1.1 Predefined Translation Database and Corresponding View
 */
struct predefined_name_mapping {
	const char *name;
	enum lsa_SidType type;
	struct dom_sid sid;
};

struct predefined_domain_mapping {
	const char *domain;
	struct dom_sid sid;
	size_t num_names;
	const struct predefined_name_mapping *names;
};

/* S-1-${AUTHORITY} */
#define _SID0(authority) \
	{ 1, 0, {0,0,0,0,0,authority}, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}
/* S-1-${AUTHORITY}-${SUB1} */
#define _SID1(authority,sub1) \
	{ 1, 1, {0,0,0,0,0,authority}, {sub1,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}
/* S-1-${AUTHORITY}-${SUB1}-${SUB2} */
#define _SID2(authority,sub1,sub2) \
	{ 1, 2, {0,0,0,0,0,authority}, {sub1,sub2,0,0,0,0,0,0,0,0,0,0,0,0,0}}

/*
 * S-1-0
 */
static const struct predefined_name_mapping predefined_names_S_1_0[] = {
	{
		.name = "NULL SID",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(0, 0), /* S-1-0-0 */
	},
};

/*
 * S-1-1
 */
static const struct predefined_name_mapping predefined_names_S_1_1[] = {
	{
		.name = "Everyone",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(1, 0), /* S-1-1-0 */
	},
};

/*
 * S-1-2
 */
static const struct predefined_name_mapping predefined_names_S_1_2[] = {
	{
		.name = "LOCAL",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(2, 0), /* S-1-2-0 */
	},
};

/*
 * S-1-3
 */
static const struct predefined_name_mapping predefined_names_S_1_3[] = {
	{
		.name = "CREATOR OWNER",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(3, 0), /* S-1-3-0 */
	},
	{
		.name = "CREATOR GROUP",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(3, 1), /* S-1-3-1 */
	},
	{
		.name = "CREATOR OWNER SERVER",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(3, 0), /* S-1-3-2 */
	},
	{
		.name = "CREATOR GROUP SERVER",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(3, 1), /* S-1-3-3 */
	},
	{
		.name = "OWNER RIGHTS",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(3, 4), /* S-1-3-4 */
	},
};

/*
 * S-1-5 only 'NT Pseudo Domain'
 */
static const struct predefined_name_mapping predefined_names_S_1_5p[] = {
	{
		.name = "NT Pseudo Domain",
		.type = SID_NAME_DOMAIN,
		.sid = _SID0(5), /* S-1-5 */
	},
};

/*
 * S-1-5 'NT AUTHORITY'
 */
static const struct predefined_name_mapping predefined_names_S_1_5a[] = {
	{
		.name = "DIALUP",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 1), /* S-1-5-1 */
	},
	{
		.name = "NETWORK",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 2), /* S-1-5-2 */
	},
	{
		.name = "BATCH",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 3), /* S-1-5-3 */
	},
	{
		.name = "INTERACTIVE",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 4), /* S-1-5-4 */
	},
	{
		.name = "SERVICE",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 6), /* S-1-5-6 */
	},
	{
		.name = "ANONYMOUS LOGON",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 7), /* S-1-5-7 */
	},
	{
		.name = "PROXY",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 8), /* S-1-5-8 */
	},
	{
		.name = "ENTERPRISE DOMAIN CONTROLLERS",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 9), /* S-1-5-9 */
	},
	{
		.name = "SELF",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 10), /* S-1-5-10 */
	},
	{
		.name = "Authenticated Users",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 11), /* S-1-5-11 */
	},
	{
		.name = "RESTRICTED",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 12), /* S-1-5-12 */
	},
	{
		.name = "TERMINAL SERVER USER",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 13), /* S-1-5-13 */
	},
	{
		.name = "REMOTE INTERACTIVE LOGON",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 14), /* S-1-5-14 */
	},
	{
		.name = "This Organization",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 15), /* S-1-5-15 */
	},
	{
		.name = "IUSR",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 17), /* S-1-5-17 */
	},
	{
		.name = "SYSTEM",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 18), /* S-1-5-18 */
	},
	{
		.name = "LOCAL SERVICE",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 19), /* S-1-5-19 */
	},
	{
		.name = "NETWORK SERVICE",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 20), /* S-1-5-20 */
	},
	{
		.name = "WRITE RESTRICTED",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 33), /* S-1-5-33 */
	},
	{
		.name = "Other Organization",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID1(5, 1000), /* S-1-5-1000 */
	},
};

/*
 * S-1-5-32
 */
static const struct predefined_name_mapping predefined_names_S_1_5_32[] = {
	{
		.name = "BUILTIN",
		.type = SID_NAME_DOMAIN,
		.sid = _SID1(5, 32), /* S-1-5-32 */
	},
};

/*
 * S-1-5-64
 */
static const struct predefined_name_mapping predefined_names_S_1_5_64[] = {
	{
		.name = "NTLM Authentication",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID2(5, 64, 10), /* S-1-5-64-10 */
	},
	{
		.name = "SChannel Authentication",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID2(5, 64, 14), /* S-1-5-64-14 */
	},
	{
		.name = "Digest Authentication",
		.type = SID_NAME_WKN_GRP,
		.sid = _SID2(5, 64, 21), /* S-1-5-64-21 */
	},
};

/*
 * S-1-7
 */
static const struct predefined_name_mapping predefined_names_S_1_7[] = {
	{
		.name = "Internet$",
		.type = SID_NAME_DOMAIN,
		.sid = _SID0(7), /* S-1-7 */
	},
};

/*
 * S-1-16
 */
static const struct predefined_name_mapping predefined_names_S_1_16[] = {
	{
		.name = "Mandatory Label",
		.type = SID_NAME_DOMAIN,
		.sid = _SID0(16), /* S-1-16 */
	},
	{
		.name = "Untrusted Mandatory Level",
		.type = SID_NAME_LABEL,
		.sid = _SID1(16, 0), /* S-1-16-0 */
	},
	{
		.name = "Low Mandatory Level",
		.type = SID_NAME_LABEL,
		.sid = _SID1(16, 4096), /* S-1-16-4096 */
	},
	{
		.name = "Medium Mandatory Level",
		.type = SID_NAME_LABEL,
		.sid = _SID1(16, 8192), /* S-1-16-8192 */
	},
	{
		.name = "High Mandatory Level",
		.type = SID_NAME_LABEL,
		.sid = _SID1(16, 12288), /* S-1-16-12288 */
	},
	{
		.name = "System Mandatory Level",
		.type = SID_NAME_LABEL,
		.sid = _SID1(16, 16384), /* S-1-16-16384 */
	},
	{
		.name = "Protected Process Mandatory Level",
		.type = SID_NAME_LABEL,
		.sid = _SID1(16, 20480), /* S-1-16-20480 */
	},
};

static const struct predefined_domain_mapping predefined_domains[] = {
	{
		.domain = "",
		.sid = _SID0(0), /* S-1-0 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_0),
		.names = predefined_names_S_1_0,
	},
	{
		.domain = "",
		.sid = _SID0(1), /* S-1-1 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_1),
		.names = predefined_names_S_1_1,
	},
	{
		.domain = "",
		.sid = _SID0(2), /* S-1-2 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_2),
		.names = predefined_names_S_1_2,
	},
	{
		.domain = "",
		.sid = _SID0(3), /* S-1-3 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_3),
		.names = predefined_names_S_1_3,
	},
	{
		.domain = "",
		.sid = _SID0(3), /* S-1-3 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_3),
		.names = predefined_names_S_1_3,
	},
	/*
	 * S-1-5 is split here
	 *
	 * 'NT Pseudo Domain' has precedence before 'NT AUTHORITY'.
	 *
	 * In a LookupSids with multiple sids e.g. S-1-5 and S-1-5-7
	 * the domain section (struct lsa_DomainInfo) gets
	 * 'NT Pseudo Domain' with S-1-5. If asked in reversed order
	 * S-1-5-7 and then S-1-5, you get struct lsa_DomainInfo
	 * with 'NT AUTHORITY' and S-1-5.
	 */
	{
		.domain = "NT Pseudo Domain",
		.sid = _SID0(5), /* S-1-5 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_5p),
		.names = predefined_names_S_1_5p,
	},
	{
		.domain = "NT AUTHORITY",
		.sid = _SID0(5), /* S-1-5 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_5a),
		.names = predefined_names_S_1_5a,
	},
	{
		.domain = "BUILTIN",
		.sid = _SID1(5, 32), /* S-1-5-32 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_5_32),
		.names = predefined_names_S_1_5_32,
	},
	/*
	 * 'NT AUTHORITY' again with S-1-5-64 this time
	 */
	{
		.domain = "NT AUTHORITY",
		.sid = _SID1(5, 64), /* S-1-5-64 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_5_64),
		.names = predefined_names_S_1_5_64,
	},
	{
		.domain = "Internet$",
		.sid = _SID0(7), /* S-1-7 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_7),
		.names = predefined_names_S_1_7,
	},
	{
		.domain = "Mandatory Label",
		.sid = _SID0(16), /* S-1-16 */
		.num_names = ARRAY_SIZE(predefined_names_S_1_16),
		.names = predefined_names_S_1_16,
	},
};

NTSTATUS dom_sid_lookup_predefined_name(const char *name,
					const struct dom_sid **sid,
					enum lsa_SidType *type,
					const struct dom_sid **authority_sid,
					const char **authority_name)
{
	size_t di;
	const char *domain = "";
	size_t domain_len = 0;
	const char *p;
	bool match;

	*sid = NULL;
	*type = SID_NAME_UNKNOWN;
	*authority_sid = NULL;
	*authority_name = NULL;

	if (name == NULL) {
		name = "";
	}

	p = strchr(name, '\\');
	if (p != NULL) {
		domain = name;
		domain_len = PTR_DIFF(p, domain);
		name = p + 1;
	}

	match = strequal(name, "");
	if (match) {
		/*
		 * Strange, but that's what W2012R2 does.
		 */
		name = "BUILTIN";
	}

	for (di = 0; di < ARRAY_SIZE(predefined_domains); di++) {
		const struct predefined_domain_mapping *d =
			&predefined_domains[di];
		size_t ni;

		if (domain_len != 0) {
			int cmp;

			cmp = strncasecmp(d->domain, domain, domain_len);
			if (cmp != 0) {
				continue;
			}
		}

		for (ni = 0; ni < d->num_names; ni++) {
			const struct predefined_name_mapping *n =
				&d->names[ni];

			match = strequal(n->name, name);
			if (!match) {
				continue;
			}

			*sid = &n->sid;
			*type = n->type;
			*authority_sid = &d->sid;
			*authority_name = d->domain;
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_NONE_MAPPED;
}

bool dom_sid_lookup_is_predefined_domain(const char *domain)
{
	size_t di;
	bool match;

	if (domain == NULL) {
		domain = "";
	}

	match = strequal(domain, "");
	if (match) {
		/*
		 * Strange, but that's what W2012R2 does.
		 */
		domain = "BUILTIN";
	}

	for (di = 0; di < ARRAY_SIZE(predefined_domains); di++) {
		const struct predefined_domain_mapping *d =
			&predefined_domains[di];
		int cmp;

		cmp = strcasecmp(d->domain, domain);
		if (cmp != 0) {
			continue;
		}

		return true;
	}

	return false;
}

NTSTATUS dom_sid_lookup_predefined_sid(const struct dom_sid *sid,
				       const char **name,
				       enum lsa_SidType *type,
				       const struct dom_sid **authority_sid,
				       const char **authority_name)
{
	size_t di;
	bool match_domain = false;

	*name = NULL;
	*type = SID_NAME_UNKNOWN;
	*authority_sid = NULL;
	*authority_name = NULL;

	if (sid == NULL) {
		return NT_STATUS_INVALID_SID;
	}

	for (di = 0; di < ARRAY_SIZE(predefined_domains); di++) {
		const struct predefined_domain_mapping *d =
			&predefined_domains[di];
		size_t ni;
		int cmp;

		cmp = dom_sid_compare_auth(&d->sid, sid);
		if (cmp != 0) {
			continue;
		}

		match_domain = true;

		for (ni = 0; ni < d->num_names; ni++) {
			const struct predefined_name_mapping *n =
				&d->names[ni];

			cmp = dom_sid_compare(&n->sid, sid);
			if (cmp != 0) {
				continue;
			}

			*name = n->name;
			*type = n->type;
			*authority_sid = &d->sid;
			*authority_name = d->domain;
			return NT_STATUS_OK;
		}
	}

	if (!match_domain) {
		return NT_STATUS_INVALID_SID;
	}

	return NT_STATUS_NONE_MAPPED;
}
