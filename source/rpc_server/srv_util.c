/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998,
 *  Copyright (C) Andrew Bartlett                   2004.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 *  in this version, which takes a "let's learn what's going on and
 *  get something running" approach, there is additional network
 *  traffic generated, but the code should be easier to understand...
 *
 *  ... if you read the docs.  or stare at packets for weeks on end.
 *
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*
 * A list of the rids of well known BUILTIN and Domain users
 * and groups.
 */

static const rid_name builtin_alias_rids[] =
{  
    { BUILTIN_ALIAS_RID_ADMINS       , "Administrators" },
    { BUILTIN_ALIAS_RID_USERS        , "Users" },
    { BUILTIN_ALIAS_RID_GUESTS       , "Guests" },
    { BUILTIN_ALIAS_RID_POWER_USERS  , "Power Users" },
   
    { BUILTIN_ALIAS_RID_ACCOUNT_OPS  , "Account Operators" },
    { BUILTIN_ALIAS_RID_SYSTEM_OPS   , "System Operators" },
    { BUILTIN_ALIAS_RID_PRINT_OPS    , "Print Operators" },
    { BUILTIN_ALIAS_RID_BACKUP_OPS   , "Backup Operators" },
    { BUILTIN_ALIAS_RID_REPLICATOR   , "Replicator" },
    { 0                             , NULL }
};

/* array lookup of well-known Domain RID users. */
static const rid_name domain_user_rids[] =
{  
    { DOMAIN_USER_RID_ADMIN         , "Administrator" },
    { DOMAIN_USER_RID_GUEST         , "Guest" },
    { 0                             , NULL }
};

/* array lookup of well-known Domain RID groups. */
static const rid_name domain_group_rids[] =
{  
    { DOMAIN_GROUP_RID_ADMINS       , "Domain Admins" },
    { DOMAIN_GROUP_RID_USERS        , "Domain Users" },
    { DOMAIN_GROUP_RID_GUESTS       , "Domain Guests" },
    { 0                             , NULL }
};

/*******************************************************************
 gets a domain user's groups
 ********************************************************************/
BOOL get_domain_user_groups(TALLOC_CTX *ctx, int *numgroups, DOM_GID **pgids, SAM_ACCOUNT *sam_pass)
{

	const char *username = pdb_get_username(sam_pass);
	int		n_unix_groups;
	int		i,j;
	gid_t *unix_groups;

	*numgroups = 0;
	*pgids   = NULL;
	
	if (!getgroups_user(username, &unix_groups, &n_unix_groups)) {
		return False;
	}

	/* now setup the space for storing the SIDS */
	
	if (n_unix_groups > 0) {
	
		*pgids   = talloc(ctx, sizeof(DOM_GID) * n_unix_groups);
		
		if (!*pgids) {
			DEBUG(0, ("get_user_group: malloc() failed for DOM_GID list!\n"));
			SAFE_FREE(unix_groups);
			return False;
		}
	}

	become_root();
	j = 0;
	for (i = 0; i < n_unix_groups; i++) {
		GROUP_MAP map;
		uint32 rid;
		
		if (!pdb_getgrgid(&map, unix_groups[i])) {
			DEBUG(3, ("get_user_groups: failed to convert gid %ld to a domain group!\n", 
				(long int)unix_groups[i+1]));
			if (i == 0) {
				DEBUG(1,("get_domain_user_groups: primary gid of user [%s] is not a Domain group !\n", username));
				DEBUGADD(1,("get_domain_user_groups: You should fix it, NT doesn't like that\n"));
			}
		} else if ((map.sid_name_use == SID_NAME_DOM_GRP)
			   && sid_peek_check_rid(get_global_sam_sid(), &map.sid, &rid)) {
			(*pgids)[j].attr=7;
			(*pgids)[j].g_rid=rid;
			j++;
		}
	}
	unbecome_root();

	*numgroups = j;

	SAFE_FREE(unix_groups);

	return True;
}

/*******************************************************************
 gets a domain user's groups from their already-calculated NT_USER_TOKEN
 ********************************************************************/
NTSTATUS nt_token_to_group_list(TALLOC_CTX *mem_ctx, const DOM_SID *domain_sid, 
				const NT_USER_TOKEN *nt_token,
				int *numgroups, DOM_GID **pgids) 
{
	DOM_GID *gids;
	int i;

	gids = (DOM_GID *)talloc(mem_ctx, sizeof(*gids) * nt_token->num_sids);

	if (!gids) {
		return NT_STATUS_NO_MEMORY;
	}

	*numgroups=0;

	for (i=PRIMARY_GROUP_SID_INDEX; i < nt_token->num_sids; i++) {
		if (sid_compare_domain(domain_sid, &nt_token->user_sids[i])==0) {
			sid_peek_rid(&nt_token->user_sids[i], &(gids[*numgroups].g_rid));
			gids[*numgroups].attr=7;
			(*numgroups)++;
		}
	}
	*pgids = gids; 
	return NT_STATUS_OK;
}

