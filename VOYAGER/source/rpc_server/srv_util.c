/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
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

rid_name builtin_alias_rids[] =
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
rid_name domain_user_rids[] =
{  
    { DOMAIN_USER_RID_ADMIN         , "Administrator" },
    { DOMAIN_USER_RID_GUEST         , "Guest" },
    { 0                             , NULL }
};

/* array lookup of well-known Domain RID groups. */
rid_name domain_group_rids[] =
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
	GROUP_MAP *map=NULL;
	int i, num, num_entries, cur_gid=0;
	struct group *grp;
	DOM_GID *gids;
	fstring user_name;
	uint32 grid;
	uint32 tmp_rid;
	BOOL ret;

	*numgroups= 0;

	fstrcpy(user_name, pdb_get_username(sam_pass));
	grid=pdb_get_group_rid(sam_pass);

	DEBUG(10,("get_domain_user_groups: searching domain groups [%s] is a member of\n", user_name));

	/* we must wrap this is become/unbecome root for ldap backends */
	
	become_root();
	/* first get the list of the domain groups */
	ret = pdb_enum_group_mapping(SID_NAME_DOM_GRP, &map, &num_entries, ENUM_ONLY_MAPPED);
	
	unbecome_root();

	/* end wrapper for group enumeration */

	
	if ( !ret )
		return False;
		
	DEBUG(10,("get_domain_user_groups: there are %d mapped groups\n", num_entries));


	/* 
	 * alloc memory. In the worse case, we alloc memory for nothing.
	 * but I prefer to alloc for nothing
	 * than reallocing everytime.
	 */
	gids = (DOM_GID *)talloc(ctx, sizeof(DOM_GID) *  num_entries);	

	/* for each group, check if the user is a member of.  Only include groups 
	   from this domain */
	
	for(i=0; i<num_entries; i++) {
	
		if ( !sid_check_is_in_our_domain(&map[i].sid) ) {
			DEBUG(10,("get_domain_user_groups: skipping check of %s since it is not in our domain\n",
				map[i].nt_name));
			continue;
		}
			
		if ((grp=getgrgid(map[i].gid)) == NULL) {
			/* very weird !!! */
			DEBUG(5,("get_domain_user_groups: gid %d doesn't exist anymore !\n", (int)map[i].gid));
			continue;
		}

		for(num=0; grp->gr_mem[num]!=NULL; num++) {
			if(strcmp(grp->gr_mem[num], user_name)==0) {
				/* we found the user, add the group to the list */
				sid_peek_rid(&map[i].sid, &(gids[cur_gid].g_rid));
				gids[cur_gid].attr=7;
				DEBUG(10,("get_domain_user_groups: user found in group %s\n", map[i].nt_name));
				cur_gid++;
				break;
			}
		}
	}

	/* we have checked the groups */
	/* we must now check the gid of the user or the primary group rid, that's the same */
	for (i=0; i<cur_gid && grid!=gids[i].g_rid; i++)
		;
	
	/* the user's gid is already there */
	if (i!=cur_gid) {
		/* 
		 * the primary group of the user but be the first one in the list
		 * don't ask ! JFM.
		 */
		gids[i].g_rid=gids[0].g_rid;
		gids[0].g_rid=grid;
		goto done;
	}

	for(i=0; i<num_entries; i++) {
		sid_peek_rid(&map[i].sid, &tmp_rid);
		if (tmp_rid==grid) {
			/* 
			 * the primary group of the user but be the first one in the list
			 * don't ask ! JFM.
			 */
			gids[cur_gid].g_rid=gids[0].g_rid;
			gids[0].g_rid=tmp_rid;
			gids[cur_gid].attr=7;
			DEBUG(10,("get_domain_user_groups: primary gid of user found in group %s\n", map[i].nt_name));
			cur_gid++;
			goto done; /* leave the loop early */
		}
	}

	DEBUG(0,("get_domain_user_groups: primary gid of user [%s] is not a Domain group !\n", user_name));
	DEBUGADD(0,("get_domain_user_groups: You should fix it, NT doesn't like that\n"));


 done:
	*pgids=gids;
	*numgroups=cur_gid;
	SAFE_FREE(map);

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

/*******************************************************************
 Look up a local (domain) rid and return a name and type.
 ********************************************************************/
NTSTATUS local_lookup_group_name(uint32 rid, char *group_name, uint32 *type)
{
	int i = 0; 
	(*type) = SID_NAME_DOM_GRP;

	DEBUG(5,("lookup_group_name: rid: %d", rid));

	while (domain_group_rids[i].rid != rid && domain_group_rids[i].rid != 0)
	{
		i++;
	}

	if (domain_group_rids[i].rid != 0)
	{
		fstrcpy(group_name, domain_group_rids[i].name);
		DEBUG(5,(" = %s\n", group_name));
		return NT_STATUS_OK;
	}

	DEBUG(5,(" none mapped\n"));
	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local alias rid and return a name and type.
 ********************************************************************/
NTSTATUS local_lookup_alias_name(uint32 rid, char *alias_name, uint32 *type)
{
	int i = 0; 
	(*type) = SID_NAME_WKN_GRP;

	DEBUG(5,("lookup_alias_name: rid: %d", rid));

	while (builtin_alias_rids[i].rid != rid && builtin_alias_rids[i].rid != 0)
	{
		i++;
	}

	if (builtin_alias_rids[i].rid != 0)
	{
		fstrcpy(alias_name, builtin_alias_rids[i].name);
		DEBUG(5,(" = %s\n", alias_name));
		return NT_STATUS_OK;
	}

	DEBUG(5,(" none mapped\n"));
	return NT_STATUS_NONE_MAPPED;
}


#if 0 /*Nobody uses this function just now*/
/*******************************************************************
 Look up a local user rid and return a name and type.
 ********************************************************************/
NTSTATUS local_lookup_user_name(uint32 rid, char *user_name, uint32 *type)
{
	SAM_ACCOUNT *sampwd=NULL;
	int i = 0;
	BOOL ret;
	
	(*type) = SID_NAME_USER;

	DEBUG(5,("lookup_user_name: rid: %d", rid));

	/* look up the well-known domain user rids first */
	while (domain_user_rids[i].rid != rid && domain_user_rids[i].rid != 0)
	{
		i++;
	}

	if (domain_user_rids[i].rid != 0) {
		fstrcpy(user_name, domain_user_rids[i].name);
		DEBUG(5,(" = %s\n", user_name));
		return NT_STATUS_OK;
	}

	pdb_init_sam(&sampwd);

	/* ok, it's a user.  find the user account */
	become_root();
	ret = pdb_getsampwrid(sampwd, rid);
	unbecome_root();

	if (ret == True) {
		fstrcpy(user_name, pdb_get_username(sampwd) );
		DEBUG(5,(" = %s\n", user_name));
		pdb_free_sam(&sampwd);
		return NT_STATUS_OK;
	}

	DEBUG(5,(" none mapped\n"));
	pdb_free_sam(&sampwd);
	return NT_STATUS_NONE_MAPPED;
}

#endif

/*******************************************************************
 Look up a local (domain) group name and return a rid
 ********************************************************************/
NTSTATUS local_lookup_group_rid(char *group_name, uint32 *rid)
{
	const char *grp_name;
	int i = -1; /* start do loop at -1 */

	do /* find, if it exists, a group rid for the group name*/
	{
		i++;
		(*rid) = domain_group_rids[i].rid;
		grp_name = domain_group_rids[i].name;

	} while (grp_name != NULL && !strequal(grp_name, group_name));

	return (grp_name != NULL) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local (BUILTIN) alias name and return a rid
 ********************************************************************/
NTSTATUS local_lookup_alias_rid(const char *alias_name, uint32 *rid)
{
	const char *als_name;
	int i = -1; /* start do loop at -1 */

	do /* find, if it exists, a alias rid for the alias name*/
	{
		i++;
		(*rid) = builtin_alias_rids[i].rid;
		als_name = builtin_alias_rids[i].name;

	} while (als_name != NULL && !strequal(als_name, alias_name));

	return (als_name != NULL) ? NT_STATUS_OK : NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 Look up a local user name and return a rid
 ********************************************************************/
NTSTATUS local_lookup_user_rid(char *user_name, uint32 *rid)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;

	(*rid) = 0;

	pdb_init_sam(&sampass);

	/* find the user account */
	become_root();
	ret = pdb_getsampwnam(sampass, user_name);
	unbecome_root();

	if (ret == True) {
		(*rid) = pdb_get_user_rid(sampass);
		pdb_free_sam(&sampass);
		return NT_STATUS_OK;
	}

	pdb_free_sam(&sampass);
	return NT_STATUS_NONE_MAPPED;
}
