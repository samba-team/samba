/* 
 *  Unix SMB/CIFS implementation.
 *  Authentication utility functions
 *  Copyright (C) Andrew Tridgell 1992-1998
 *  Copyright (C) Andrew Bartlett 2001
 *  Copyright (C) Jeremy Allison 2000-2001
 *  Copyright (C) Rafal Szczesniak 2002
 *  Copyright (C) Volker Lendecke 2006
 *  Copyright (C) Michael Adam 2007
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

/* functions moved from auth/auth_util.c to minimize linker deps */

#include "includes.h"

/****************************************************************************
 Duplicate a SID token.
****************************************************************************/

NT_USER_TOKEN *dup_nt_token(TALLOC_CTX *mem_ctx, const NT_USER_TOKEN *ptoken)
{
	NT_USER_TOKEN *token;

	if (!ptoken)
		return NULL;

	token = TALLOC_P(mem_ctx, NT_USER_TOKEN);
	if (token == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	ZERO_STRUCTP(token);

	if (ptoken->user_sids && ptoken->num_sids) {
		token->user_sids = (DOM_SID *)talloc_memdup(
			token, ptoken->user_sids, sizeof(DOM_SID) * ptoken->num_sids );

		if (token->user_sids == NULL) {
			DEBUG(0, ("talloc_memdup failed\n"));
			TALLOC_FREE(token);
			return NULL;
		}
		token->num_sids = ptoken->num_sids;
	}
	
	/* copy the privileges; don't consider failure to be critical here */
	
	if ( !se_priv_copy( &token->privileges, &ptoken->privileges ) ) {
		DEBUG(0,("dup_nt_token: Failure to copy SE_PRIV!.  "
			 "Continuing with 0 privileges assigned.\n"));
	}

	return token;
}

/****************************************************************************
 Check for a SID in an NT_USER_TOKEN
****************************************************************************/

BOOL nt_token_check_sid ( const DOM_SID *sid, const NT_USER_TOKEN *token )
{
	int i;
	
	if ( !sid || !token )
		return False;
	
	for ( i=0; i<token->num_sids; i++ ) {
		if ( sid_equal( sid, &token->user_sids[i] ) )
			return True;
	}

	return False;
}

BOOL nt_token_check_domain_rid( NT_USER_TOKEN *token, uint32 rid ) 
{
	DOM_SID domain_sid;

	/* if we are a domain member, the get the domain SID, else for 
	   a DC or standalone server, use our own SID */

	if ( lp_server_role() == ROLE_DOMAIN_MEMBER ) {
		if ( !secrets_fetch_domain_sid( lp_workgroup(),
						&domain_sid ) ) {
			DEBUG(1,("nt_token_check_domain_rid: Cannot lookup "
				 "SID for domain [%s]\n", lp_workgroup()));
			return False;
		}
	} 
	else
		sid_copy( &domain_sid, get_global_sam_sid() );

	sid_append_rid( &domain_sid, rid );
	
	return nt_token_check_sid( &domain_sid, token );\
}

/******************************************************************************
 Create a token for the root user to be used internally by smbd.
 This is similar to running under the context of the LOCAL_SYSTEM account
 in Windows.  This is a read-only token.  Do not modify it or free() it.
 Create a copy if your need to change it.
******************************************************************************/

NT_USER_TOKEN *get_root_nt_token( void )
{
	static NT_USER_TOKEN *token = NULL;
	DOM_SID u_sid, g_sid;
	struct passwd *pw;
	
	if ( token )
		return token;

	if ( !(pw = sys_getpwnam( "root" )) ) {
		DEBUG(0,("get_root_nt_token: getpwnam\"root\") failed!\n"));
		return NULL;
	}
	
	/* get the user and primary group SIDs; although the 
	   BUILTIN\Administrators SId is really the one that matters here */
	   
	uid_to_sid(&u_sid, pw->pw_uid);
	gid_to_sid(&g_sid, pw->pw_gid);

	token = create_local_nt_token(NULL, &u_sid, False,
				      1, &global_sid_Builtin_Administrators);
	return token;
}


/*
 * Add alias SIDs from memberships within the partially created token SID list
 */

static NTSTATUS add_aliases(const DOM_SID *domain_sid,
			    struct nt_user_token *token)
{
	uint32 *aliases;
	size_t i, num_aliases;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	if (!(tmp_ctx = talloc_init("add_aliases"))) {
		return NT_STATUS_NO_MEMORY;
	}

	aliases = NULL;
	num_aliases = 0;

	status = pdb_enum_alias_memberships(tmp_ctx, domain_sid,
					    token->user_sids,
					    token->num_sids,
					    &aliases, &num_aliases);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("pdb_enum_alias_memberships failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	for (i=0; i<num_aliases; i++) {
		DOM_SID alias_sid;
		sid_compose(&alias_sid, domain_sid, aliases[i]);
		if (!add_sid_to_array_unique(token, &alias_sid,
					&token->user_sids,
					&token->num_sids)) {
			DEBUG(0, ("add_sid_to_array failed\n"));
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

/*******************************************************************
*******************************************************************/

static NTSTATUS add_builtin_administrators( struct nt_user_token *token )
{
	DOM_SID domadm;

	/* nothing to do if we aren't in a domain */
	
	if ( !(IS_DC || lp_server_role()==ROLE_DOMAIN_MEMBER) ) {
		return NT_STATUS_OK;
	}
	
	/* Find the Domain Admins SID */
	
	if ( IS_DC ) {
		sid_copy( &domadm, get_global_sam_sid() );
	} else {
		if ( !secrets_fetch_domain_sid( lp_workgroup(), &domadm ) )
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	sid_append_rid( &domadm, DOMAIN_GROUP_RID_ADMINS );
	
	/* Add Administrators if the user beloongs to Domain Admins */
	
	if ( nt_token_check_sid( &domadm, token ) ) {
		if (!add_sid_to_array(token, &global_sid_Builtin_Administrators,
					 &token->user_sids, &token->num_sids)) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	
	return NT_STATUS_OK;
}

/*******************************************************************
*******************************************************************/

static NTSTATUS create_builtin_users( void )
{
	NTSTATUS status;
	DOM_SID dom_users;

	status = pdb_create_builtin_alias( BUILTIN_ALIAS_RID_USERS );
	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(0,("create_builtin_users: Failed to create Users\n"));
		return status;
	}
	
	/* add domain users */
	if ((IS_DC || (lp_server_role() == ROLE_DOMAIN_MEMBER)) 
		&& secrets_fetch_domain_sid(lp_workgroup(), &dom_users))
	{
		sid_append_rid(&dom_users, DOMAIN_GROUP_RID_USERS );
		status = pdb_add_aliasmem( &global_sid_Builtin_Users, &dom_users);
		if ( !NT_STATUS_IS_OK(status) ) {
			DEBUG(0,("create_builtin_administrators: Failed to add Domain Users to"
				" Users\n"));
			return status;
		}
	}
			
	return NT_STATUS_OK;
}		

/*******************************************************************
*******************************************************************/

static NTSTATUS create_builtin_administrators( void )
{
	NTSTATUS status;
	DOM_SID dom_admins, root_sid;
	fstring root_name;
	enum lsa_SidType type;		
	TALLOC_CTX *ctx;
	BOOL ret;

	status = pdb_create_builtin_alias( BUILTIN_ALIAS_RID_ADMINS );
	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(0,("create_builtin_administrators: Failed to create Administrators\n"));
		return status;
	}
	
	/* add domain admins */
	if ((IS_DC || (lp_server_role() == ROLE_DOMAIN_MEMBER)) 
		&& secrets_fetch_domain_sid(lp_workgroup(), &dom_admins))
	{
		sid_append_rid(&dom_admins, DOMAIN_GROUP_RID_ADMINS);
		status = pdb_add_aliasmem( &global_sid_Builtin_Administrators, &dom_admins );
		if ( !NT_STATUS_IS_OK(status) ) {
			DEBUG(0,("create_builtin_administrators: Failed to add Domain Admins"
				" Administrators\n"));
			return status;
		}
	}
			
	/* add root */
	if ( (ctx = talloc_init("create_builtin_administrators")) == NULL ) {
		return NT_STATUS_NO_MEMORY;
	}
	fstr_sprintf( root_name, "%s\\root", get_global_sam_name() );
	ret = lookup_name( ctx, root_name, 0, NULL, NULL, &root_sid, &type );
	TALLOC_FREE( ctx );

	if ( ret ) {
		status = pdb_add_aliasmem( &global_sid_Builtin_Administrators, &root_sid );
		if ( !NT_STATUS_IS_OK(status) ) {
			DEBUG(0,("create_builtin_administrators: Failed to add root"
				" Administrators\n"));
			return status;
		}
	}
	
	return NT_STATUS_OK;
}		


/*******************************************************************
 Create a NT token for the user, expanding local aliases
*******************************************************************/

struct nt_user_token *create_local_nt_token(TALLOC_CTX *mem_ctx,
					    const DOM_SID *user_sid,
					    BOOL is_guest,
					    int num_groupsids,
					    const DOM_SID *groupsids)
{
	struct nt_user_token *result = NULL;
	int i;
	NTSTATUS status;
	gid_t gid;

	DEBUG(10, ("Create local NT token for %s\n", sid_string_static(user_sid)));

	if (!(result = TALLOC_ZERO_P(mem_ctx, NT_USER_TOKEN))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	/* Add the user and primary group sid */

	if (!add_sid_to_array(result, user_sid,
			 &result->user_sids, &result->num_sids)) {
		return NULL;
	}

	/* For guest, num_groupsids may be zero. */
	if (num_groupsids) {
		if (!add_sid_to_array(result, &groupsids[0],
				 &result->user_sids, &result->num_sids)) {
			return NULL;
		}
	}
			 
	/* Add in BUILTIN sids */
	
	if (!add_sid_to_array(result, &global_sid_World,
			 &result->user_sids, &result->num_sids)) {
		return NULL;
	}
	if (!add_sid_to_array(result, &global_sid_Network,
			 &result->user_sids, &result->num_sids)) {
		return NULL;
	}

	if (is_guest) {
		if (!add_sid_to_array(result, &global_sid_Builtin_Guests,
				 &result->user_sids, &result->num_sids)) {
			return NULL;
		}
	} else {
		if (!add_sid_to_array(result, &global_sid_Authenticated_Users,
				 &result->user_sids, &result->num_sids)) {
			return NULL;
		}
	}
	
	/* Now the SIDs we got from authentication. These are the ones from
	 * the info3 struct or from the pdb_enum_group_memberships, depending
	 * on who authenticated the user.
	 * Note that we start the for loop at "1" here, we already added the
	 * first group sid as primary above. */

	for (i=1; i<num_groupsids; i++) {
		if (!add_sid_to_array_unique(result, &groupsids[i],
					&result->user_sids, &result->num_sids)) {
			return NULL;
		}
	}
	
	/* Deal with the BUILTIN\Administrators group.  If the SID can
	   be resolved then assume that the add_aliasmem( S-1-5-32 ) 
	   handled it. */

	if ( !sid_to_gid( &global_sid_Builtin_Administrators, &gid ) ) {
		/* We can only create a mapping if winbind is running 
		   and the nested group functionality has been enabled */
		   
		if ( lp_winbind_nested_groups() && winbind_ping() ) {
			become_root();
			status = create_builtin_administrators( );
			if ( !NT_STATUS_IS_OK(status) ) {
				DEBUG(2,("create_local_nt_token: Failed to create BUILTIN\\Administrators group!\n"));
				/* don't fail, just log the message */
			}
			unbecome_root();
		}
		else {
			status = add_builtin_administrators( result );
			if ( !NT_STATUS_IS_OK(status) ) {
				/* just log a complaint but do not fail */
				DEBUG(3,("create_local_nt_token: failed to check for local Administrators"
					" membership (%s)\n", nt_errstr(status)));
			}			
		}		
	}

	/* Deal with the BUILTIN\Users group.  If the SID can
	   be resolved then assume that the add_aliasmem( S-1-5-32 ) 
	   handled it. */

	if ( !sid_to_gid( &global_sid_Builtin_Users, &gid ) ) {
		/* We can only create a mapping if winbind is running 
		   and the nested group functionality has been enabled */
		   
		if ( lp_winbind_nested_groups() && winbind_ping() ) {
			become_root();
			status = create_builtin_users( );
			if ( !NT_STATUS_IS_OK(status) ) {
				DEBUG(2,("create_local_nt_token: Failed to create BUILTIN\\Users group!\n"));
				/* don't fail, just log the message */
			}
			unbecome_root();
		}
	}

	/* Deal with local groups */
	
	if (lp_winbind_nested_groups()) {

		/* Now add the aliases. First the one from our local SAM */

		status = add_aliases(get_global_sam_sid(), result);

		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(result);
			return NULL;
		}

		/* Finally the builtin ones */

		status = add_aliases(&global_sid_Builtin, result);

		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(result);
			return NULL;
		}
	} 


	get_privileges_for_sids(&result->privileges, result->user_sids,
				result->num_sids);
	return result;
}

/* END */
