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
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* functions moved from auth/auth_util.c to minimize linker deps */

#include "includes.h"

/****************************************************************************
 Check for a SID in an NT_USER_TOKEN
****************************************************************************/

bool nt_token_check_sid ( const DOM_SID *sid, const NT_USER_TOKEN *token )
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

bool nt_token_check_domain_rid( NT_USER_TOKEN *token, uint32 rid )
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
	struct nt_user_token *token, *for_cache;
	DOM_SID u_sid, g_sid;
	struct passwd *pw;
	void *cache_data;

	cache_data = memcache_lookup_talloc(
		NULL, SINGLETON_CACHE_TALLOC,
		data_blob_string_const_null("root_nt_token"));

	if (cache_data != NULL) {
		return talloc_get_type_abort(
			cache_data, struct nt_user_token);
	}

	if ( !(pw = sys_getpwuid(0)) ) {
		if ( !(pw = sys_getpwnam("root")) ) {
			DEBUG(0,("get_root_nt_token: both sys_getpwuid(0) "
				"and sys_getpwnam(\"root\") failed!\n"));
			return NULL;
		}
	}

	/* get the user and primary group SIDs; although the
	   BUILTIN\Administrators SId is really the one that matters here */

	uid_to_sid(&u_sid, pw->pw_uid);
	gid_to_sid(&g_sid, pw->pw_gid);

	token = create_local_nt_token(talloc_autofree_context(), &u_sid, False,
				      1, &global_sid_Builtin_Administrators);

	token->privileges = se_disk_operators;

	for_cache = token;

	memcache_add_talloc(
		NULL, SINGLETON_CACHE_TALLOC,
		data_blob_string_const_null("root_nt_token"), &for_cache);

	return token;
}


/*
 * Add alias SIDs from memberships within the partially created token SID list
 */

NTSTATUS add_aliases(const DOM_SID *domain_sid,
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
		goto done;
	}

	for (i=0; i<num_aliases; i++) {
		DOM_SID alias_sid;
		sid_compose(&alias_sid, domain_sid, aliases[i]);
		status = add_sid_to_array_unique(token, &alias_sid,
						 &token->user_sids,
						 &token->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("add_sid_to_array failed\n"));
			goto done;
		}
	}

done:
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

/*******************************************************************
*******************************************************************/

static NTSTATUS add_builtin_administrators(struct nt_user_token *token,
					   const DOM_SID *dom_sid)
{
	DOM_SID domadm;
	NTSTATUS status;

	/* nothing to do if we aren't in a domain */

	if ( !(IS_DC || lp_server_role()==ROLE_DOMAIN_MEMBER) ) {
		return NT_STATUS_OK;
	}

	/* Find the Domain Admins SID */

	if ( IS_DC ) {
		sid_copy( &domadm, get_global_sam_sid() );
	} else {
		sid_copy(&domadm, dom_sid);
	}
	sid_append_rid( &domadm, DOMAIN_GROUP_RID_ADMINS );

	/* Add Administrators if the user beloongs to Domain Admins */

	if ( nt_token_check_sid( &domadm, token ) ) {
		status = add_sid_to_array(token,
					  &global_sid_Builtin_Administrators,
					  &token->user_sids, &token->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

/**
 * Create the requested BUILTIN if it doesn't already exist.  This requires
 * winbindd to be running.
 *
 * @param[in] rid BUILTIN rid to create
 * @return Normal NTSTATUS return.
 */
static NTSTATUS create_builtin(uint32 rid)
{
	NTSTATUS status = NT_STATUS_OK;
	DOM_SID sid;
	gid_t gid;

	if (!sid_compose(&sid, &global_sid_Builtin, rid)) {
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	if (!sid_to_gid(&sid, &gid)) {
		if (!lp_winbind_nested_groups() || !winbind_ping()) {
			return NT_STATUS_PROTOCOL_UNREACHABLE;
		}
		status = pdb_create_builtin_alias(rid);
	}
	return status;
}

/**
 * Add sid as a member of builtin_sid.
 *
 * @param[in] builtin_sid	An existing builtin group.
 * @param[in] dom_sid		sid to add as a member of builtin_sid.
 * @return Normal NTSTATUS return
 */
static NTSTATUS add_sid_to_builtin(const DOM_SID *builtin_sid,
				   const DOM_SID *dom_sid)
{
	NTSTATUS status = NT_STATUS_OK;

	if (!dom_sid || !builtin_sid) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = pdb_add_aliasmem(builtin_sid, dom_sid);

	if (NT_STATUS_EQUAL(status, NT_STATUS_MEMBER_IN_ALIAS)) {
		DEBUG(5, ("add_sid_to_builtin %s is already a member of %s\n",
			  sid_string_dbg(dom_sid),
			  sid_string_dbg(builtin_sid)));
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(4, ("add_sid_to_builtin %s could not be added to %s: "
			  "%s\n", sid_string_dbg(dom_sid),
			  sid_string_dbg(builtin_sid), nt_errstr(status)));
	}
	return status;
}

/*******************************************************************
*******************************************************************/

NTSTATUS create_builtin_users(const DOM_SID *dom_sid)
{
	NTSTATUS status;
	DOM_SID dom_users;

	status = create_builtin(BUILTIN_ALIAS_RID_USERS);
	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(5,("create_builtin_users: Failed to create Users\n"));
		return status;
	}

	/* add domain users */
	if ((IS_DC || (lp_server_role() == ROLE_DOMAIN_MEMBER))
		&& sid_compose(&dom_users, dom_sid, DOMAIN_GROUP_RID_USERS))
	{
		status = add_sid_to_builtin(&global_sid_Builtin_Users,
					    &dom_users);
	}

	return status;
}

/*******************************************************************
*******************************************************************/

NTSTATUS create_builtin_administrators(const DOM_SID *dom_sid)
{
	NTSTATUS status;
	DOM_SID dom_admins, root_sid;
	fstring root_name;
	enum lsa_SidType type;
	TALLOC_CTX *ctx;
	bool ret;

	status = create_builtin(BUILTIN_ALIAS_RID_ADMINS);
	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(5,("create_builtin_administrators: Failed to create Administrators\n"));
		return status;
	}

	/* add domain admins */
	if ((IS_DC || (lp_server_role() == ROLE_DOMAIN_MEMBER))
		&& sid_compose(&dom_admins, dom_sid, DOMAIN_GROUP_RID_ADMINS))
	{
		status = add_sid_to_builtin(&global_sid_Builtin_Administrators,
					    &dom_admins);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* add root */
	if ( (ctx = talloc_init("create_builtin_administrators")) == NULL ) {
		return NT_STATUS_NO_MEMORY;
	}
	fstr_sprintf( root_name, "%s\\root", get_global_sam_name() );
	ret = lookup_name(ctx, root_name, LOOKUP_NAME_DOMAIN, NULL, NULL,
			  &root_sid, &type);
	TALLOC_FREE( ctx );

	if ( ret ) {
		status = add_sid_to_builtin(&global_sid_Builtin_Administrators,
					    &root_sid);
	}

	return status;
}


/*******************************************************************
 Create a NT token for the user, expanding local aliases
*******************************************************************/

struct nt_user_token *create_local_nt_token(TALLOC_CTX *mem_ctx,
					    const DOM_SID *user_sid,
					    bool is_guest,
					    int num_groupsids,
					    const DOM_SID *groupsids)
{
	struct nt_user_token *result = NULL;
	int i;
	NTSTATUS status;
	gid_t gid;
	DOM_SID dom_sid;

	DEBUG(10, ("Create local NT token for %s\n",
		   sid_string_dbg(user_sid)));

	if (!(result = TALLOC_ZERO_P(mem_ctx, struct nt_user_token))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	/* Add the user and primary group sid */

	status = add_sid_to_array(result, user_sid,
				  &result->user_sids, &result->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	/* For guest, num_groupsids may be zero. */
	if (num_groupsids) {
		status = add_sid_to_array(result, &groupsids[0],
					  &result->user_sids,
					  &result->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}
	}

	/* Add in BUILTIN sids */

	status = add_sid_to_array(result, &global_sid_World,
				  &result->user_sids, &result->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	status = add_sid_to_array(result, &global_sid_Network,
				  &result->user_sids, &result->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	if (is_guest) {
		status = add_sid_to_array(result, &global_sid_Builtin_Guests,
					  &result->user_sids,
					  &result->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}
	} else {
		status = add_sid_to_array(result,
					  &global_sid_Authenticated_Users,
					  &result->user_sids,
					  &result->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}
	}

	/* Now the SIDs we got from authentication. These are the ones from
	 * the info3 struct or from the pdb_enum_group_memberships, depending
	 * on who authenticated the user.
	 * Note that we start the for loop at "1" here, we already added the
	 * first group sid as primary above. */

	for (i=1; i<num_groupsids; i++) {
		status = add_sid_to_array_unique(result, &groupsids[i],
						 &result->user_sids,
						 &result->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}
	}

	/* Deal with the BUILTIN\Administrators group.  If the SID can
	   be resolved then assume that the add_aliasmem( S-1-5-32 )
	   handled it. */

	if (!sid_to_gid(&global_sid_Builtin_Administrators, &gid)) {

		become_root();
		if (!secrets_fetch_domain_sid(lp_workgroup(), &dom_sid)) {
			status = NT_STATUS_OK;
			DEBUG(3, ("Failed to fetch domain sid for %s\n",
				  lp_workgroup()));
		} else {
			status = create_builtin_administrators(&dom_sid);
		}
		unbecome_root();

		if (NT_STATUS_EQUAL(status, NT_STATUS_PROTOCOL_UNREACHABLE)) {
			/* Add BUILTIN\Administrators directly to token. */
			status = add_builtin_administrators(result, &dom_sid);
			if ( !NT_STATUS_IS_OK(status) ) {
				DEBUG(3, ("Failed to check for local "
					  "Administrators membership (%s)\n",
					  nt_errstr(status)));
			}
		} else if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("WARNING: Failed to create "
				  "BUILTIN\\Administrators group!  Can "
				  "Winbind allocate gids?\n"));
		}
	}

	/* Deal with the BUILTIN\Users group.  If the SID can
	   be resolved then assume that the add_aliasmem( S-1-5-32 )
	   handled it. */

	if (!sid_to_gid(&global_sid_Builtin_Users, &gid)) {

		become_root();
		if (!secrets_fetch_domain_sid(lp_workgroup(), &dom_sid)) {
			status = NT_STATUS_OK;
			DEBUG(3, ("Failed to fetch domain sid for %s\n",
				  lp_workgroup()));
		} else {
			status = create_builtin_users(&dom_sid);
		}
		unbecome_root();

		if (!NT_STATUS_EQUAL(status, NT_STATUS_PROTOCOL_UNREACHABLE) &&
		    !NT_STATUS_IS_OK(status))
		{
			DEBUG(2, ("WARNING: Failed to create BUILTIN\\Users group! "
				  "Can Winbind allocate gids?\n"));
		}
	}

	/* Deal with local groups */

	if (lp_winbind_nested_groups()) {

		become_root();

		/* Now add the aliases. First the one from our local SAM */

		status = add_aliases(get_global_sam_sid(), result);

		if (!NT_STATUS_IS_OK(status)) {
			unbecome_root();
			TALLOC_FREE(result);
			return NULL;
		}

		/* Finally the builtin ones */

		status = add_aliases(&global_sid_Builtin, result);

		if (!NT_STATUS_IS_OK(status)) {
			unbecome_root();
			TALLOC_FREE(result);
			return NULL;
		}

		unbecome_root();
	}


	get_privileges_for_sids(&result->privileges, result->user_sids,
				result->num_sids);
	return result;
}

/****************************************************************************
 prints a NT_USER_TOKEN to debug output.
****************************************************************************/

void debug_nt_user_token(int dbg_class, int dbg_lev, NT_USER_TOKEN *token)
{
	size_t     i;

	if (!token) {
		DEBUGC(dbg_class, dbg_lev, ("NT user token: (NULL)\n"));
		return;
	}

	DEBUGC(dbg_class, dbg_lev,
	       ("NT user token of user %s\n",
		sid_string_dbg(&token->user_sids[0]) ));
	DEBUGADDC(dbg_class, dbg_lev,
		  ("contains %lu SIDs\n", (unsigned long)token->num_sids));
	for (i = 0; i < token->num_sids; i++)
		DEBUGADDC(dbg_class, dbg_lev,
			  ("SID[%3lu]: %s\n", (unsigned long)i,
			   sid_string_dbg(&token->user_sids[i])));

	dump_se_priv( dbg_class, dbg_lev, &token->privileges );
}

/****************************************************************************
 prints a UNIX 'token' to debug output.
****************************************************************************/

void debug_unix_user_token(int dbg_class, int dbg_lev, uid_t uid, gid_t gid,
			   int n_groups, gid_t *groups)
{
	int     i;
	DEBUGC(dbg_class, dbg_lev,
	       ("UNIX token of user %ld\n", (long int)uid));

	DEBUGADDC(dbg_class, dbg_lev,
		  ("Primary group is %ld and contains %i supplementary "
		   "groups\n", (long int)gid, n_groups));
	for (i = 0; i < n_groups; i++)
		DEBUGADDC(dbg_class, dbg_lev, ("Group[%3i]: %ld\n", i,
			(long int)groups[i]));
}

/*
 * Create an artificial NT token given just a username. (Initially intended
 * for force user)
 *
 * We go through lookup_name() to avoid problems we had with 'winbind use
 * default domain'.
 *
 * We have 3 cases:
 *
 * unmapped unix users: Go directly to nss to find the user's group.
 *
 * A passdb user: The list of groups is provided by pdb_enum_group_memberships.
 *
 * If the user is provided by winbind, the primary gid is set to "domain
 * users" of the user's domain. For an explanation why this is necessary, see
 * the thread starting at
 * http://lists.samba.org/archive/samba-technical/2006-January/044803.html.
 */

NTSTATUS create_token_from_username(TALLOC_CTX *mem_ctx, const char *username,
				    bool is_guest,
				    uid_t *uid, gid_t *gid,
				    char **found_username,
				    struct nt_user_token **token)
{
	NTSTATUS result = NT_STATUS_NO_SUCH_USER;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	DOM_SID user_sid;
	enum lsa_SidType type;
	gid_t *gids;
	DOM_SID *group_sids;
	DOM_SID unix_group_sid;
	size_t num_group_sids;
	size_t num_gids;
	size_t i;

	if (!lookup_name_smbconf(tmp_ctx, username, LOOKUP_NAME_ALL,
			 NULL, NULL, &user_sid, &type)) {
		DEBUG(1, ("lookup_name_smbconf for %s failed\n", username));
		goto done;
	}

	if (type != SID_NAME_USER) {
		DEBUG(1, ("%s is a %s, not a user\n", username,
			  sid_type_lookup(type)));
		goto done;
	}

	if (sid_check_is_in_our_domain(&user_sid)) {
		bool ret;

		/* This is a passdb user, so ask passdb */

		struct samu *sam_acct = NULL;

		if ( !(sam_acct = samu_new( tmp_ctx )) ) {
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}

		become_root();
		ret = pdb_getsampwsid(sam_acct, &user_sid);
		unbecome_root();

		if (!ret) {
			DEBUG(1, ("pdb_getsampwsid(%s) for user %s failed\n",
				  sid_string_dbg(&user_sid), username));
			DEBUGADD(1, ("Fall back to unix user %s\n", username));
			goto unix_user;
		}

		result = pdb_enum_group_memberships(tmp_ctx, sam_acct,
						    &group_sids, &gids,
						    &num_group_sids);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(1, ("enum_group_memberships failed for %s (%s): "
				  "%s\n", username, sid_string_dbg(&user_sid),
				  nt_errstr(result)));
			DEBUGADD(1, ("Fall back to unix user %s\n", username));
			goto unix_user;
		}

		/* see the smb_panic() in pdb_default_enum_group_memberships */
		SMB_ASSERT(num_group_sids > 0);

		*gid = gids[0];

		/* Ensure we're returning the found_username on the right context. */
		*found_username = talloc_strdup(mem_ctx,
						pdb_get_username(sam_acct));

		/*
		 * If the SID from lookup_name() was the guest sid, passdb knows
		 * about the mapping of guest sid to lp_guestaccount()
		 * username and will return the unix_pw info for a guest
		 * user. Use it if it's there, else lookup the *uid details
		 * using getpwnam_alloc(). See bug #6291 for details. JRA.
		 */

		/* We must always assign the *uid. */
		if (sam_acct->unix_pw == NULL) {
			struct passwd *pwd = getpwnam_alloc(sam_acct, *found_username );
			if (!pwd) {
				DEBUG(10, ("getpwnam_alloc failed for %s\n",
					*found_username));
				result = NT_STATUS_NO_SUCH_USER;
				goto done;
			}
			result = samu_set_unix(sam_acct, pwd );
			if (!NT_STATUS_IS_OK(result)) {
				DEBUG(10, ("samu_set_unix failed for %s\n",
					*found_username));
				result = NT_STATUS_NO_SUCH_USER;
				goto done;
			}
		}
		*uid = sam_acct->unix_pw->pw_uid;

	} else 	if (sid_check_is_in_unix_users(&user_sid)) {

		/* This is a unix user not in passdb. We need to ask nss
		 * directly, without consulting passdb */

		struct passwd *pass;

		/*
		 * This goto target is used as a fallback for the passdb
		 * case. The concrete bug report is when passdb gave us an
		 * unmapped gid.
		 */

	unix_user:

		if (!sid_to_uid(&user_sid, uid)) {
			DEBUG(1, ("unix_user case, sid_to_uid for %s (%s) failed\n",
				  username, sid_string_dbg(&user_sid)));
			result = NT_STATUS_NO_SUCH_USER;
			goto done;
		}

		uid_to_unix_users_sid(*uid, &user_sid);

		pass = getpwuid_alloc(tmp_ctx, *uid);
		if (pass == NULL) {
			DEBUG(1, ("getpwuid(%u) for user %s failed\n",
				  (unsigned int)*uid, username));
			goto done;
		}

		if (!getgroups_unix_user(tmp_ctx, username, pass->pw_gid,
					 &gids, &num_group_sids)) {
			DEBUG(1, ("getgroups_unix_user for user %s failed\n",
				  username));
			goto done;
		}

		if (num_group_sids) {
			group_sids = TALLOC_ARRAY(tmp_ctx, DOM_SID, num_group_sids);
			if (group_sids == NULL) {
				DEBUG(1, ("TALLOC_ARRAY failed\n"));
				result = NT_STATUS_NO_MEMORY;
				goto done;
			}
		} else {
			group_sids = NULL;
		}

		for (i=0; i<num_group_sids; i++) {
			gid_to_sid(&group_sids[i], gids[i]);
		}

		/* In getgroups_unix_user we always set the primary gid */
		SMB_ASSERT(num_group_sids > 0);

		*gid = gids[0];

		/* Ensure we're returning the found_username on the right context. */
		*found_username = talloc_strdup(mem_ctx, pass->pw_name);
	} else {

		/* This user is from winbind, force the primary gid to the
		 * user's "domain users" group. Under certain circumstances
		 * (user comes from NT4), this might be a loss of
		 * information. But we can not rely on winbind getting the
		 * correct info. AD might prohibit winbind looking up that
		 * information. */

		uint32 dummy;

		/* We must always assign the *uid. */
		if (!sid_to_uid(&user_sid, uid)) {
			DEBUG(1, ("winbindd case, sid_to_uid for %s (%s) failed\n",
				  username, sid_string_dbg(&user_sid)));
			result = NT_STATUS_NO_SUCH_USER;
			goto done;
		}

		num_group_sids = 1;
		group_sids = TALLOC_ARRAY(tmp_ctx, DOM_SID, num_group_sids);
		if (group_sids == NULL) {
			DEBUG(1, ("TALLOC_ARRAY failed\n"));
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}

		sid_copy(&group_sids[0], &user_sid);
		sid_split_rid(&group_sids[0], &dummy);
		sid_append_rid(&group_sids[0], DOMAIN_GROUP_RID_USERS);

		if (!sid_to_gid(&group_sids[0], gid)) {
			DEBUG(1, ("sid_to_gid(%s) failed\n",
				  sid_string_dbg(&group_sids[0])));
			goto done;
		}

		gids = gid;

		/* Ensure we're returning the found_username on the right context. */
		*found_username = talloc_strdup(mem_ctx, username);
	}

	/* Add the "Unix Group" SID for each gid to catch mapped groups
	   and their Unix equivalent.  This is to solve the backwards
	   compatibility problem of 'valid users = +ntadmin' where
	   ntadmin has been paired with "Domain Admins" in the group
	   mapping table.  Otherwise smb.conf would need to be changed
	   to 'valid user = "Domain Admins"'.  --jerry */

	num_gids = num_group_sids;
	for ( i=0; i<num_gids; i++ ) {
		gid_t high, low;

		/* don't pickup anything managed by Winbind */

		if ( lp_idmap_gid(&low, &high) && (gids[i] >= low) && (gids[i] <= high) )
			continue;

		if ( !gid_to_unix_groups_sid( gids[i], &unix_group_sid ) ) {
			DEBUG(1,("create_token_from_username: Failed to create SID "
				"for gid %u!\n", (unsigned int)gids[i]));
			continue;
		}
		result = add_sid_to_array_unique(tmp_ctx, &unix_group_sid,
						 &group_sids, &num_group_sids);
		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}
	}

	/* Ensure we're creating the nt_token on the right context. */
	*token = create_local_nt_token(mem_ctx, &user_sid,
				       is_guest, num_group_sids, group_sids);

	if ((*token == NULL) || (*found_username == NULL)) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result = NT_STATUS_OK;
 done:
	TALLOC_FREE(tmp_ctx);
	return result;
}

/***************************************************************************
 Build upon create_token_from_username:

 Expensive helper function to figure out whether a user given its name is
 member of a particular group.
***************************************************************************/

bool user_in_group_sid(const char *username, const DOM_SID *group_sid)
{
	NTSTATUS status;
	uid_t uid;
	gid_t gid;
	char *found_username;
	struct nt_user_token *token;
	bool result;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	status = create_token_from_username(mem_ctx, username, False,
					    &uid, &gid, &found_username,
					    &token);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("could not create token for %s\n", username));
		TALLOC_FREE(mem_ctx);
		return False;
	}

	result = nt_token_check_sid(group_sid, token);

	TALLOC_FREE(mem_ctx);
	return result;
}

bool user_in_group(const char *username, const char *groupname)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	DOM_SID group_sid;
	bool ret;

	ret = lookup_name(mem_ctx, groupname, LOOKUP_NAME_ALL,
			  NULL, NULL, &group_sid, NULL);
	TALLOC_FREE(mem_ctx);

	if (!ret) {
		DEBUG(10, ("lookup_name for (%s) failed.\n", groupname));
		return False;
	}

	return user_in_group_sid(username, &group_sid);
}

/* END */
