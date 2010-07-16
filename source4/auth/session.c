/* 
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001-2010
   Copyright (C) Jeremy Allison 2000-2001
   Copyright (C) Rafal Szczesniak 2002
   Copyright (C) Stefan Metzmacher 2005

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
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "dsdb/samdb/samdb.h"
#include "auth/session_proto.h"

_PUBLIC_ struct auth_session_info *anonymous_session(TALLOC_CTX *mem_ctx, 
					    struct loadparm_context *lp_ctx)
{
	NTSTATUS nt_status;
	struct auth_session_info *session_info = NULL;
	nt_status = auth_anonymous_session_info(mem_ctx, lp_ctx, &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return NULL;
	}
	return session_info;
}

_PUBLIC_ NTSTATUS auth_generate_session_info(TALLOC_CTX *mem_ctx,
					     struct auth_context *auth_context,
					     struct auth_serversupplied_info *server_info,
					     uint32_t session_info_flags,
					     struct auth_session_info **_session_info)
{
	struct auth_session_info *session_info;
	NTSTATUS nt_status;
	unsigned int i, num_groupSIDs = 0;
	const char *account_sid_string;
	const char *account_sid_dn;
	DATA_BLOB account_sid_blob;
	const char *primary_group_string;
	const char *primary_group_dn;
	DATA_BLOB primary_group_blob;

	const char *filter;

	struct dom_sid **groupSIDs = NULL;
	const struct dom_sid *dom_sid;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	if (!auth_context->sam_ctx) {
		DEBUG(0, ("No SAM available, cannot determine local groups\n"));
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* For now, we don't have trusted domains, so we do a very
	 * simple check to see that the user's SID is in *this*
	 * domain, and then trust the user account control.  When we
	 * get trusted domains, we should check it's a trusted domain
	 * in this forest.  This elaborate check is to try and avoid a
	 * nasty security bug if we forget about this later... */

	if (server_info->acct_flags & ACB_SVRTRUST) {
		dom_sid = samdb_domain_sid(auth_context->sam_ctx);
		if (dom_sid) {
			if (dom_sid_in_domain(dom_sid, server_info->account_sid)) {
				session_info_flags |= AUTH_SESSION_INFO_ENTERPRISE_DC;
			} else {
				DEBUG(2, ("DC %s is not in our domain.  "
					  "It will not have Enterprise Domain Controllers membership on this server",
					  server_info->account_name));
			}
		} else {
			DEBUG(2, ("Could not obtain local domain SID, "
				  "so can not determine if DC %s is a DC of this domain.  "
				  "It will not have Enterprise Domain Controllers membership",
				  server_info->account_name));
		}
	}

	groupSIDs = talloc_array(tmp_ctx, struct dom_sid *, server_info->n_domain_groups);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(groupSIDs, tmp_ctx);
	if (!groupSIDs) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	num_groupSIDs = server_info->n_domain_groups;

	for (i=0; i < server_info->n_domain_groups; i++) {
		groupSIDs[i] = server_info->domain_groups[i];
	}

	filter = talloc_asprintf(tmp_ctx, "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=%u))",
				 GROUP_TYPE_BUILTIN_LOCAL_GROUP);

	session_info = talloc(tmp_ctx, struct auth_session_info);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(session_info, tmp_ctx);

	session_info->server_info = talloc_reference(session_info, server_info);

	/* unless set otherwise, the session key is the user session
	 * key from the auth subsystem */ 
	session_info->session_key = server_info->user_session_key;

	/* Search for each group in the token */

	/* Expands the account SID - this function takes in
	 * memberOf-like values, so we fake one up with the
	 * <SID=S-...> format of DN and then let it expand
	 * them, as long as they meet the filter - so only
	 * builtin groups
	 *
	 * We already have the primary group in the token, so set
	 * 'only childs' flag to true
	 */
	account_sid_string = dom_sid_string(tmp_ctx, server_info->account_sid);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(account_sid_string, server_info);

	account_sid_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", account_sid_string);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(account_sid_dn, server_info);

	account_sid_blob = data_blob_string_const(account_sid_dn);

	nt_status = authsam_expand_nested_groups(auth_context->sam_ctx, &account_sid_blob, true, filter,
					      tmp_ctx, &groupSIDs, &num_groupSIDs);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	/* Expands the primary group - this function takes in
	 * memberOf-like values, so we fake one up with the
	 * <SID=S-...> format of DN and then let it expand
	 * them, as long as they meet the filter - so only
	 * builtin groups
	 *
	 * We already have the primary group in the token, so set
	 * 'only childs' flag to true
	 */
	primary_group_string = dom_sid_string(tmp_ctx, server_info->primary_group_sid);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(primary_group_string, server_info);

	primary_group_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", primary_group_string);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(primary_group_dn, server_info);

	primary_group_blob = data_blob_string_const(primary_group_dn);

	nt_status = authsam_expand_nested_groups(auth_context->sam_ctx, &primary_group_blob, true, filter,
					      tmp_ctx, &groupSIDs, &num_groupSIDs);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	for (i = 0; i < server_info->n_domain_groups; i++) {
		char *group_string;
		const char *group_dn;
		DATA_BLOB group_blob;

		group_string = dom_sid_string(tmp_ctx,
					      server_info->domain_groups[i]);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(group_string, server_info);

		group_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", group_string);
		talloc_free(group_string);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(group_dn, server_info);
		group_blob = data_blob_string_const(group_dn);

		/* This function takes in memberOf values and expands
		 * them, as long as they meet the filter - so only
		 * builtin groups */
		nt_status = authsam_expand_nested_groups(auth_context->sam_ctx, &group_blob, true, filter,
						      tmp_ctx, &groupSIDs, &num_groupSIDs);
		if (!NT_STATUS_IS_OK(nt_status)) {
			talloc_free(tmp_ctx);
			return nt_status;
		}
	}

	nt_status = security_token_create(session_info,
					  auth_context->event_ctx,
					  auth_context->lp_ctx,
					  server_info->account_sid,
					  server_info->primary_group_sid,
					  num_groupSIDs,
					  groupSIDs,
					  session_info_flags,
					  &session_info->security_token);
	NT_STATUS_NOT_OK_RETURN_AND_FREE(nt_status, tmp_ctx);

	session_info->credentials = NULL;

	talloc_steal(mem_ctx, session_info);
	*_session_info = session_info;
	return NT_STATUS_OK;
}

/**
 * prints a struct auth_session_info security token to debug output.
 */
void auth_session_info_debug(int dbg_lev, 
			     const struct auth_session_info *session_info)
{
	if (!session_info) {
		DEBUG(dbg_lev, ("Session Info: (NULL)\n"));
		return;	
	}

	security_token_debug(dbg_lev, session_info->security_token);
}

