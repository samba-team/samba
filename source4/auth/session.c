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
#include "auth/auth_sam.h"
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
					     struct loadparm_context *lp_ctx, /* Optional, if you don't want privilages */
					     struct ldb_context *sam_ctx, /* Optional, if you don't want local groups */
					     struct auth_serversupplied_info *server_info,
					     uint32_t session_info_flags,
					     struct auth_session_info **_session_info)
{
	struct auth_session_info *session_info;
	NTSTATUS nt_status;
	unsigned int i, num_sids = 0;

	const char *filter;

	struct dom_sid *sids = NULL;
	const struct dom_sid *anonymous_sid, *system_sid;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	session_info = talloc(tmp_ctx, struct auth_session_info);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(session_info, tmp_ctx);

	session_info->server_info = talloc_reference(session_info, server_info);

	/* unless set otherwise, the session key is the user session
	 * key from the auth subsystem */ 
	session_info->session_key = server_info->user_session_key;

	anonymous_sid = dom_sid_parse_talloc(tmp_ctx, SID_NT_ANONYMOUS);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(anonymous_sid, tmp_ctx);

	system_sid = dom_sid_parse_talloc(tmp_ctx, SID_NT_SYSTEM);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(system_sid, tmp_ctx);

	sids = talloc_array(tmp_ctx, struct dom_sid, server_info->num_sids);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(sids, tmp_ctx);
	if (!sids) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	num_sids = server_info->num_sids;

	for (i=0; i < server_info->num_sids; i++) {
		sids[i] = server_info->sids[i];
	}

	if (server_info->num_sids > PRIMARY_USER_SID_INDEX && dom_sid_equal(anonymous_sid, &server_info->sids[PRIMARY_USER_SID_INDEX])) {
		/* Don't expand nested groups of system, anonymous etc*/
	} else if (server_info->num_sids > PRIMARY_USER_SID_INDEX && dom_sid_equal(system_sid, &server_info->sids[PRIMARY_USER_SID_INDEX])) {
		/* Don't expand nested groups of system, anonymous etc*/
	} else if (sam_ctx) {
		filter = talloc_asprintf(tmp_ctx, "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=%u))",
					 GROUP_TYPE_BUILTIN_LOCAL_GROUP);

		/* Search for each group in the token */
		for (i = 0; i < server_info->num_sids; i++) {
			char *sid_string;
			const char *sid_dn;
			DATA_BLOB sid_blob;
			
			sid_string = dom_sid_string(tmp_ctx,
						      &server_info->sids[i]);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(sid_string, server_info);
			
			sid_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", sid_string);
			talloc_free(sid_string);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(sid_dn, server_info);
			sid_blob = data_blob_string_const(sid_dn);
			
			/* This function takes in memberOf values and expands
			 * them, as long as they meet the filter - so only
			 * builtin groups
			 *
			 * We already have the SID in the token, so set
			 * 'only childs' flag to true */
			nt_status = dsdb_expand_nested_groups(sam_ctx, &sid_blob, true, filter,
							      tmp_ctx, &sids, &num_sids);
			if (!NT_STATUS_IS_OK(nt_status)) {
				talloc_free(tmp_ctx);
				return nt_status;
			}
		}
	}

	nt_status = security_token_create(session_info,
					  lp_ctx,
					  num_sids,
					  sids,
					  session_info_flags,
					  &session_info->security_token);
	NT_STATUS_NOT_OK_RETURN_AND_FREE(nt_status, tmp_ctx);

	session_info->credentials = NULL;

	talloc_steal(mem_ctx, session_info);
	*_session_info = session_info;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/* Produce a session_info for an arbitary DN or principal in the local
 * DB, assuming the local DB holds all the groups
 *
 * Supply either a principal or a DN
 */
NTSTATUS authsam_get_session_info_principal(TALLOC_CTX *mem_ctx,
					    struct loadparm_context *lp_ctx,
					    struct ldb_context *sam_ctx,
					    const char *principal,
					    struct ldb_dn *user_dn,
					    uint32_t session_info_flags,
					    struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	struct auth_serversupplied_info *server_info;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	nt_status = authsam_get_server_info_principal(tmp_ctx, lp_ctx, sam_ctx,
						      principal, user_dn,
						      &server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	nt_status = auth_generate_session_info(tmp_ctx, lp_ctx, sam_ctx,
					       server_info, session_info_flags,
					       session_info);

	if (NT_STATUS_IS_OK(nt_status)) {
		talloc_steal(mem_ctx, *session_info);
	}
	talloc_free(tmp_ctx);
	return nt_status;
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

	security_token_debug(0, dbg_lev, session_info->security_token);
}

