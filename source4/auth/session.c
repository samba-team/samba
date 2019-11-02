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
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "dsdb/samdb/samdb.h"
#include "auth/session_proto.h"
#include "system/kerberos.h"
#include <gssapi/gssapi.h>
#include "libcli/wbclient/wbclient.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

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
					     struct auth_user_info_dc *user_info_dc,
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

	session_info = talloc_zero(tmp_ctx, struct auth_session_info);
	if (session_info == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	session_info->info = talloc_reference(session_info, user_info_dc->info);

	session_info->torture = talloc_zero(session_info, struct auth_user_info_torture);
	if (session_info->torture == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	session_info->torture->num_dc_sids = user_info_dc->num_sids;
	session_info->torture->dc_sids = talloc_reference(session_info, user_info_dc->sids);
	if (session_info->torture->dc_sids == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* unless set otherwise, the session key is the user session
	 * key from the auth subsystem */ 
	session_info->session_key = data_blob_talloc(session_info, user_info_dc->user_session_key.data, user_info_dc->user_session_key.length);
	if (!session_info->session_key.data && session_info->session_key.length) {
		if (session_info->session_key.data == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	anonymous_sid = dom_sid_parse_talloc(tmp_ctx, SID_NT_ANONYMOUS);
	if (anonymous_sid == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	system_sid = dom_sid_parse_talloc(tmp_ctx, SID_NT_SYSTEM);
	if (system_sid == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	sids = talloc_array(tmp_ctx, struct dom_sid, user_info_dc->num_sids);
	if (sids == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	num_sids = user_info_dc->num_sids;

	for (i=0; i < user_info_dc->num_sids; i++) {
		sids[i] = user_info_dc->sids[i];
	}

	/*
	 * Finally add the "standard" sids.
	 * The only difference between guest and "anonymous"
	 * is the addition of Authenticated_Users.
	 */

	if (session_info_flags & AUTH_SESSION_INFO_DEFAULT_GROUPS) {
		sids = talloc_realloc(tmp_ctx, sids, struct dom_sid, num_sids + 2);
		if (sids == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		sid_copy(&sids[num_sids], &global_sid_World);
		num_sids++;

		sid_copy(&sids[num_sids], &global_sid_Network);
		num_sids++;
	}

	if (session_info_flags & AUTH_SESSION_INFO_AUTHENTICATED) {
		sids = talloc_realloc(tmp_ctx, sids, struct dom_sid, num_sids + 1);
		if (sids == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		sid_copy(&sids[num_sids], &global_sid_Authenticated_Users);
		num_sids++;
	}

	if (session_info_flags & AUTH_SESSION_INFO_NTLM) {
		sids = talloc_realloc(tmp_ctx, sids, struct dom_sid, num_sids + 1);
		if (sids == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		if (!dom_sid_parse(SID_NT_NTLM_AUTHENTICATION, &sids[num_sids])) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}
		num_sids++;
	}


	if (num_sids > PRIMARY_USER_SID_INDEX && dom_sid_equal(anonymous_sid, &sids[PRIMARY_USER_SID_INDEX])) {
		/* Don't expand nested groups of system, anonymous etc*/
	} else if (num_sids > PRIMARY_USER_SID_INDEX && dom_sid_equal(system_sid, &sids[PRIMARY_USER_SID_INDEX])) {
		/* Don't expand nested groups of system, anonymous etc*/
	} else if (sam_ctx) {
		filter = talloc_asprintf(tmp_ctx, "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=%u))",
					 GROUP_TYPE_BUILTIN_LOCAL_GROUP);

		/* Search for each group in the token */
		for (i = 0; i < num_sids; i++) {
			struct dom_sid_buf buf;
			const char *sid_dn;
			DATA_BLOB sid_blob;

			sid_dn = talloc_asprintf(
				tmp_ctx,
				"<SID=%s>",
				dom_sid_str_buf(&sids[i], &buf));
			if (sid_dn == NULL) {
				TALLOC_FREE(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}
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
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	session_info->unique_session_token = GUID_random();

	session_info->credentials = NULL;

	talloc_steal(mem_ctx, session_info);
	*_session_info = session_info;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}


/* Fill out the auth_session_info with a cli_credentials based on the
 * auth_session_info we were forwarded over named pipe forwarding.
 *
 * NOTE: The stucture members of session_info_transport are stolen
 * with talloc_move() into auth_session_info for long term use
 */
struct auth_session_info *auth_session_info_from_transport(TALLOC_CTX *mem_ctx,
							   struct auth_session_info_transport *session_info_transport,
							   struct loadparm_context *lp_ctx,
							   const char **reason)
{
	struct auth_session_info *session_info;
	session_info = talloc_steal(mem_ctx, session_info_transport->session_info);
	/*
	 * This is to allow us to check the type of this pointer using
	 * talloc_get_type()
	 */
	talloc_set_name(session_info, "struct auth_session_info");
#ifdef HAVE_GSS_IMPORT_CRED
	if (session_info_transport->exported_gssapi_credentials.length) {
		struct cli_credentials *creds;
		OM_uint32 minor_status;
		gss_buffer_desc cred_token;
		gss_cred_id_t cred_handle;
		const char *error_string;
		int ret;

		DEBUG(10, ("Delegated credentials supplied by client\n"));

		cred_token.value = session_info_transport->exported_gssapi_credentials.data;
		cred_token.length = session_info_transport->exported_gssapi_credentials.length;

		ret = gss_import_cred(&minor_status,
				      &cred_token,
				      &cred_handle);
		if (ret != GSS_S_COMPLETE) {
			*reason = "Internal error in gss_import_cred()";
			return NULL;
		}

		creds = cli_credentials_init(session_info);
		if (!creds) {
			*reason = "Out of memory in cli_credentials_init()";
			return NULL;
		}
		session_info->credentials = creds;

		cli_credentials_set_conf(creds, lp_ctx);
		/* Just so we don't segfault trying to get at a username */
		cli_credentials_set_anonymous(creds);

		ret = cli_credentials_set_client_gss_creds(creds,
							   lp_ctx,
							   cred_handle,
							   CRED_SPECIFIED,
							   &error_string);
		if (ret) {
			*reason = talloc_asprintf(mem_ctx,
						  "Failed to set pipe forwarded"
						  "creds: %s\n", error_string);
			return NULL;
		}

		/* This credential handle isn't useful for password
		 * authentication, so ensure nobody tries to do that */
		cli_credentials_set_kerberos_state(creds,
						   CRED_MUST_USE_KERBEROS);

	}
#endif
	return session_info;
}


/* Create a auth_session_info_transport from an auth_session_info.
 *
 * NOTE: Members of the auth_session_info_transport structure are
 * talloc_referenced() into this structure, and should not be changed.
 */
NTSTATUS auth_session_info_transport_from_session(TALLOC_CTX *mem_ctx,
						  struct auth_session_info *session_info,
						  struct tevent_context *event_ctx,
						  struct loadparm_context *lp_ctx,
						  struct auth_session_info_transport **transport_out)
{

	struct auth_session_info_transport *session_info_transport
		= talloc_zero(mem_ctx, struct auth_session_info_transport);
	if (!session_info_transport) {
		return NT_STATUS_NO_MEMORY;
	};
	session_info_transport->session_info = talloc_reference(session_info_transport, session_info);
	if (!session_info_transport->session_info) {
		return NT_STATUS_NO_MEMORY;
	};
#ifdef HAVE_GSS_EXPORT_CRED
	if (session_info->credentials) {
		struct gssapi_creds_container *gcc;
		OM_uint32 gret;
		OM_uint32 minor_status;
		gss_buffer_desc cred_token;
		const char *error_string;
		int ret;

		ret = cli_credentials_get_client_gss_creds(session_info->credentials,
							   event_ctx,
							   lp_ctx,
							   &gcc, &error_string);
		if (ret != 0) {
			*transport_out = session_info_transport;
			return NT_STATUS_OK;
		}

		gret = gss_export_cred(&minor_status,
				       gcc->creds,
				       &cred_token);
		if (gret != GSS_S_COMPLETE) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (cred_token.length) {
			session_info_transport->exported_gssapi_credentials
				= data_blob_talloc(session_info_transport,
						   cred_token.value,
						   cred_token.length);
			gss_release_buffer(&minor_status, &cred_token);
			NT_STATUS_HAVE_NO_MEMORY(session_info_transport->exported_gssapi_credentials.data);
		}
	}
#endif
	*transport_out = session_info_transport;
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
	struct auth_user_info_dc *user_info_dc;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	nt_status = authsam_get_user_info_dc_principal(tmp_ctx, lp_ctx, sam_ctx,
						      principal, user_dn,
						      &user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	nt_status = auth_generate_session_info(tmp_ctx, lp_ctx, sam_ctx,
					       user_info_dc, session_info_flags,
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

	security_token_debug(DBGC_AUTH, dbg_lev,
			     session_info->security_token);
}
