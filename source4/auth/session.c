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
#include "libcli/security/claims-conversions.h"
#include "libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/claims.h"
#include "librpc/gen_ndr/ndr_claims.h"
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

static NTSTATUS auth_user_info_dc_expand_sids(TALLOC_CTX *mem_ctx,
					      struct loadparm_context *lp_ctx,
					      struct ldb_context *sam_ctx,
					      const struct auth_user_info_dc *user_info_dc,
					      uint32_t session_info_flags,
					      struct auth_SidAttr **_sids,
					      uint32_t *_num_sids)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS nt_status;
	struct auth_SidAttr *sids = NULL;
	uint32_t num_sids = 0;
	uint32_t i;
	const char *filter = NULL;

	sids = talloc_array(mem_ctx,
			    struct auth_SidAttr,
			    user_info_dc->num_sids);
	if (sids == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_steal(frame, sids);

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
		sids = talloc_realloc(frame,
				      sids,
				      struct auth_SidAttr,
				      num_sids + 2);
		if (sids == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		sids[num_sids] = (struct auth_SidAttr) {
			.sid = global_sid_World,
			.attrs = SE_GROUP_DEFAULT_FLAGS,
		};
		num_sids++;

		sids[num_sids] = (struct auth_SidAttr) {
			.sid = global_sid_Network,
			.attrs = SE_GROUP_DEFAULT_FLAGS,
		};
		num_sids++;
	}

	if (session_info_flags & AUTH_SESSION_INFO_AUTHENTICATED) {
		sids = talloc_realloc(frame,
				      sids,
				      struct auth_SidAttr,
				      num_sids + 1);
		if (sids == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		sids[num_sids] = (struct auth_SidAttr) {
			.sid = global_sid_Authenticated_Users,
			.attrs = SE_GROUP_DEFAULT_FLAGS,
		};
		num_sids++;
	}

	if (session_info_flags & AUTH_SESSION_INFO_NTLM) {
		sids = talloc_realloc(frame,
				      sids,
				      struct auth_SidAttr,
				      num_sids + 1);
		if (sids == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		sids[num_sids] = (struct auth_SidAttr) {
			.sid = global_sid_NTLM_Authentication,
			.attrs = SE_GROUP_DEFAULT_FLAGS,
		};
		num_sids++;
	}

	if (num_sids > PRIMARY_USER_SID_INDEX && dom_sid_equal(&global_sid_Anonymous, &sids[PRIMARY_USER_SID_INDEX].sid)) {
		/* Don't expand nested groups of system, anonymous etc*/
		goto done;
	}

	if (num_sids > PRIMARY_USER_SID_INDEX && dom_sid_equal(&global_sid_System, &sids[PRIMARY_USER_SID_INDEX].sid)) {
		/* Don't expand nested groups of system, anonymous etc*/
		goto done;
	}
	if (sam_ctx == NULL) {
		/* Don't expand nested groups of system, anonymous etc*/
		goto done;
	}

	filter = talloc_asprintf(frame,
		"(&(objectClass=group)(groupType:"LDB_OID_COMPARATOR_AND":=%u))",
		GROUP_TYPE_BUILTIN_LOCAL_GROUP);
	if (filter == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* Search for each group in the token */
	for (i = 0; i < num_sids; i++) {
		struct dom_sid_buf buf;
		const char *sid_dn;
		DATA_BLOB sid_blob;

		sid_dn = talloc_asprintf(
			frame,
			"<SID=%s>",
			dom_sid_str_buf(&sids[i].sid, &buf));
		if (sid_dn == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		sid_blob = data_blob_string_const(sid_dn);

		/*
		 * This function takes in memberOf values and expands
		 * them, as long as they meet the filter - so only
		 * builtin groups
		 *
		 * We already have the SID in the token, so set
		 * 'only childs' flag to true
		 */
		nt_status = dsdb_expand_nested_groups(sam_ctx,
						      &sid_blob,
						      true,
						      filter,
						      frame,
						      &sids,
						      &num_sids);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(frame);
			return nt_status;
		}
	}

done:
	*_sids = talloc_move(mem_ctx, &sids);
	*_num_sids = num_sids;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS auth_generate_security_token(TALLOC_CTX *mem_ctx,
					       struct loadparm_context *lp_ctx, /* Optional, if you don't want privileges */
					       struct ldb_context *sam_ctx, /* Optional, if you don't want local groups */
					       const struct auth_user_info_dc *user_info_dc,
					       const struct auth_user_info_dc *device_info_dc,
					       const struct auth_claims auth_claims,
					       uint32_t session_info_flags,
					       struct security_token **_security_token)
{
	struct security_token *security_token = NULL;
	NTSTATUS nt_status;
	uint32_t i;
	uint32_t num_sids = 0;
	uint32_t num_device_sids = 0;
	struct auth_SidAttr *sids = NULL;
	struct auth_SidAttr *device_sids = NULL;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = auth_user_info_dc_expand_sids(tmp_ctx,
						  lp_ctx,
						  sam_ctx,
						  user_info_dc,
						  session_info_flags,
						  &sids,
						  &num_sids);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	if (device_info_dc != NULL) {
		/*
		 * Make a copy of the device SIDs in case we need to add extra SIDs on
		 * the end. One can never have too much copying.
		 */
		num_device_sids = device_info_dc->num_sids;
		device_sids = talloc_array(tmp_ctx,
				    struct auth_SidAttr,
				    num_device_sids);
		if (device_sids == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		for (i = 0; i < num_device_sids; i++) {
			device_sids[i] = device_info_dc->sids[i];
		}

		if (session_info_flags & AUTH_SESSION_INFO_DEVICE_DEFAULT_GROUPS) {
			device_sids = talloc_realloc(tmp_ctx,
						     device_sids,
						     struct auth_SidAttr,
						     num_device_sids + 2);
			if (device_sids == NULL) {
				TALLOC_FREE(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}

			device_sids[num_device_sids++] = (struct auth_SidAttr) {
				.sid = global_sid_World,
				.attrs = SE_GROUP_DEFAULT_FLAGS,
			};
			device_sids[num_device_sids++] = (struct auth_SidAttr) {
				.sid = global_sid_Network,
				.attrs = SE_GROUP_DEFAULT_FLAGS,
			};
		}

		if (session_info_flags & AUTH_SESSION_INFO_DEVICE_AUTHENTICATED) {
			device_sids = talloc_realloc(tmp_ctx,
						     device_sids,
						     struct auth_SidAttr,
						     num_device_sids + 1);
			if (device_sids == NULL) {
				TALLOC_FREE(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}

			device_sids[num_device_sids++] = (struct auth_SidAttr) {
				.sid = global_sid_Authenticated_Users,
				.attrs = SE_GROUP_DEFAULT_FLAGS,
			};
		}
	}

	nt_status = security_token_create(mem_ctx,
					  lp_ctx,
					  num_sids,
					  sids,
					  num_device_sids,
					  device_sids,
					  auth_claims,
					  session_info_flags,
					  &security_token);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	talloc_steal(mem_ctx, security_token);
	*_security_token = security_token;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS auth_generate_session_info(TALLOC_CTX *mem_ctx,
					     struct loadparm_context *lp_ctx, /* Optional, if you don't want privileges */
					     struct ldb_context *sam_ctx, /* Optional, if you don't want local groups */
					     const struct auth_user_info_dc *user_info_dc,
					     uint32_t session_info_flags,
					     struct auth_session_info **_session_info)
{
	struct auth_session_info *session_info;
	NTSTATUS nt_status;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	session_info = talloc_zero(tmp_ctx, struct auth_session_info);
	if (session_info == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	session_info->info = talloc_reference(session_info, user_info_dc->info);
	if (session_info->info == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

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
	if (!session_info->session_key.data && user_info_dc->user_session_key.length) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = auth_generate_security_token(session_info,
						 lp_ctx,
						 sam_ctx,
						 user_info_dc,
						 NULL /*device_info_dc */,
						 (struct auth_claims) {},
						 session_info_flags,
						 &session_info->security_token);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	session_info->unique_session_token = GUID_random();

	session_info->credentials = NULL;

	session_info->ticket_type = user_info_dc->ticket_type;

	talloc_steal(mem_ctx, session_info);
	*_session_info = session_info;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}


/* Fill out the auth_session_info with a cli_credentials based on the
 * auth_session_info we were forwarded over named pipe forwarding.
 *
 * NOTE: The structure members of session_info_transport are stolen
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
		bool ok;

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
			gss_release_cred(&minor_status, &cred_handle);
			*reason = "Out of memory in cli_credentials_init()";
			return NULL;
		}
		session_info->credentials = creds;

		ok = cli_credentials_set_conf(creds, lp_ctx);
		if (!ok) {
			gss_release_cred(&minor_status, &cred_handle);
			*reason = "Failed to load smb.conf";
			return NULL;
		}

		/* Just so we don't segfault trying to get at a username */
		cli_credentials_set_anonymous(creds);

		ret = cli_credentials_set_client_gss_creds(creds,
							   lp_ctx,
							   cred_handle,
							   CRED_SPECIFIED,
							   &error_string);
		if (ret) {
			gss_release_cred(&minor_status, &cred_handle);
			*reason = talloc_asprintf(mem_ctx,
						  "Failed to set pipe forwarded "
						  "creds: %s\n", error_string);
			return NULL;
		}

		/* This credential handle isn't useful for password
		 * authentication, so ensure nobody tries to do that */
		cli_credentials_set_kerberos_state(creds,
						   CRED_USE_KERBEROS_REQUIRED,
						   CRED_SPECIFIED);

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


/* Produce a session_info for an arbitrary DN or principal in the local
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
					       user_info_dc,
					       session_info_flags,
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

NTSTATUS encode_claims_set(TALLOC_CTX *mem_ctx,
			   struct CLAIMS_SET *claims_set,
			   DATA_BLOB *claims_blob)
{
	TALLOC_CTX *tmp_ctx = NULL;
	enum ndr_err_code ndr_err;
	struct CLAIMS_SET_NDR *claims_set_info = NULL;
	struct CLAIMS_SET_METADATA *metadata = NULL;
	struct CLAIMS_SET_METADATA_NDR *metadata_ndr = NULL;

	if (claims_blob == NULL) {
		return NT_STATUS_INVALID_PARAMETER_3;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	metadata_ndr = talloc(tmp_ctx, struct CLAIMS_SET_METADATA_NDR);
	if (metadata_ndr == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	metadata = talloc(metadata_ndr, struct CLAIMS_SET_METADATA);
	if (metadata == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	claims_set_info = talloc(metadata, struct CLAIMS_SET_NDR);
	if (claims_set_info == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	*metadata_ndr = (struct CLAIMS_SET_METADATA_NDR) {
		.claims.metadata = metadata,
	};

	*metadata = (struct CLAIMS_SET_METADATA) {
		.claims_set = claims_set_info,
		.compression_format = CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF,
	};

	*claims_set_info = (struct CLAIMS_SET_NDR) {
		.claims.claims = claims_set,
	};

	ndr_err = ndr_push_struct_blob(claims_blob, mem_ctx, metadata_ndr,
				       (ndr_push_flags_fn_t)ndr_push_CLAIMS_SET_METADATA_NDR);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("CLAIMS_SET_METADATA_NDR push failed: %s\n",
			nt_errstr(nt_status));

		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/*
 * Construct a ‘claims_data’ structure from a claims blob, such as is found in a
 * PAC.
 */
NTSTATUS claims_data_from_encoded_claims_set(TALLOC_CTX *claims_data_ctx,
					     const DATA_BLOB *encoded_claims_set,
					     struct claims_data **out)
{
	struct claims_data *claims_data = NULL;
	DATA_BLOB data = {};

	if (out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*out = NULL;

	claims_data = talloc(claims_data_ctx, struct claims_data);
	if (claims_data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (encoded_claims_set != NULL) {
		/*
		 * We make a copy of the data, for it might not be
		 * talloc‐allocated — we might have obtained it directly with
		 * krb5_pac_get_buffer().
		 */
		data = data_blob_dup_talloc(claims_data, *encoded_claims_set);
		if (data.length != encoded_claims_set->length) {
			talloc_free(claims_data);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*claims_data = (struct claims_data) {
		.encoded_claims_set = data,
		.flags = CLAIMS_DATA_ENCODED_CLAIMS_PRESENT,
	};

	*out = claims_data;

	return NT_STATUS_OK;
}

/*
 * Construct a ‘claims_data’ structure from a talloc‐allocated claims set, such
 * as we might build from searching the database. If this function returns
 * successfully, it assumes ownership of the claims set.
 */
NTSTATUS claims_data_from_claims_set(TALLOC_CTX *claims_data_ctx,
				     struct CLAIMS_SET *claims_set,
				     struct claims_data **out)
{
	struct claims_data *claims_data = NULL;

	if (out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*out = NULL;

	claims_data = talloc(claims_data_ctx, struct claims_data);
	if (claims_data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*claims_data = (struct claims_data) {
		.claims_set = talloc_steal(claims_data, claims_set),
		.flags = CLAIMS_DATA_CLAIMS_PRESENT,
	};

	*out = claims_data;

	return NT_STATUS_OK;
}

/*
 * From a ‘claims_data’ structure, return an encoded claims blob that can be put
 * into a PAC.
 */
NTSTATUS claims_data_encoded_claims_set(TALLOC_CTX *mem_ctx,
					struct claims_data *claims_data,
					DATA_BLOB *encoded_claims_set_out)
{
	uint8_t *data = NULL;
	size_t len;

	if (encoded_claims_set_out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*encoded_claims_set_out = data_blob_null;

	if (claims_data == NULL) {
		return NT_STATUS_OK;
	}

	if (!(claims_data->flags & CLAIMS_DATA_ENCODED_CLAIMS_PRESENT)) {
		NTSTATUS status;

		/* See whether we have a claims set that we can encode. */
		if (!(claims_data->flags & CLAIMS_DATA_CLAIMS_PRESENT)) {
			return NT_STATUS_OK;
		}

		status = encode_claims_set(claims_data,
					   claims_data->claims_set,
					   &claims_data->encoded_claims_set);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		claims_data->flags |= CLAIMS_DATA_ENCODED_CLAIMS_PRESENT;
	}

	if (claims_data->encoded_claims_set.data != NULL) {
		data = talloc_reference(mem_ctx, claims_data->encoded_claims_set.data);
		if (data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	len = claims_data->encoded_claims_set.length;

	*encoded_claims_set_out = data_blob_const(data, len);
	return NT_STATUS_OK;
}

/*
 * From a ‘claims_data’ structure, return an array of security claims that can
 * be put in a security token for access checks.
 */
NTSTATUS claims_data_security_claims(TALLOC_CTX *mem_ctx,
				     struct claims_data *claims_data,
				     struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **security_claims_out,
				     uint32_t *n_security_claims_out)
{
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *security_claims = NULL;
	uint32_t n_security_claims;
	NTSTATUS status;

	if (security_claims_out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (n_security_claims_out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*security_claims_out = NULL;
	*n_security_claims_out = 0;

	if (claims_data == NULL) {
		return NT_STATUS_OK;
	}

	if (!(claims_data->flags & CLAIMS_DATA_SECURITY_CLAIMS_PRESENT)) {
		struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *decoded_claims = NULL;
		uint32_t n_decoded_claims = 0;

		/* See whether we have a claims set that we can convert. */
		if (!(claims_data->flags & CLAIMS_DATA_CLAIMS_PRESENT)) {

			/*
			 * See whether we have an encoded claims set that we can
			 * decode.
			 */
			if (!(claims_data->flags & CLAIMS_DATA_ENCODED_CLAIMS_PRESENT)) {
				/* We don’t have anything. */
				return NT_STATUS_OK;
			}

			/* Decode an existing claims set. */

			if (claims_data->encoded_claims_set.length) {
				TALLOC_CTX *tmp_ctx = NULL;
				struct CLAIMS_SET_METADATA_NDR claims;
				const struct CLAIMS_SET_METADATA *metadata = NULL;
				enum ndr_err_code ndr_err;

				tmp_ctx = talloc_new(claims_data);
				if (tmp_ctx == NULL) {
					return NT_STATUS_NO_MEMORY;
				}

				ndr_err = ndr_pull_struct_blob(&claims_data->encoded_claims_set,
							       tmp_ctx,
							       &claims,
							       (ndr_pull_flags_fn_t)ndr_pull_CLAIMS_SET_METADATA_NDR);
				if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
					status = ndr_map_error2ntstatus(ndr_err);
					DBG_ERR("Failed to parse encoded claims set: %s\n",
						nt_errstr(status));
					talloc_free(tmp_ctx);
					return status;
				}

				metadata = claims.claims.metadata;
				if (metadata != NULL) {
					struct CLAIMS_SET_NDR *claims_set_ndr = metadata->claims_set;
					if (claims_set_ndr != NULL) {
						struct CLAIMS_SET **claims_set = &claims_set_ndr->claims.claims;

						claims_data->claims_set = talloc_move(claims_data, claims_set);
					}
				}

				talloc_free(tmp_ctx);
			}

			claims_data->flags |= CLAIMS_DATA_CLAIMS_PRESENT;
		}

		/*
		 * Convert the decoded claims set to the security attribute
		 * claims format.
		 */
		status = token_claims_to_claims_v1(claims_data,
						   claims_data->claims_set,
						   &decoded_claims,
						   &n_decoded_claims);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		claims_data->security_claims = decoded_claims;
		claims_data->n_security_claims = n_decoded_claims;

		claims_data->flags |= CLAIMS_DATA_SECURITY_CLAIMS_PRESENT;
	}

	if (claims_data->security_claims != NULL) {
		security_claims = talloc_reference(mem_ctx, claims_data->security_claims);
		if (security_claims == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	n_security_claims = claims_data->n_security_claims;

	*security_claims_out = security_claims;
	*n_security_claims_out = n_security_claims;

	return NT_STATUS_OK;
}
