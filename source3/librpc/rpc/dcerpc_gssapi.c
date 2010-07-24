/*
 *  GSSAPI Security Extensions
 *  RPC Pipe client routines
 *  Copyright (C) Simo Sorce 2010.
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

/* We support only GSSAPI/KRB5 here */

#include "includes.h"
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include "dcerpc_gssapi.h"

#ifdef HAVE_GSSAPI_H

static char *gse_errstr(TALLOC_CTX *mem_ctx, OM_uint32 maj, OM_uint32 min);

struct gse_context {
	krb5_context k5ctx;
	krb5_ccache ccache;

	bool spnego_wrap;

	gss_ctx_id_t gss_ctx;

	OM_uint32 gss_c_flags;
	gss_OID_desc gss_mech;

	gss_name_t server_name;
	gss_cred_id_t cli_creds;

	DATA_BLOB session_key;

	bool more_processing;
};

/* free non talloc dependent contexts */
static int gse_context_destructor(void *ptr)
{
	struct gse_context *gse_ctx;
	OM_uint32 gss_min, gss_maj;

	gse_ctx = talloc_get_type_abort(ptr, struct gse_context);
	if (gse_ctx->k5ctx) {
		if (gse_ctx->ccache) {
			krb5_cc_close(gse_ctx->k5ctx, gse_ctx->ccache);
			gse_ctx->ccache = NULL;
		}
		krb5_free_context(gse_ctx->k5ctx);
		gse_ctx->k5ctx = NULL;
	}
	if (gse_ctx->gss_ctx != GSS_C_NO_CONTEXT) {
		gss_maj = gss_delete_sec_context(&gss_min,
						 &gse_ctx->gss_ctx,
						 GSS_C_NO_BUFFER);
	}
	if (gse_ctx->server_name) {
		gss_maj = gss_release_name(&gss_min,
					   &gse_ctx->server_name);
	}

	return 0;
}

static NTSTATUS gse_context_init(TALLOC_CTX *mem_ctx,
				 enum dcerpc_AuthType auth_type,
				 enum dcerpc_AuthLevel auth_level,
				 const char *ccache_name,
				 uint32_t add_gss_c_flags,
				 struct gse_context **_gse_ctx)
{
	struct gse_context *gse_ctx;
	krb5_error_code k5ret;
	NTSTATUS status;

	gse_ctx = talloc_zero(mem_ctx, struct gse_context);
	if (!gse_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor((TALLOC_CTX *)gse_ctx, gse_context_destructor);

	memcpy(&gse_ctx->gss_mech, gss_mech_krb5, sizeof(gss_OID_desc));

	switch (auth_type) {
	case DCERPC_AUTH_TYPE_SPNEGO:
		gse_ctx->spnego_wrap = true;
		break;
	case DCERPC_AUTH_TYPE_KRB5:
		gse_ctx->spnego_wrap = false;
		break;
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_out;
	}

	gse_ctx->gss_c_flags = GSS_C_MUTUAL_FLAG |
				GSS_C_DELEG_FLAG |
				GSS_C_DELEG_POLICY_FLAG |
				GSS_C_REPLAY_FLAG |
				GSS_C_SEQUENCE_FLAG;
	switch (auth_level) {
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		gse_ctx->gss_c_flags |= GSS_C_INTEG_FLAG;
		break;
	case DCERPC_AUTH_LEVEL_PRIVACY:
		gse_ctx->gss_c_flags |= GSS_C_CONF_FLAG;
		break;
	default:
		break;
	}

	gse_ctx->gss_c_flags |= add_gss_c_flags;

	/* Initialize Kerberos Context */
	initialize_krb5_error_table();

	k5ret = krb5_init_context(&gse_ctx->k5ctx);
	if (k5ret) {
		DEBUG(0, ("Failed to initialize kerberos context! (%s)\n",
			  error_message(k5ret)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto err_out;
	}

	if (!ccache_name) {
		ccache_name = krb5_cc_default_name(gse_ctx->k5ctx);
	}
	k5ret = krb5_cc_resolve(gse_ctx->k5ctx, ccache_name,
				&gse_ctx->ccache);
	if (k5ret) {
		DEBUG(1, ("Failed to resolve credential cache! (%s)\n",
			  error_message(k5ret)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto err_out;
	}

	/* TODO: Should we enforce a enc_types list ?
	ret = krb5_set_default_tgs_ktypes(gse_ctx->k5ctx, enc_types);
	*/

	*_gse_ctx = gse_ctx;
	return NT_STATUS_OK;

err_out:
	TALLOC_FREE(gse_ctx);
	return status;
}

NTSTATUS gse_init_client(TALLOC_CTX *mem_ctx,
			  enum dcerpc_AuthType auth_type,
			  enum dcerpc_AuthLevel auth_level,
			  const char *ccache_name,
			  const char *server,
			  const char *service,
			  const char *username,
			  const char *password,
			  uint32_t add_gss_c_flags,
			  struct pipe_auth_data **_auth)
{
	struct pipe_auth_data *auth;
	struct gse_context *gse_ctx;
	OM_uint32 gss_maj, gss_min;
	gss_buffer_desc name_buffer = {0, NULL};
	gss_OID_set_desc mech_set;
	NTSTATUS status;

	if (!server || !service) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	auth = talloc(mem_ctx, struct pipe_auth_data);
	if (auth == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	auth->auth_type = auth_type;
	if (auth_type == DCERPC_AUTH_TYPE_SPNEGO) {
		auth->spnego_type = PIPE_AUTH_TYPE_SPNEGO_KRB5;
	}
	auth->auth_level = auth_level;

	if (!username) {
		username = "";
	}

	auth->user_name = talloc_strdup(auth, username);
	if (!auth->user_name) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	/* Fixme, should we fetch/set the Realm ? */
	auth->domain = talloc_strdup(auth, "");
	if (!auth->domain) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	status = gse_context_init(auth, auth_type, auth_level,
				  ccache_name, add_gss_c_flags,
				  &gse_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_out;
	}

	name_buffer.value = talloc_asprintf(auth, "%s@%s", service, server);
	if (!name_buffer.value) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}
	name_buffer.length = strlen((char *)name_buffer.value);
	gss_maj = gss_import_name(&gss_min, &name_buffer,
				  GSS_C_NT_HOSTBASED_SERVICE,
				  &gse_ctx->server_name);
	if (gss_maj) {
		DEBUG(0, ("gss_import_name failed for %s, with [%s]\n",
			  (char *)name_buffer.value,
			  gse_errstr(auth, gss_maj, gss_min)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto err_out;
	}

	/* TODO: get krb5 ticket using username/password, if no valid
	 * one already available in ccache */

	mech_set.count = 1;
	mech_set.elements = &gse_ctx->gss_mech;

	gss_maj = gss_acquire_cred(&gss_min,
				   GSS_C_NO_NAME,
				   GSS_C_INDEFINITE,
				   &mech_set,
				   GSS_C_INITIATE,
				   &gse_ctx->cli_creds,
				   NULL, NULL);
	if (gss_maj) {
		DEBUG(0, ("gss_acquire_creds failed for %s, with [%s]\n",
			  (char *)name_buffer.value,
			  gse_errstr(auth, gss_maj, gss_min)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto err_out;
	}

	auth->a_u.gssapi_state = gse_ctx;
	*_auth = auth;
	TALLOC_FREE(name_buffer.value);
	return NT_STATUS_OK;

err_out:
	TALLOC_FREE(auth);
	return status;
}

NTSTATUS gse_get_client_auth_token(TALLOC_CTX *mem_ctx,
				   struct gse_context *gse_ctx,
				   DATA_BLOB *token_in,
				   DATA_BLOB *token_out)
{
	OM_uint32 gss_maj, gss_min;
	gss_buffer_desc in_data;
	gss_buffer_desc out_data;
	DATA_BLOB blob = data_blob_null;
	NTSTATUS status;

	in_data.value = token_in->data;
	in_data.length = token_in->length;

	gss_maj = gss_init_sec_context(&gss_min,
					gse_ctx->cli_creds,
					&gse_ctx->gss_ctx,
					gse_ctx->server_name,
					&gse_ctx->gss_mech,
					gse_ctx->gss_c_flags,
					0, GSS_C_NO_CHANNEL_BINDINGS,
					&in_data, NULL, &out_data,
					NULL, NULL);
	switch (gss_maj) {
	case GSS_S_COMPLETE:
		/* we are done with it */
		gse_ctx->more_processing = false;
		status = NT_STATUS_OK;
		break;
	case GSS_S_CONTINUE_NEEDED:
		/* we will need a third leg */
		gse_ctx->more_processing = true;
		/* status = NT_STATUS_MORE_PROCESSING_REQUIRED; */
		status = NT_STATUS_OK;
		break;
	default:
		DEBUG(0, ("gss_init_sec_context failed with [%s]\n",
			  gse_errstr(talloc_tos(), gss_maj, gss_min)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	blob = data_blob_talloc(mem_ctx, out_data.value, out_data.length);
	if (!blob.data) {
		status = NT_STATUS_NO_MEMORY;
	}

	gss_maj = gss_release_buffer(&gss_min, &out_data);

done:
	*token_out = blob;
	return status;
}

static char *gse_errstr(TALLOC_CTX *mem_ctx, OM_uint32 maj, OM_uint32 min)
{
	OM_uint32 gss_min, gss_maj;
	gss_buffer_desc msg_min;
	gss_buffer_desc msg_maj;
	OM_uint32 msg_ctx = 0;

	char *errstr = NULL;

	ZERO_STRUCT(msg_min);
	ZERO_STRUCT(msg_maj);

	gss_maj = gss_display_status(&gss_min, maj, GSS_C_GSS_CODE,
				     GSS_C_NO_OID, &msg_ctx, &msg_maj);
	if (gss_maj) {
		goto done;
	}
	gss_maj = gss_display_status(&gss_min, min, GSS_C_MECH_CODE,
				     discard_const(gss_mech_krb5),
				     &msg_ctx, &msg_min);
	if (gss_maj) {
		goto done;
	}

	errstr = talloc_strndup(mem_ctx,
				(char *)msg_maj.value,
					msg_maj.length);
	if (!errstr) {
		goto done;
	}
	errstr = talloc_strdup_append_buffer(errstr, ": ");
	if (!errstr) {
		goto done;
	}
	errstr = talloc_strndup_append_buffer(errstr,
						(char *)msg_min.value,
							msg_min.length);
	if (!errstr) {
		goto done;
	}

done:
	if (msg_min.value) {
		gss_maj = gss_release_buffer(&gss_min, &msg_min);
	}
	if (msg_maj.value) {
		gss_maj = gss_release_buffer(&gss_min, &msg_maj);
	}
	return errstr;
}

bool gse_require_more_processing(struct gse_context *gse_ctx)
{
	return gse_ctx->more_processing;
}

DATA_BLOB gse_get_session_key(struct gse_context *gse_ctx)
{
	return gse_ctx->session_key;
}

#else /* HAVE_GSSAPI_H */

NTSTATUS gse_init_client(TALLOC_CTX *mem_ctx,
			  enum dcerpc_AuthType auth_type,
			  enum dcerpc_AuthLevel auth_level,
			  const char *ccache_name,
			  const char *server,
			  const char *service,
			  const char *username,
			  const char *password,
			  uint32_t add_gss_c_flags,
			  struct pipe_auth_data **_auth)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS gse_gen_client_auth_token(TALLOC_CTX *mem_ctx,
				   struct gse_context *gse_ctx,
				   DATA_BLOB *auth_blob)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

bool gse_require_more_processing(struct gse_context *gse_ctx)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

DATA_BLOB gse_get_session_key(struct gse_context *gse_ctx)
{
	return data_blob_null;
}

#endif /* HAVE_GSSAPI_H */
