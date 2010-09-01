/*
 *  SPNEGO Encapsulation
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

#include "includes.h"
#include "../libcli/auth/spnego.h"
#include "include/ntlmssp_wrap.h"
#include "librpc/gen_ndr/ntlmssp.h"
#include "dcerpc_spnego.h"
#include "librpc/crypto/gse.h"

struct spnego_context {
	enum dcerpc_AuthType auth_type;

	union {
		struct auth_ntlmssp_state *ntlmssp_state;
		struct gse_context *gssapi_state;
	} mech_ctx;

	enum {
		SPNEGO_CONV_INIT = 0,
		SPNEGO_CONV_AUTH_MORE,
		SPNEGO_CONV_AUTH_CONFIRM,
		SPNEGO_CONV_AUTH_DONE
	} state;
};

static NTSTATUS spnego_context_init(TALLOC_CTX *mem_ctx,
				    enum dcerpc_AuthType auth_type,
				    struct spnego_context **spnego_ctx)
{
	struct spnego_context *sp_ctx;

	sp_ctx = talloc_zero(mem_ctx, struct spnego_context);
	if (!sp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	sp_ctx->auth_type = auth_type;
	sp_ctx->state = SPNEGO_CONV_INIT;

	*spnego_ctx = sp_ctx;
	return NT_STATUS_OK;
}

NTSTATUS spnego_gssapi_init_client(TALLOC_CTX *mem_ctx,
				   enum dcerpc_AuthLevel auth_level,
				   const char *ccache_name,
				   const char *server,
				   const char *service,
				   const char *username,
				   const char *password,
				   uint32_t add_gss_c_flags,
				   struct spnego_context **spnego_ctx)
{
	struct spnego_context *sp_ctx = NULL;
	NTSTATUS status;

	status = spnego_context_init(mem_ctx,
					DCERPC_AUTH_TYPE_KRB5, &sp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gse_init_client(sp_ctx, DCERPC_AUTH_TYPE_KRB5, auth_level,
				 ccache_name, server, service,
				 username, password, add_gss_c_flags,
				 &sp_ctx->mech_ctx.gssapi_state);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sp_ctx);
		return status;
	}

	*spnego_ctx = sp_ctx;
	return NT_STATUS_OK;
}

NTSTATUS spnego_ntlmssp_init_client(TALLOC_CTX *mem_ctx,
				    enum dcerpc_AuthLevel auth_level,
				    const char *domain,
				    const char *username,
				    const char *password,
				    struct spnego_context **spnego_ctx)
{
	struct spnego_context *sp_ctx = NULL;
	NTSTATUS status;

	status = spnego_context_init(mem_ctx,
					DCERPC_AUTH_TYPE_NTLMSSP, &sp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = auth_ntlmssp_client_start(sp_ctx,
					global_myname(),
					lp_workgroup(),
					lp_client_ntlmv2_auth(),
					&sp_ctx->mech_ctx.ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sp_ctx);
		return status;
	}

	status = auth_ntlmssp_set_username(sp_ctx->mech_ctx.ntlmssp_state,
					   username);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sp_ctx);
		return status;
	}

	status = auth_ntlmssp_set_domain(sp_ctx->mech_ctx.ntlmssp_state,
					 domain);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sp_ctx);
		return status;
	}

	status = auth_ntlmssp_set_password(sp_ctx->mech_ctx.ntlmssp_state,
					   password);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(sp_ctx);
		return status;
	}

	/*
	 * Turn off sign+seal to allow selected auth level to turn it back on.
	 */
	auth_ntlmssp_and_flags(sp_ctx->mech_ctx.ntlmssp_state,
						~(NTLMSSP_NEGOTIATE_SIGN |
						  NTLMSSP_NEGOTIATE_SEAL));

	if (auth_level == DCERPC_AUTH_LEVEL_INTEGRITY) {
		auth_ntlmssp_or_flags(sp_ctx->mech_ctx.ntlmssp_state,
						NTLMSSP_NEGOTIATE_SIGN);
	} else if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		auth_ntlmssp_or_flags(sp_ctx->mech_ctx.ntlmssp_state,
						NTLMSSP_NEGOTIATE_SEAL |
						NTLMSSP_NEGOTIATE_SIGN);
	}

	*spnego_ctx = sp_ctx;
	return NT_STATUS_OK;
}

NTSTATUS spnego_get_client_auth_token(TALLOC_CTX *mem_ctx,
				      struct spnego_context *sp_ctx,
				      DATA_BLOB *spnego_in,
				      DATA_BLOB *spnego_out)
{
	struct gse_context *gse_ctx;
	struct auth_ntlmssp_state *ntlmssp_ctx;
	struct spnego_data sp_in, sp_out;
	DATA_BLOB token_in = data_blob_null;
	DATA_BLOB token_out = data_blob_null;
	const char *mech_oids[2] = { NULL, NULL };
	char *principal = NULL;
	ssize_t len_in = 0;
	ssize_t len_out = 0;
	bool mech_wants_more = false;
	NTSTATUS status;

	if (!spnego_in->length) {
		/* server didn't send anything, is init ? */
		if (sp_ctx->state != SPNEGO_CONV_INIT) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	} else {
		len_in = spnego_read_data(mem_ctx, *spnego_in, &sp_in);
		if (len_in == -1) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}
		if (sp_in.type != SPNEGO_NEG_TOKEN_TARG) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}
		if (sp_in.negTokenTarg.negResult == SPNEGO_REJECT) {
			status = NT_STATUS_ACCESS_DENIED;
			goto done;
		}
		token_in = sp_in.negTokenTarg.responseToken;
	}

	if (sp_ctx->state == SPNEGO_CONV_AUTH_CONFIRM) {
		if (sp_in.negTokenTarg.negResult == SPNEGO_ACCEPT_COMPLETED) {
			sp_ctx->state = SPNEGO_CONV_AUTH_DONE;
			*spnego_out = data_blob_null;
			status = NT_STATUS_OK;
		} else {
			status = NT_STATUS_ACCESS_DENIED;
		}
		goto done;
	}

	switch (sp_ctx->auth_type) {
	case DCERPC_AUTH_TYPE_KRB5:

		gse_ctx = sp_ctx->mech_ctx.gssapi_state;
		status = gse_get_client_auth_token(mem_ctx, gse_ctx,
						   &token_in, &token_out);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		mech_oids[0] = OID_KERBEROS5;
		mech_wants_more = gse_require_more_processing(gse_ctx);

		break;

	case DCERPC_AUTH_TYPE_NTLMSSP:

		ntlmssp_ctx = sp_ctx->mech_ctx.ntlmssp_state;
		status = auth_ntlmssp_update(ntlmssp_ctx,
					     token_in, &token_out);
		if (NT_STATUS_EQUAL(status,
				    NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			mech_wants_more = true;
		} else if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		mech_oids[0] = OID_NTLMSSP;

		break;

	default:
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	switch (sp_ctx->state) {
	case SPNEGO_CONV_INIT:
		*spnego_out = spnego_gen_negTokenInit(mem_ctx, mech_oids,
						      &token_out, principal);
		if (!spnego_out->data) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto done;
		}
		sp_ctx->state = SPNEGO_CONV_AUTH_MORE;
		break;

	case SPNEGO_CONV_AUTH_MORE:
		/* server says it's done and we do not seem to agree */
		if (sp_in.negTokenTarg.negResult ==
						SPNEGO_ACCEPT_COMPLETED) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

		sp_out.type = SPNEGO_NEG_TOKEN_TARG;
		sp_out.negTokenTarg.negResult = SPNEGO_NONE_RESULT;
		sp_out.negTokenTarg.supportedMech = NULL;
		sp_out.negTokenTarg.responseToken = token_out;
		sp_out.negTokenTarg.mechListMIC = data_blob_null;

		len_out = spnego_write_data(mem_ctx, spnego_out, &sp_out);
		if (len_out == -1) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto done;
		}

		if (!mech_wants_more) {
			/* we still need to get an ack from the server */
			sp_ctx->state = SPNEGO_CONV_AUTH_CONFIRM;
		}

		break;

	default:
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	status = NT_STATUS_OK;

done:
	if (len_in > 0) {
		spnego_free_data(&sp_in);
	}
	data_blob_free(&token_out);
	return status;
}

bool spnego_require_more_processing(struct spnego_context *sp_ctx)
{
	struct gse_context *gse_ctx;

	/* see if spnego processing itself requires more */
	if (sp_ctx->state == SPNEGO_CONV_AUTH_MORE ||
	    sp_ctx->state == SPNEGO_CONV_AUTH_CONFIRM) {
		return true;
	}

	/* otherwise see if underlying mechnism does */
	switch (sp_ctx->auth_type) {
	case DCERPC_AUTH_TYPE_KRB5:
		gse_ctx = sp_ctx->mech_ctx.gssapi_state;
		return gse_require_more_processing(gse_ctx);
	case DCERPC_AUTH_TYPE_NTLMSSP:
		return false;
	default:
		DEBUG(0, ("Unsupported type in request!\n"));
		return false;
	}
}

NTSTATUS spnego_get_negotiated_mech(struct spnego_context *sp_ctx,
				    enum dcerpc_AuthType *auth_type,
				    void **auth_context)
{
	switch (sp_ctx->auth_type) {
	case DCERPC_AUTH_TYPE_KRB5:
		*auth_context = sp_ctx->mech_ctx.gssapi_state;
		break;
	case DCERPC_AUTH_TYPE_NTLMSSP:
		*auth_context = sp_ctx->mech_ctx.ntlmssp_state;
		break;
	default:
		return NT_STATUS_INTERNAL_ERROR;
	}

	*auth_type = sp_ctx->auth_type;
	return NT_STATUS_OK;
}

DATA_BLOB spnego_get_session_key(TALLOC_CTX *mem_ctx,
				 struct spnego_context *sp_ctx)
{
	DATA_BLOB sk;

	switch (sp_ctx->auth_type) {
	case DCERPC_AUTH_TYPE_KRB5:
		return gse_get_session_key(mem_ctx,
					   sp_ctx->mech_ctx.gssapi_state);
	case DCERPC_AUTH_TYPE_NTLMSSP:
		sk = auth_ntlmssp_get_session_key(
					sp_ctx->mech_ctx.ntlmssp_state);
		return data_blob_dup_talloc(mem_ctx, &sk);
	default:
		DEBUG(0, ("Unsupported type in request!\n"));
		return data_blob_null;
	}
}

