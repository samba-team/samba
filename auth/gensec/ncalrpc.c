/*
   Unix SMB/CIFS implementation.

   dcerpc ncalrpc as system operations

   Copyright (C) 2014      Andreas Schneider <asn@samba.org>
   Copyright (C) 2014      Stefan Metzmacher <metze@samba.org>

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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "lib/param/param.h"
#include "tsocket.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

_PUBLIC_ NTSTATUS gensec_ncalrpc_as_system_init(TALLOC_CTX *ctx);

struct gensec_ncalrpc_state {
	enum {
		GENSEC_NCALRPC_START,
		GENSEC_NCALRPC_MORE,
		GENSEC_NCALRPC_DONE,
		GENSEC_NCALRPC_ERROR,
	} step;

	struct auth_user_info_dc *user_info_dc;
};

static NTSTATUS gensec_ncalrpc_client_start(struct gensec_security *gensec_security)
{
	struct gensec_ncalrpc_state *state;

	state = talloc_zero(gensec_security,
			    struct gensec_ncalrpc_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec_security->private_data = state;

	state->step = GENSEC_NCALRPC_START;
	return NT_STATUS_OK;
}

static NTSTATUS gensec_ncalrpc_server_start(struct gensec_security *gensec_security)
{
	struct gensec_ncalrpc_state *state;

	state = talloc_zero(gensec_security,
			    struct gensec_ncalrpc_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec_security->private_data = state;

	state->step = GENSEC_NCALRPC_START;
	return NT_STATUS_OK;
}

struct gensec_ncalrpc_update_state {
	NTSTATUS status;
	DATA_BLOB out;
};

static NTSTATUS gensec_ncalrpc_update_internal(
				struct gensec_security *gensec_security,
				TALLOC_CTX *mem_ctx,
				const DATA_BLOB in,
				DATA_BLOB *out);

static struct tevent_req *gensec_ncalrpc_update_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct gensec_security *gensec_security,
					const DATA_BLOB in)
{
	struct tevent_req *req;
	struct gensec_ncalrpc_update_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_ncalrpc_update_state);
	if (req == NULL) {
		return NULL;
	}

	status = gensec_ncalrpc_update_internal(gensec_security,
						state, in,
						&state->out);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS gensec_ncalrpc_update_internal(
				struct gensec_security *gensec_security,
				TALLOC_CTX *mem_ctx,
				const DATA_BLOB in,
				DATA_BLOB *out)
{
	struct gensec_ncalrpc_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct gensec_ncalrpc_state);
	DATA_BLOB magic_req = data_blob_string_const("NCALRPC_AUTH_TOKEN");
	DATA_BLOB magic_ok = data_blob_string_const("NCALRPC_AUTH_OK");
	DATA_BLOB magic_fail = data_blob_string_const("NCALRPC_AUTH_FAIL");
	char *unix_path = NULL;
	int cmp;
	NTSTATUS status;

	*out = data_blob_null;

	if (state->step >= GENSEC_NCALRPC_DONE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		switch (state->step) {
		case GENSEC_NCALRPC_START:
			*out = data_blob_dup_talloc(mem_ctx, magic_req);
			if (out->data == NULL) {
				state->step = GENSEC_NCALRPC_ERROR;
				return NT_STATUS_NO_MEMORY;
			}

			state->step = GENSEC_NCALRPC_MORE;
			return NT_STATUS_MORE_PROCESSING_REQUIRED;

		case GENSEC_NCALRPC_MORE:
			cmp = data_blob_cmp(&in, &magic_ok);
			if (cmp != 0) {
				state->step = GENSEC_NCALRPC_ERROR;
				return NT_STATUS_LOGON_FAILURE;
			}

			state->step = GENSEC_NCALRPC_DONE;
			return NT_STATUS_OK;

		case GENSEC_NCALRPC_DONE:
		case GENSEC_NCALRPC_ERROR:
			break;
		}

		state->step = GENSEC_NCALRPC_ERROR;
		return NT_STATUS_INTERNAL_ERROR;

	case GENSEC_SERVER:
		if (state->step != GENSEC_NCALRPC_START) {
			state->step = GENSEC_NCALRPC_ERROR;
			return NT_STATUS_INTERNAL_ERROR;
		}

		cmp = data_blob_cmp(&in, &magic_req);
		if (cmp != 0) {
			state->step = GENSEC_NCALRPC_ERROR;
			*out = data_blob_dup_talloc(mem_ctx, magic_fail);
			if (out->data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			return NT_STATUS_LOGON_FAILURE;
		}

		if (gensec_security->remote_addr == NULL) {
			state->step = GENSEC_NCALRPC_ERROR;
			*out = data_blob_dup_talloc(mem_ctx, magic_fail);
			if (out->data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			return NT_STATUS_LOGON_FAILURE;
		}

		unix_path = tsocket_address_unix_path(gensec_security->remote_addr,
						      state);
		if (unix_path == NULL) {
			state->step = GENSEC_NCALRPC_ERROR;
			*out = data_blob_dup_talloc(mem_ctx, magic_fail);
			if (out->data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			return NT_STATUS_LOGON_FAILURE;
		}

		cmp = strcmp(unix_path, AS_SYSTEM_MAGIC_PATH_TOKEN);
		TALLOC_FREE(unix_path);
		if (cmp != 0) {
			state->step = GENSEC_NCALRPC_ERROR;
			*out = data_blob_dup_talloc(mem_ctx, magic_fail);
			if (out->data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			return NT_STATUS_LOGON_FAILURE;
		}

		status = auth_system_user_info_dc(state,
				lpcfg_netbios_name(gensec_security->settings->lp_ctx),
				&state->user_info_dc);
		if (!NT_STATUS_IS_OK(status)) {
			state->step = GENSEC_NCALRPC_ERROR;
			*out = data_blob_dup_talloc(mem_ctx, magic_fail);
			if (out->data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			return status;
		}

		*out = data_blob_dup_talloc(mem_ctx, magic_ok);
		if (out->data == NULL) {
			state->step = GENSEC_NCALRPC_ERROR;
			return NT_STATUS_NO_MEMORY;
		}

		state->step = GENSEC_NCALRPC_DONE;
		return NT_STATUS_OK;
	}

	state->step = GENSEC_NCALRPC_ERROR;
	return NT_STATUS_INTERNAL_ERROR;
}

static NTSTATUS gensec_ncalrpc_update_recv(struct tevent_req *req,
					   TALLOC_CTX *out_mem_ctx,
					   DATA_BLOB *out)
{
	struct gensec_ncalrpc_update_state *state =
		tevent_req_data(req,
		struct gensec_ncalrpc_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	status = state->status;
	talloc_steal(out_mem_ctx, state->out.data);
	*out = state->out;
	tevent_req_received(req);
	return status;
}

static NTSTATUS gensec_ncalrpc_session_info(struct gensec_security *gensec_security,
					    TALLOC_CTX *mem_ctx,
					    struct auth_session_info **psession_info)
{
	struct gensec_ncalrpc_state *state =
		talloc_get_type_abort(gensec_security->private_data,
		struct gensec_ncalrpc_state);
	struct auth4_context *auth_ctx = gensec_security->auth_context;
	struct auth_session_info *session_info = NULL;
	uint32_t session_info_flags = 0;
	NTSTATUS status;

	if (gensec_security->gensec_role != GENSEC_SERVER) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state->step != GENSEC_NCALRPC_DONE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (auth_ctx == NULL) {
		DEBUG(0, ("Cannot generate a session_info without the auth_context\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (auth_ctx->generate_session_info == NULL) {
		DEBUG(0, ("Cannot generate a session_info without the generate_session_info hook\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;

	status = auth_ctx->generate_session_info(
				auth_ctx,
				mem_ctx,
				state->user_info_dc,
				state->user_info_dc->info->account_name,
				session_info_flags,
				&session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*psession_info = session_info;
	return NT_STATUS_OK;
}

/* We have no features */
static bool gensec_ncalrpc_have_feature(struct gensec_security *gensec_security,
				 uint32_t feature)
{
	if (feature & GENSEC_FEATURE_DCE_STYLE) {
		return true;
	}

	return false;
}

static const struct gensec_security_ops gensec_ncalrpc_security_ops = {
	.name           = "naclrpc_as_system",
	.auth_type      = DCERPC_AUTH_TYPE_NCALRPC_AS_SYSTEM,
	.client_start   = gensec_ncalrpc_client_start,
	.server_start   = gensec_ncalrpc_server_start,
	.update_send    = gensec_ncalrpc_update_send,
	.update_recv    = gensec_ncalrpc_update_recv,
	.session_info   = gensec_ncalrpc_session_info,
	.have_feature   = gensec_ncalrpc_have_feature,
	.enabled        = true,
	.priority       = GENSEC_EXTERNAL,
};

_PUBLIC_ NTSTATUS gensec_ncalrpc_as_system_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = gensec_register(ctx, &gensec_ncalrpc_security_ops);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register '%s' gensec backend!\n",
			  gensec_ncalrpc_security_ops.name));
		return status;
	}

	return status;
}
