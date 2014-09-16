/*
   Unix SMB/CIFS implementation.

   HTTP library - NTLM authentication mechanism gensec module

   Copyright (C) 2014 Samuel Cabrero <samuelcabrero@kernevil.me>

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
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"

_PUBLIC_ NTSTATUS gensec_http_ntlm_init(void);

struct gensec_http_ntlm_state {
	struct gensec_security *sub;
};

static NTSTATUS gensec_http_ntlm_client_start(struct gensec_security *gensec)
{
	NTSTATUS status;
	struct gensec_http_ntlm_state *state;

	state = talloc_zero(gensec, struct gensec_http_ntlm_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec->private_data = state;

	status = gensec_subcontext_start(state, gensec, &state->sub);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return gensec_start_mech_by_oid(state->sub, GENSEC_OID_NTLMSSP);
}

static NTSTATUS gensec_http_ntlm_update(struct gensec_security *gensec_ctx,
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const DATA_BLOB in,
					DATA_BLOB *out)
{
	NTSTATUS status;
	struct gensec_http_ntlm_state *state;
	DATA_BLOB ntlm_in;

	state = talloc_get_type_abort(gensec_ctx->private_data,
				      struct gensec_http_ntlm_state);

	if (in.length) {
		if (strncasecmp((char *)in.data, "NTLM ", 5) != 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ntlm_in = base64_decode_data_blob_talloc(mem_ctx,
							 (char *)&in.data[5]);
	} else {
		ntlm_in = data_blob_null;
	}

	status = gensec_update_ev(state->sub, mem_ctx, ev, ntlm_in, out);
	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		char *tmp, *b64;
		b64 = base64_encode_data_blob(mem_ctx, *out);
		if (b64 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		tmp = talloc_asprintf(mem_ctx, "NTLM %s", b64);
		TALLOC_FREE(b64);
		if (tmp == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		*out = data_blob_string_const(tmp);
	}

	if (ntlm_in.data) {
		data_blob_free(&ntlm_in);
	}

	return status;
}

static const struct gensec_security_ops gensec_http_ntlm_security_ops = {
	.name           = "http_ntlm",
	.auth_type      = 0,
	.client_start   = gensec_http_ntlm_client_start,
	.update         = gensec_http_ntlm_update,
	.enabled        = true,
	.priority       = GENSEC_EXTERNAL,
};

_PUBLIC_ NTSTATUS gensec_http_ntlm_init(void)
{
	NTSTATUS status;

	status = gensec_register(&gensec_http_ntlm_security_ops);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register '%s' gensec backend!\n",
				gensec_http_ntlm_security_ops.name));
		return status;
	}

	return status;
}
