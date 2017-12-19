/*
   Unix SMB/CIFS implementation.

   SASL/EXTERNAL authentication.

   Copyright (C) Howard Chu <hyc@symas.com> 2013

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
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/gensec/gensec_proto.h"
#include "auth/gensec/gensec_toplevel_proto.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/* SASL/EXTERNAL is essentially a no-op; it is only usable when the transport
 * layer is already mutually authenticated.
 */

NTSTATUS gensec_external_init(TALLOC_CTX *ctx);

static NTSTATUS gensec_external_start(struct gensec_security *gensec_security)
{
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN)
		return NT_STATUS_INVALID_PARAMETER;
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL)
		return NT_STATUS_INVALID_PARAMETER;

	return NT_STATUS_OK;
}

struct gensec_external_update_state {
	DATA_BLOB out;
};

static struct tevent_req *gensec_external_update_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct gensec_security *gensec_security,
					const DATA_BLOB in)
{
	struct tevent_req *req;
	struct gensec_external_update_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_external_update_state);
	if (req == NULL) {
		return NULL;
	}

	state->out = data_blob_talloc(state, "", 0);
	if (tevent_req_nomem(state->out.data, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS gensec_external_update_recv(struct tevent_req *req,
					    TALLOC_CTX *out_mem_ctx,
					    DATA_BLOB *out)
{
	struct gensec_external_update_state *state =
		tevent_req_data(req,
		struct gensec_external_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out = state->out;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/* We have no features */
static bool gensec_external_have_feature(struct gensec_security *gensec_security,
				     uint32_t feature)
{
	return false;
}

static const struct gensec_security_ops gensec_external_ops = {
	.name             = "sasl-EXTERNAL",
	.sasl_name        = "EXTERNAL",
	.client_start     = gensec_external_start,
	.update_send      = gensec_external_update_send,
	.update_recv      = gensec_external_update_recv,
	.have_feature     = gensec_external_have_feature,
	.enabled          = true,
	.priority         = GENSEC_EXTERNAL
};


NTSTATUS gensec_external_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = gensec_register(ctx, &gensec_external_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			 gensec_external_ops.name));
	}
	return ret;
}
