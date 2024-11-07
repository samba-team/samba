/*
 * Unix SMB/CIFS implementation.
 * tls based tldap connect
 * Copyright (C) Stefan Metzmacher 2024
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "tldap.h"
#include "tldap_tls_connect.h"
#include "lib/util/samba_util.h"
#include "lib/util/debug.h"
#include "lib/param/param.h"
#include "../libcli/util/ntstatus.h"
#include "../source4/lib/tls/tls.h"

struct tldap_tls_connect_state {
	struct tevent_context *ev;
	struct tldap_context *ctx;
	struct tstream_tls_params *tls_params;
};

static void tldap_tls_connect_crypto_done(struct tevent_req *subreq);

struct tevent_req *tldap_tls_connect_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tldap_context *ctx,
					  struct tstream_tls_params *tls_params)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct tldap_tls_connect_state *state = NULL;
	struct tstream_context *plain_stream = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct tldap_tls_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->ctx = ctx;
	state->tls_params = tls_params;

	if (!tldap_connection_ok(ctx)) {
		DBG_ERR("tldap_connection_ok() => false\n");
		tevent_req_ldap_error(req, TLDAP_CONNECT_ERROR);
		return tevent_req_post(req, ev);
	}

	if (tldap_has_gensec_tstream(ctx)) {
		DBG_ERR("tldap_has_gensec_tstream() => true\n");
		tevent_req_ldap_error(req, TLDAP_LOCAL_ERROR);
		return tevent_req_post(req, ev);
	}

	plain_stream = tldap_get_plain_tstream(state->ctx);
	if (plain_stream == NULL) {
		DBG_ERR("tldap_get_plain_tstream() = NULL\n");
		tevent_req_ldap_error(req, TLDAP_LOCAL_ERROR);
		return req;
	}

	subreq = tstream_tls_connect_send(state,
					  state->ev,
					  plain_stream,
					  state->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				tldap_tls_connect_crypto_done,
				req);
	return req;
}

static void tldap_tls_connect_crypto_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_tls_connect_state *state = tevent_req_data(
		req, struct tldap_tls_connect_state);
	struct tstream_context *tls_stream = NULL;
	int ret;
	int error;

	ret = tstream_tls_connect_recv(subreq, &error, state, &tls_stream);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DBG_ERR("tstream_tls_connect_recv(%s): %d %d\n",
			tstream_tls_params_peer_name(state->tls_params),
			ret,
			error);
		tevent_req_ldap_error(req, TLDAP_CONNECT_ERROR);
		return;
	}

	tldap_set_tls_tstream(state->ctx, &tls_stream);

	tevent_req_done(req);
}

TLDAPRC tldap_tls_connect_recv(struct tevent_req *req)
{
	TLDAPRC rc;

	if (tevent_req_is_ldap_error(req, &rc)) {
		return rc;
	}

	return TLDAP_SUCCESS;
}

TLDAPRC tldap_tls_connect(struct tldap_context *ctx,
			  struct tstream_tls_params *tls_params)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	TLDAPRC rc = TLDAP_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tldap_tls_connect_send(frame, ev, ctx, tls_params);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		rc = TLDAP_OPERATIONS_ERROR;
		goto fail;
	}
	rc = tldap_tls_connect_recv(req);
 fail:
	TALLOC_FREE(frame);
	return rc;
}
