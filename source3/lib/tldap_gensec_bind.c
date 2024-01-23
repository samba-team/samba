/*
 * Unix SMB/CIFS implementation.
 * Gensec based tldap auth
 * Copyright (C) Volker Lendecke 2015
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
#include "tldap_gensec_bind.h"
#include "auth/credentials/credentials.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/samba_util.h"
#include "lib/util/debug.h"
#include "auth/gensec/gensec.h"
#include "lib/param/param.h"
#include "source4/auth/gensec/gensec_tstream.h"

struct tldap_gensec_bind_state {
	struct tevent_context *ev;
	struct tldap_context *ctx;
	struct cli_credentials *creds;
	const char *target_service;
	const char *target_hostname;
	const char *target_principal;
	struct loadparm_context *lp_ctx;
	uint32_t gensec_features;

	bool first;
	struct gensec_security *gensec;
	NTSTATUS gensec_status;
	DATA_BLOB gensec_input;
	DATA_BLOB gensec_output;
};

static void tldap_gensec_update_next(struct tevent_req *req);
static void tldap_gensec_update_done(struct tevent_req *subreq);
static void tldap_gensec_bind_done(struct tevent_req *subreq);

struct tevent_req *tldap_gensec_bind_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct tldap_context *ctx, struct cli_credentials *creds,
	const char *target_service, const char *target_hostname,
	const char *target_principal, struct loadparm_context *lp_ctx,
	uint32_t gensec_features)
{
	struct tevent_req *req = NULL;
	struct tldap_gensec_bind_state *state = NULL;
	const DATA_BLOB *tls_cb = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct tldap_gensec_bind_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->ctx = ctx;
	state->creds = creds;
	state->target_service = target_service;
	state->target_hostname = target_hostname;
	state->target_principal = target_principal;
	state->lp_ctx = lp_ctx;
	state->gensec_features = gensec_features;
	state->first = true;

	gensec_init();

	status = gensec_client_start(
		state, &state->gensec,
		lpcfg_gensec_settings(state, state->lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_client_start failed: %s\n",
			  nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return tevent_req_post(req, ev);
	}

	status = gensec_set_credentials(state->gensec, state->creds);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_set_credentials failed: %s\n",
			  nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return tevent_req_post(req, ev);
	}

	status = gensec_set_target_service(state->gensec,
					   state->target_service);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_set_target_service failed: %s\n",
			  nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return tevent_req_post(req, ev);
	}

	if (state->target_hostname != NULL) {
		status = gensec_set_target_hostname(state->gensec,
						    state->target_hostname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("gensec_set_target_hostname failed: %s\n",
				  nt_errstr(status));
			tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
			return tevent_req_post(req, ev);
		}
	}

	if (state->target_principal != NULL) {
		status = gensec_set_target_principal(state->gensec,
						     state->target_principal);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("gensec_set_target_principal failed: %s\n",
				  nt_errstr(status));
			tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
			return tevent_req_post(req, ev);
		}
	}

	if (tldap_has_tls_tstream(state->ctx)) {
		if (gensec_features & (GENSEC_FEATURE_SIGN|GENSEC_FEATURE_SEAL)) {
			DBG_WARNING("sign or seal not allowed over tls\n");
			tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
			return tevent_req_post(req, ev);
		}

		tls_cb = tldap_tls_channel_bindings(state->ctx);
	}

	if (tls_cb != NULL) {
		uint32_t initiator_addrtype = 0;
		const DATA_BLOB *initiator_address = NULL;
		uint32_t acceptor_addrtype = 0;
		const DATA_BLOB *acceptor_address = NULL;
		const DATA_BLOB *application_data = tls_cb;

		status = gensec_set_channel_bindings(state->gensec,
						     initiator_addrtype,
						     initiator_address,
						     acceptor_addrtype,
						     acceptor_address,
						     application_data);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("gensec_set_channel_bindings: %s\n",
				  nt_errstr(status));
			tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
			return tevent_req_post(req, ev);
		}
	}

	gensec_want_feature(state->gensec, state->gensec_features);

	status = gensec_start_mech_by_sasl_name(state->gensec, "GSS-SPNEGO");
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("gensec_start_mech_by_sasl_name(GSS-SPNEGO) failed: %s\n",
			nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return tevent_req_post(req, ev);
	}

	tldap_gensec_update_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tldap_gensec_update_next(struct tevent_req *req)
{
	struct tldap_gensec_bind_state *state = tevent_req_data(
		req, struct tldap_gensec_bind_state);
	struct tevent_req *subreq = NULL;

	subreq = gensec_update_send(state,
				    state->ev,
				    state->gensec,
				    state->gensec_input);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				tldap_gensec_update_done,
				req);
}

static void tldap_gensec_update_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_gensec_bind_state *state = tevent_req_data(
		req, struct tldap_gensec_bind_state);

	state->gensec_status = gensec_update_recv(subreq,
						  state,
						  &state->gensec_output);
	TALLOC_FREE(subreq);
	data_blob_free(&state->gensec_input);
	if (!NT_STATUS_IS_OK(state->gensec_status) &&
	    !NT_STATUS_EQUAL(state->gensec_status,
			     NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DBG_DEBUG("gensec_update failed: %s\n",
			  nt_errstr(state->gensec_status));
		tevent_req_ldap_error(req, TLDAP_INVALID_CREDENTIALS);
		return;
	}

	if (NT_STATUS_IS_OK(state->gensec_status) &&
	    (state->gensec_output.length == 0)) {

		if (state->first) {
			tevent_req_ldap_error(req, TLDAP_INVALID_CREDENTIALS);
		} else {
			tevent_req_done(req);
		}
		return;
	}

	state->first = false;

	subreq = tldap_sasl_bind_send(state,
				      state->ev,
				      state->ctx,
				      "",
				      "GSS-SPNEGO",
				      &state->gensec_output,
				      NULL,
				      0,
				      NULL,
				      0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tldap_gensec_bind_done, req);
}

static void tldap_gensec_bind_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_gensec_bind_state *state = tevent_req_data(
		req, struct tldap_gensec_bind_state);
	TLDAPRC rc;

	rc = tldap_sasl_bind_recv(subreq, state, &state->gensec_input);
	TALLOC_FREE(subreq);
	data_blob_free(&state->gensec_output);
	if (!TLDAP_RC_IS_SUCCESS(rc) &&
	    !TLDAP_RC_EQUAL(rc, TLDAP_SASL_BIND_IN_PROGRESS)) {
		tevent_req_ldap_error(req, rc);
		return;
	}

	if (TLDAP_RC_IS_SUCCESS(rc) && NT_STATUS_IS_OK(state->gensec_status)) {
		tevent_req_done(req);
		return;
	}

	tldap_gensec_update_next(req);
}

TLDAPRC tldap_gensec_bind_recv(struct tevent_req *req)
{
	struct tldap_gensec_bind_state *state = tevent_req_data(
		req, struct tldap_gensec_bind_state);
	struct tstream_context *plain, *sec;
	NTSTATUS status;
	TLDAPRC rc;

	if (tevent_req_is_ldap_error(req, &rc)) {
		return rc;
	}

	if ((state->gensec_features & GENSEC_FEATURE_SIGN) &&
	    !gensec_have_feature(state->gensec, GENSEC_FEATURE_SIGN)) {
		return TLDAP_OPERATIONS_ERROR;
	}
	if ((state->gensec_features & GENSEC_FEATURE_SEAL) &&
	    !gensec_have_feature(state->gensec, GENSEC_FEATURE_SEAL)) {
		return TLDAP_OPERATIONS_ERROR;
	}

	if (!gensec_have_feature(state->gensec, GENSEC_FEATURE_SIGN) &&
	    !gensec_have_feature(state->gensec, GENSEC_FEATURE_SEAL)) {
		return TLDAP_SUCCESS;
	}

	/*
	 * The gensec ctx needs to survive as long as the ldap context
	 * lives
	 */
	talloc_steal(state->ctx, state->gensec);

	plain = tldap_get_plain_tstream(state->ctx);

	status = gensec_create_tstream(state->ctx, state->gensec,
				       plain, &sec);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_create_tstream failed: %s\n",
			  nt_errstr(status));
		return TLDAP_OPERATIONS_ERROR;
	}

	tldap_set_gensec_tstream(state->ctx, &sec);

	return TLDAP_SUCCESS;
}

TLDAPRC tldap_gensec_bind(
	struct tldap_context *ctx, struct cli_credentials *creds,
	const char *target_service, const char *target_hostname,
	const char *target_principal, struct loadparm_context *lp_ctx,
	uint32_t gensec_features)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	TLDAPRC rc = TLDAP_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tldap_gensec_bind_send(frame, ev, ctx, creds, target_service,
				     target_hostname, target_principal, lp_ctx,
				     gensec_features);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		rc = TLDAP_OPERATIONS_ERROR;
		goto fail;
	}
	rc = tldap_gensec_bind_recv(req);
 fail:
	TALLOC_FREE(frame);
	return rc;
}
