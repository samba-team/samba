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

#include "tldap_gensec_bind.h"
#include "tldap_util.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/samba_util.h"
#include "lib/util/debug.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h" /* TODO: remove this */
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
	DATA_BLOB gensec_output;
};

static void tldap_gensec_bind_got_mechs(struct tevent_req *subreq);
static void tldap_gensec_update_done(struct tldap_gensec_bind_state *state,
				struct tevent_req *subreq);
static void tldap_gensec_bind_done(struct tevent_req *subreq);

static struct tevent_req *tldap_gensec_bind_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct tldap_context *ctx, struct cli_credentials *creds,
	const char *target_service, const char *target_hostname,
	const char *target_principal, struct loadparm_context *lp_ctx,
	uint32_t gensec_features)
{
	struct tevent_req *req, *subreq;
	struct tldap_gensec_bind_state *state;

	const char *attrs[] = { "supportedSASLMechanisms" };

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

	subreq = tldap_search_all_send(
		state, state->ev, state->ctx, "", TLDAP_SCOPE_BASE,
		"(objectclass=*)", attrs, ARRAY_SIZE(attrs),
		false, NULL, 0, NULL, 0, 0, 1 /* sizelimit */, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tldap_gensec_bind_got_mechs, req);
	return req;
}

static void tldap_gensec_bind_got_mechs(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tldap_gensec_bind_state *state = tevent_req_data(
		req, struct tldap_gensec_bind_state);
	struct tldap_message **msgs, *msg, *result;
	struct tldap_attribute *attribs, *attrib;
	int num_attribs;
	size_t num_msgs;
	TLDAPRC rc;
	int i;
	bool ok;
	const char **sasl_mechs;
	NTSTATUS status;

	rc = tldap_search_all_recv(subreq, state, &msgs, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_ldap_error(req, rc)) {
		return;
	}

	/*
	 * TODO: Inspect "Result"
	 */

	num_msgs = talloc_array_length(msgs);
	if (num_msgs != 1) {
		DBG_DEBUG("num_msgs = %zu\n", num_msgs);
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return;
	}
	msg = msgs[0];

	ok = tldap_entry_attributes(msg, &attribs, &num_attribs);
	if (!ok) {
		DBG_DEBUG("tldap_entry_attributes failed\n");
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return;
	}

	if (num_attribs != 1) {
		DBG_DEBUG("num_attribs = %d\n", num_attribs);
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return;
	}
	attrib = &attribs[0];

	sasl_mechs = talloc_array(state, const char *, attrib->num_values+1);
	if (tevent_req_nomem(sasl_mechs, req)) {
		return;
	}

	for (i=0; i<attrib->num_values; i++) {
		DATA_BLOB *v = &attrib->values[i];
		size_t len;

		ok = convert_string_talloc(sasl_mechs, CH_UTF8, CH_UNIX,
					   v->data, v->length,
					   &sasl_mechs[i], &len);
		if (!ok) {
			DBG_DEBUG("convert_string_talloc failed\n");
			tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
			return;
		}
	}
	sasl_mechs[attrib->num_values] = NULL;

	gensec_init();

	status = gensec_client_start(
		state, &state->gensec,
		lpcfg_gensec_settings(state, state->lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_client_start failed: %s\n",
			  nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return;
	}

	status = gensec_set_credentials(state->gensec, state->creds);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_set_credentials failed: %s\n",
			  nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return;
	}

	status = gensec_set_target_service(state->gensec,
					   state->target_service);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_set_target_service failed: %s\n",
			  nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return;
	}

	if (state->target_hostname != NULL) {
		status = gensec_set_target_hostname(state->gensec,
						    state->target_hostname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("gensec_set_target_hostname failed: %s\n",
				  nt_errstr(status));
			tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
			return;
		}
	}

	if (state->target_principal != NULL) {
		status = gensec_set_target_principal(state->gensec,
						     state->target_principal);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("gensec_set_target_principal failed: %s\n",
				  nt_errstr(status));
			tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
			return;
		}
	}

	gensec_want_feature(state->gensec, state->gensec_features);

	status = gensec_start_mech_by_sasl_list(state->gensec, sasl_mechs);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_start_mech_by_sasl_list failed: %s\n",
			  nt_errstr(status));
		tevent_req_ldap_error(req, TLDAP_OPERATIONS_ERROR);
		return;
	}

	state->gensec_status = gensec_update(state->gensec, state,
						data_blob_null,
						&state->gensec_output);
	tldap_gensec_update_done(state, req);
}

static void tldap_gensec_update_done(struct tldap_gensec_bind_state *state,
					struct tevent_req *req)
{
	struct tevent_req *subreq;

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

	subreq = tldap_sasl_bind_send(
		state, state->ev, state->ctx, "",
		state->gensec->ops->sasl_name, &state->gensec_output,
		NULL, 0, NULL, 0);
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
	DATA_BLOB input;
	TLDAPRC rc;

	rc = tldap_sasl_bind_recv(subreq, state, &input);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc) &&
	    !TLDAP_RC_EQUAL(rc, TLDAP_SASL_BIND_IN_PROGRESS)) {
		tevent_req_ldap_error(req, rc);
		return;
	}

	if (TLDAP_RC_IS_SUCCESS(rc) && NT_STATUS_IS_OK(state->gensec_status)) {
		tevent_req_done(req);
		return;
	}

	state->gensec_status = gensec_update(state->gensec, state,
						input,
						&state->gensec_output);
	tldap_gensec_update_done(state, req);
}

static TLDAPRC tldap_gensec_bind_recv(struct tevent_req *req)
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

	plain = tldap_get_tstream(state->ctx);

	status = gensec_create_tstream(state->ctx, state->gensec,
				       plain, &sec);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("gensec_create_tstream failed: %s\n",
			  nt_errstr(status));
		return TLDAP_OPERATIONS_ERROR;
	}

	tldap_set_tstream(state->ctx, sec);

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
