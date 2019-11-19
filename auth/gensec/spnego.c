/* 
   Unix SMB/CIFS implementation.

   RFC2478 Compliant SPNEGO implementation

   Copyright (C) Jim McDonough <jmcd@us.ibm.com>      2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Stefan Metzmacher <metze@samba.org>  2004-2008

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
#include "../libcli/auth/spnego.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "param/param.h"
#include "lib/util/asn1.h"
#include "lib/util/base64.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

#undef strcasecmp

_PUBLIC_ NTSTATUS gensec_spnego_init(TALLOC_CTX *ctx);

enum spnego_state_position {
	SPNEGO_SERVER_START,
	SPNEGO_CLIENT_START,
	SPNEGO_SERVER_TARG,
	SPNEGO_CLIENT_TARG,
	SPNEGO_FALLBACK,
	SPNEGO_DONE
};

struct spnego_state;
struct spnego_neg_ops;
struct spnego_neg_state;

struct spnego_neg_state {
	const struct spnego_neg_ops *ops;
	const struct gensec_security_ops_wrapper *all_sec;
	size_t all_idx;
	const char * const *mech_types;
	size_t mech_idx;
};

struct spnego_neg_ops {
	const char *name;
	/*
	 * The start hook does the initial processing on the incoming paket and
	 * may starts the first possible subcontext. It indicates that
	 * gensec_update() is required on the subcontext by returning
	 * NT_STATUS_MORE_PROCESSING_REQUIRED and return something useful in
	 * 'in_next'. Note that 'in_mem_ctx' is just passed as a hint, the
	 * caller should treat 'in_next' as const and don't attempt to free the
	 * content.  NT_STATUS_OK indicates the finish hook should be invoked
	 * directly within the need of gensec_update() on the subcontext.
	 * Every other error indicates an error that's returned to the caller.
	 */
	NTSTATUS (*start_fn)(struct gensec_security *gensec_security,
			     struct spnego_state *spnego_state,
			     struct spnego_neg_state *n,
			     struct spnego_data *spnego_in,
			     TALLOC_CTX *in_mem_ctx,
			     DATA_BLOB *in_next);
	/*
	 * The step hook processes the result of a failed gensec_update() and
	 * can decide to ignore a failure and continue the negotiation by
	 * setting up the next possible subcontext. It indicates that
	 * gensec_update() is required on the subcontext by returning
	 * NT_STATUS_MORE_PROCESSING_REQUIRED and return something useful in
	 * 'in_next'. Note that 'in_mem_ctx' is just passed as a hint, the
	 * caller should treat 'in_next' as const and don't attempt to free the
	 * content.  NT_STATUS_OK indicates the finish hook should be invoked
	 * directly within the need of gensec_update() on the subcontext.
	 * Every other error indicates an error that's returned to the caller.
	 */
	NTSTATUS (*step_fn)(struct gensec_security *gensec_security,
			    struct spnego_state *spnego_state,
			    struct spnego_neg_state *n,
			    struct spnego_data *spnego_in,
			    NTSTATUS last_status,
			    TALLOC_CTX *in_mem_ctx,
			    DATA_BLOB *in_next);
	/*
	 * The finish hook processes the result of a successful gensec_update()
	 * (NT_STATUS_OK or NT_STATUS_MORE_PROCESSING_REQUIRED). It forms the
	 * response pdu that will be returned from the toplevel gensec_update()
	 * together with NT_STATUS_OK or NT_STATUS_MORE_PROCESSING_REQUIRED. It
	 * may also alter the state machine to prepare receiving the next pdu
	 * from the peer.
	 */
	NTSTATUS (*finish_fn)(struct gensec_security *gensec_security,
			      struct spnego_state *spnego_state,
			      struct spnego_neg_state *n,
			      struct spnego_data *spnego_in,
			      NTSTATUS sub_status,
			      const DATA_BLOB sub_out,
			      TALLOC_CTX *out_mem_ctx,
			      DATA_BLOB *out);
};

struct spnego_state {
	enum spnego_message_type expected_packet;
	enum spnego_state_position state_position;
	struct gensec_security *sub_sec_security;
	bool sub_sec_ready;

	const char *neg_oid;

	DATA_BLOB mech_types;
	size_t num_targs;
	bool downgraded;
	bool mic_requested;
	bool needs_mic_sign;
	bool needs_mic_check;
	bool may_skip_mic_check;
	bool done_mic_check;

	bool simulate_w2k;
	bool no_optimistic;

	/*
	 * The following is used to implement
	 * the update token fragmentation
	 */
	size_t in_needed;
	DATA_BLOB in_frag;
	size_t out_max_length;
	DATA_BLOB out_frag;
	NTSTATUS out_status;
};

static struct spnego_neg_state *gensec_spnego_neg_state(TALLOC_CTX *mem_ctx,
		const struct spnego_neg_ops *ops)
{
	struct spnego_neg_state *n = NULL;

	n = talloc_zero(mem_ctx, struct spnego_neg_state);
	if (n == NULL) {
		return NULL;
	}
	n->ops = ops;

	return n;
}

static void gensec_spnego_reset_sub_sec(struct spnego_state *spnego_state)
{
	spnego_state->sub_sec_ready = false;
	TALLOC_FREE(spnego_state->sub_sec_security);
}

static NTSTATUS gensec_spnego_client_start(struct gensec_security *gensec_security)
{
	struct spnego_state *spnego_state;

	spnego_state = talloc_zero(gensec_security, struct spnego_state);
	if (!spnego_state) {
		return NT_STATUS_NO_MEMORY;
	}

	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
	spnego_state->state_position = SPNEGO_CLIENT_START;
	spnego_state->sub_sec_security = NULL;
	spnego_state->sub_sec_ready = false;
	spnego_state->mech_types = data_blob_null;
	spnego_state->out_max_length = gensec_max_update_size(gensec_security);
	spnego_state->out_status = NT_STATUS_MORE_PROCESSING_REQUIRED;

	spnego_state->simulate_w2k = gensec_setting_bool(gensec_security->settings,
						"spnego", "simulate_w2k", false);
	spnego_state->no_optimistic = gensec_setting_bool(gensec_security->settings,
							  "spnego",
							  "client_no_optimistic",
							  false);

	gensec_security->private_data = spnego_state;
	return NT_STATUS_OK;
}

static NTSTATUS gensec_spnego_server_start(struct gensec_security *gensec_security)
{
	struct spnego_state *spnego_state;

	spnego_state = talloc_zero(gensec_security, struct spnego_state);
	if (!spnego_state) {
		return NT_STATUS_NO_MEMORY;
	}

	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
	spnego_state->state_position = SPNEGO_SERVER_START;
	spnego_state->sub_sec_security = NULL;
	spnego_state->sub_sec_ready = false;
	spnego_state->mech_types = data_blob_null;
	spnego_state->out_max_length = gensec_max_update_size(gensec_security);
	spnego_state->out_status = NT_STATUS_MORE_PROCESSING_REQUIRED;

	spnego_state->simulate_w2k = gensec_setting_bool(gensec_security->settings,
						"spnego", "simulate_w2k", false);

	gensec_security->private_data = spnego_state;
	return NT_STATUS_OK;
}

/** Fallback to another GENSEC mechanism, based on magic strings 
 *
 * This is the 'fallback' case, where we don't get SPNEGO, and have to
 * try all the other options (and hope they all have a magic string
 * they check)
*/

static NTSTATUS gensec_spnego_server_try_fallback(struct gensec_security *gensec_security, 
						  struct spnego_state *spnego_state,
						  TALLOC_CTX *mem_ctx,
						  const DATA_BLOB in)
{
	int i,j;
	const struct gensec_security_ops **all_ops;

	all_ops = gensec_security_mechs(gensec_security, mem_ctx);

	for (i=0; all_ops && all_ops[i]; i++) {
		bool is_spnego;
		NTSTATUS nt_status;

		if (gensec_security != NULL &&
		    !gensec_security_ops_enabled(all_ops[i], gensec_security))
		{
			continue;
		}

		if (!all_ops[i]->oid) {
			continue;
		}

		is_spnego = false;
		for (j=0; all_ops[i]->oid[j]; j++) {
			if (strcasecmp(GENSEC_OID_SPNEGO,all_ops[i]->oid[j]) == 0) {
				is_spnego = true;
			}
		}
		if (is_spnego) {
			continue;
		}

		if (!all_ops[i]->magic) {
			continue;
		}

		nt_status = all_ops[i]->magic(gensec_security, &in);
		if (!NT_STATUS_IS_OK(nt_status)) {
			continue;
		}

		spnego_state->state_position = SPNEGO_FALLBACK;

		nt_status = gensec_subcontext_start(spnego_state, 
						    gensec_security, 
						    &spnego_state->sub_sec_security);

		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		/* select the sub context */
		nt_status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						     all_ops[i]);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		return NT_STATUS_OK;
	}
	DEBUG(1, ("Failed to parse SPNEGO request\n"));
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_spnego_create_negTokenInit_start(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	n->mech_idx = 0;
	n->mech_types = gensec_security_oids(gensec_security, n,
					     GENSEC_OID_SPNEGO);
	if (n->mech_types == NULL) {
		DBG_WARNING("gensec_security_oids() failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	n->all_idx = 0;
	n->all_sec = gensec_security_by_oid_list(gensec_security,
						 n, n->mech_types,
						 GENSEC_OID_SPNEGO);
	if (n->all_sec == NULL) {
		DBG_WARNING("gensec_security_by_oid_list() failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	return n->ops->step_fn(gensec_security, spnego_state, n,
			       spnego_in, NT_STATUS_OK, in_mem_ctx, in_next);
}

static NTSTATUS gensec_spnego_create_negTokenInit_step(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS last_status,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	if (!NT_STATUS_IS_OK(last_status)) {
		const struct gensec_security_ops_wrapper *cur_sec =
			&n->all_sec[n->all_idx];
		const struct gensec_security_ops_wrapper *next_sec = NULL;
		const char *next = NULL;
		const char *principal = NULL;
		int dbg_level = DBGLVL_WARNING;
		NTSTATUS status = last_status;

		if (cur_sec[1].op != NULL) {
			next_sec = &cur_sec[1];
		}

		if (next_sec != NULL) {
			next = next_sec->op->name;
			dbg_level = DBGLVL_NOTICE;
		}

		if (gensec_security->target.principal != NULL) {
			principal = gensec_security->target.principal;
		} else if (gensec_security->target.service != NULL &&
			   gensec_security->target.hostname != NULL)
		{
			principal = talloc_asprintf(spnego_state->sub_sec_security,
						    "%s/%s",
						    gensec_security->target.service,
						    gensec_security->target.hostname);
		} else {
			principal = gensec_security->target.hostname;
		}

		DBG_PREFIX(dbg_level, (
			   "%s: creating NEG_TOKEN_INIT for %s failed "
			   "(next[%s]): %s\n", cur_sec->op->name,
			   principal, next, nt_errstr(status)));

		if (next == NULL) {
			/*
			 * A hard error without a possible fallback.
			 */
			return status;
		}

		/*
		 * Pretend we never started it
		 */
		gensec_spnego_reset_sub_sec(spnego_state);

		/*
		 * And try the next one...
		 */
		n->all_idx += 1;
	}

	for (; n->all_sec[n->all_idx].op != NULL; n->all_idx++) {
		const struct gensec_security_ops_wrapper *cur_sec =
			&n->all_sec[n->all_idx];
		NTSTATUS status;

		status = gensec_subcontext_start(spnego_state,
						 gensec_security,
						 &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* select the sub context */
		status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						  cur_sec->op);
		if (!NT_STATUS_IS_OK(status)) {
			gensec_spnego_reset_sub_sec(spnego_state);
			continue;
		}

		/* In the client, try and produce the first (optimistic) packet */
		if (spnego_state->state_position == SPNEGO_CLIENT_START) {
			*in_next = data_blob_null;
			return NT_STATUS_MORE_PROCESSING_REQUIRED;
		}

		*in_next = data_blob_null;
		return NT_STATUS_OK;
	}

	DBG_WARNING("Failed to setup SPNEGO negTokenInit request\n");
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_spnego_create_negTokenInit_finish(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS sub_status,
					const DATA_BLOB sub_out,
					TALLOC_CTX *out_mem_ctx,
					DATA_BLOB *out)
{
	const struct gensec_security_ops_wrapper *cur_sec =
			&n->all_sec[n->all_idx];
	struct spnego_data spnego_out;
	bool ok;

	spnego_out.type = SPNEGO_NEG_TOKEN_INIT;

	n->mech_types = gensec_security_oids_from_ops_wrapped(n, cur_sec);
	if (n->mech_types == NULL) {
		DBG_WARNING("gensec_security_oids_from_ops_wrapped() failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	ok = spnego_write_mech_types(spnego_state,
				     n->mech_types,
				     &spnego_state->mech_types);
	if (!ok) {
		DBG_ERR("Failed to write mechTypes\n");
		return NT_STATUS_NO_MEMORY;
	}

	/* List the remaining mechs as options */
	spnego_out.negTokenInit.mechTypes = n->mech_types;
	spnego_out.negTokenInit.reqFlags = data_blob_null;
	spnego_out.negTokenInit.reqFlagsPadding = 0;

	if (spnego_state->state_position == SPNEGO_SERVER_START) {
		spnego_out.negTokenInit.mechListMIC
			= data_blob_string_const(ADS_IGNORE_PRINCIPAL);
	} else {
		spnego_out.negTokenInit.mechListMIC = data_blob_null;
	}

	spnego_out.negTokenInit.mechToken = sub_out;

	if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
		DBG_ERR("Failed to write NEG_TOKEN_INIT\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * Note that 'cur_sec' is temporary memory, but
	 * cur_sec->oid points to a const string in the
	 * backends gensec_security_ops structure.
	 */
	spnego_state->neg_oid = cur_sec->oid;

	/* set next state */
	if (spnego_state->state_position == SPNEGO_SERVER_START) {
		spnego_state->state_position = SPNEGO_SERVER_START;
		spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
	} else {
		spnego_state->state_position = SPNEGO_CLIENT_TARG;
		spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
	}

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static const struct spnego_neg_ops gensec_spnego_create_negTokenInit_ops = {
	.name      = "create_negTokenInit",
	.start_fn  = gensec_spnego_create_negTokenInit_start,
	.step_fn   = gensec_spnego_create_negTokenInit_step,
	.finish_fn = gensec_spnego_create_negTokenInit_finish,
};

static NTSTATUS gensec_spnego_client_negTokenInit_start(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	const char *tp = NULL;

	/* The server offers a list of mechanisms */

	tp = spnego_in->negTokenInit.targetPrincipal;
	if (tp != NULL && strcmp(tp, ADS_IGNORE_PRINCIPAL) != 0) {
		DBG_INFO("Server claims it's principal name is %s\n", tp);
		if (lpcfg_client_use_spnego_principal(gensec_security->settings->lp_ctx)) {
			gensec_set_target_principal(gensec_security, tp);
		}
	}

	n->mech_idx = 0;

	/* Do not use server mech list as it isn't protected. Instead, get all
	 * supported mechs (excluding SPNEGO). */
	n->mech_types = gensec_security_oids(gensec_security, n,
					     GENSEC_OID_SPNEGO);
	if (n->mech_types == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	n->all_idx = 0;
	n->all_sec = gensec_security_by_oid_list(gensec_security,
						 n, n->mech_types,
						 GENSEC_OID_SPNEGO);
	if (n->all_sec == NULL) {
		DBG_WARNING("gensec_security_by_oid_list() failed\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	return n->ops->step_fn(gensec_security, spnego_state, n,
			       spnego_in, NT_STATUS_OK, in_mem_ctx, in_next);
}

static NTSTATUS gensec_spnego_client_negTokenInit_step(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS last_status,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	if (!NT_STATUS_IS_OK(last_status)) {
		const struct gensec_security_ops_wrapper *cur_sec =
			&n->all_sec[n->all_idx];
		const struct gensec_security_ops_wrapper *next_sec = NULL;
		const char *next = NULL;
		const char *principal = NULL;
		int dbg_level = DBGLVL_WARNING;
		bool allow_fallback = false;
		NTSTATUS status = last_status;

		if (cur_sec[1].op != NULL) {
			next_sec = &cur_sec[1];
		}

		/*
		 * it is likely that a NULL input token will
		 * not be liked by most server mechs, but if
		 * we are in the client, we want the first
		 * update packet to be able to abort the use
		 * of this mech
		 */
		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_ACCOUNT_NAME) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_COMPUTER_NAME) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_DOMAIN) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NO_LOGON_SERVERS) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_TIME_DIFFERENCE_AT_DC) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO))
		{
			allow_fallback = true;
		}

		if (allow_fallback && next_sec != NULL) {
			next = next_sec->op->name;
			dbg_level = DBGLVL_NOTICE;
		}

		if (gensec_security->target.principal != NULL) {
			principal = gensec_security->target.principal;
		} else if (gensec_security->target.service != NULL &&
			   gensec_security->target.hostname != NULL)
		{
			principal = talloc_asprintf(spnego_state->sub_sec_security,
						    "%s/%s",
						    gensec_security->target.service,
						    gensec_security->target.hostname);
		} else {
			principal = gensec_security->target.hostname;
		}

		DBG_PREFIX(dbg_level, (
			   "%s: creating NEG_TOKEN_INIT for %s failed "
			   "(next[%s]): %s\n", cur_sec->op->name,
			   principal, next, nt_errstr(status)));

		if (next == NULL) {
			/*
			 * A hard error without a possible fallback.
			 */
			return status;
		}

		/*
		 * Pretend we never started it.
		 */
		gensec_spnego_reset_sub_sec(spnego_state);

		/*
		 * And try the next one...
		 */
		n->all_idx += 1;
	}

	for (; n->all_sec[n->all_idx].op != NULL; n->all_idx++) {
		const struct gensec_security_ops_wrapper *cur_sec =
			&n->all_sec[n->all_idx];
		NTSTATUS status;

		status = gensec_subcontext_start(spnego_state,
						 gensec_security,
						 &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* select the sub context */
		status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						  cur_sec->op);
		if (!NT_STATUS_IS_OK(status)) {
			gensec_spnego_reset_sub_sec(spnego_state);
			continue;
		}

		/*
		 * Note that 'cur_sec' is temporary memory, but
		 * cur_sec->oid points to a const string in the
		 * backends gensec_security_ops structure.
		 */
		spnego_state->neg_oid = cur_sec->oid;

		/*
		 * As client we don't use an optimistic token from the server.
		 * But try to produce one for the server.
		 */
		*in_next = data_blob_null;
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	DBG_WARNING("Could not find a suitable mechtype in NEG_TOKEN_INIT\n");
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_spnego_client_negTokenInit_finish(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS sub_status,
					const DATA_BLOB sub_out,
					TALLOC_CTX *out_mem_ctx,
					DATA_BLOB *out)
{
	struct spnego_data spnego_out;
	const char * const *mech_types = NULL;
	bool ok;

	if (n->mech_types == NULL) {
		DBG_WARNING("No mech_types list\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (mech_types = n->mech_types; *mech_types != NULL; mech_types++) {
		int cmp = strcmp(*mech_types, spnego_state->neg_oid);

		if (cmp == 0) {
			break;
		}
	}

	if (*mech_types == NULL) {
		DBG_ERR("Can't find selected sub mechanism in mech_types\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* compose reply */
	spnego_out.type = SPNEGO_NEG_TOKEN_INIT;
	spnego_out.negTokenInit.mechTypes = mech_types;
	spnego_out.negTokenInit.reqFlags = data_blob_null;
	spnego_out.negTokenInit.reqFlagsPadding = 0;
	spnego_out.negTokenInit.mechListMIC = data_blob_null;
	spnego_out.negTokenInit.mechToken = sub_out;

	if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
		DBG_ERR("Failed to write SPNEGO reply to NEG_TOKEN_INIT\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	ok = spnego_write_mech_types(spnego_state,
				     mech_types,
				     &spnego_state->mech_types);
	if (!ok) {
		DBG_ERR("failed to write mechTypes\n");
		return NT_STATUS_NO_MEMORY;
	}

	/* set next state */
	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
	spnego_state->state_position = SPNEGO_CLIENT_TARG;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static const struct spnego_neg_ops gensec_spnego_client_negTokenInit_ops = {
	.name      = "client_negTokenInit",
	.start_fn  = gensec_spnego_client_negTokenInit_start,
	.step_fn   = gensec_spnego_client_negTokenInit_step,
	.finish_fn = gensec_spnego_client_negTokenInit_finish,
};

static NTSTATUS gensec_spnego_client_negTokenTarg_start(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	struct spnego_negTokenTarg *ta = &spnego_in->negTokenTarg;
	NTSTATUS status;

	spnego_state->num_targs++;

	if (ta->negResult == SPNEGO_REJECT) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if (ta->negResult == SPNEGO_REQUEST_MIC) {
		spnego_state->mic_requested = true;
	}

	if (ta->mechListMIC.length > 0) {
		DATA_BLOB *m = &ta->mechListMIC;
		const DATA_BLOB *r = &ta->responseToken;

		/*
		 * Windows 2000 has a bug, it repeats the
		 * responseToken in the mechListMIC field.
		 */
		if (m->length == r->length) {
			int cmp;

			cmp = memcmp(m->data, r->data, m->length);
			if (cmp == 0) {
				data_blob_free(m);
			}
		}
	}

	/* Server didn't like our choice of mech, and chose something else */
	if (((ta->negResult == SPNEGO_ACCEPT_INCOMPLETE) ||
	     (ta->negResult == SPNEGO_REQUEST_MIC)) &&
	    ta->supportedMech != NULL &&
	    strcmp(ta->supportedMech, spnego_state->neg_oid) != 0)
	{
		const char *client_mech = NULL;
		const char *client_oid = NULL;
		const char *server_mech = NULL;
		const char *server_oid = NULL;

		client_mech = gensec_get_name_by_oid(gensec_security,
						     spnego_state->neg_oid);
		client_oid = spnego_state->neg_oid;
		server_mech = gensec_get_name_by_oid(gensec_security,
						     ta->supportedMech);
		server_oid = ta->supportedMech;

		DBG_NOTICE("client preferred mech (%s[%s]) not accepted, "
			   "server wants: %s[%s]\n",
			   client_mech, client_oid, server_mech, server_oid);

		spnego_state->downgraded = true;
		gensec_spnego_reset_sub_sec(spnego_state);

		status = gensec_subcontext_start(spnego_state,
						 gensec_security,
						 &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* select the sub context */
		status = gensec_start_mech_by_oid(spnego_state->sub_sec_security,
						  ta->supportedMech);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		spnego_state->neg_oid = talloc_strdup(spnego_state,
					ta->supportedMech);
		if (spnego_state->neg_oid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (ta->mechListMIC.length > 0) {
		if (spnego_state->sub_sec_ready) {
			spnego_state->needs_mic_check = true;
		}
	}

	if (spnego_state->needs_mic_check) {
		if (ta->responseToken.length != 0) {
			DBG_WARNING("non empty response token not expected\n");
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (ta->mechListMIC.length == 0
		    && spnego_state->may_skip_mic_check) {
			/*
			 * In this case we don't require
			 * a mechListMIC from the server.
			 *
			 * This works around bugs in the Azure
			 * and Apple spnego implementations.
			 *
			 * See
			 * https://bugzilla.samba.org/show_bug.cgi?id=11994
			 */
			spnego_state->needs_mic_check = false;
			return NT_STATUS_OK;
		}

		status = gensec_check_packet(spnego_state->sub_sec_security,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     &ta->mechListMIC);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("failed to verify mechListMIC: %s\n",
				    nt_errstr(status));
			return status;
		}
		spnego_state->needs_mic_check = false;
		spnego_state->done_mic_check = true;
		return NT_STATUS_OK;
	}

	if (!spnego_state->sub_sec_ready) {
		*in_next = ta->responseToken;
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_spnego_client_negTokenTarg_step(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS last_status,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	if (GENSEC_UPDATE_IS_NTERROR(last_status)) {
		DBG_WARNING("SPNEGO(%s) login failed: %s\n",
			    spnego_state->sub_sec_security->ops->name,
			    nt_errstr(last_status));
		return last_status;
	}

	/*
	 * This should never be reached!
	 * The step function is only called on errors!
	 */
	smb_panic(__location__);
	return NT_STATUS_INTERNAL_ERROR;
}

static NTSTATUS gensec_spnego_client_negTokenTarg_finish(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS sub_status,
					const DATA_BLOB sub_out,
					TALLOC_CTX *out_mem_ctx,
					DATA_BLOB *out)
{
	const struct spnego_negTokenTarg *ta =
		&spnego_in->negTokenTarg;
	DATA_BLOB mech_list_mic = data_blob_null;
	NTSTATUS status;
	struct spnego_data spnego_out;

	if (!spnego_state->sub_sec_ready) {
		/*
		 * We're not yet ready to deal with signatures.
		 */
		goto client_response;
	}

	if (spnego_state->done_mic_check) {
		/*
		 * We already checked the mic,
		 * either the in last round here
		 * in gensec_spnego_client_negTokenTarg_finish()
		 * or during this round in
		 * gensec_spnego_client_negTokenTarg_start().
		 *
		 * Both cases we're sure we don't have to
		 * call gensec_sign_packet().
		 */
		goto client_response;
	}

	if (spnego_state->may_skip_mic_check) {
		/*
		 * This can only be set during
		 * the last round here in
		 * gensec_spnego_client_negTokenTarg_finish()
		 * below. And during this round
		 * we already passed the checks in
		 * gensec_spnego_client_negTokenTarg_start().
		 *
		 * So we need to skip to deal with
		 * any signatures now.
		 */
		goto client_response;
	}

	if (!spnego_state->done_mic_check) {
		bool have_sign = true;
		bool new_spnego = false;

		have_sign = gensec_have_feature(spnego_state->sub_sec_security,
						GENSEC_FEATURE_SIGN);
		if (spnego_state->simulate_w2k) {
			have_sign = false;
		}
		new_spnego = gensec_have_feature(spnego_state->sub_sec_security,
						 GENSEC_FEATURE_NEW_SPNEGO);

		switch (ta->negResult) {
		case SPNEGO_ACCEPT_COMPLETED:
		case SPNEGO_NONE_RESULT:
			if (spnego_state->num_targs == 1) {
				/*
				 * the first exchange doesn't require
				 * verification
				 */
				new_spnego = false;
			}

			break;

		case SPNEGO_ACCEPT_INCOMPLETE:
			if (ta->mechListMIC.length > 0) {
				new_spnego = true;
				break;
			}

			if (spnego_state->downgraded) {
				/*
				 * A downgrade should be protected if
				 * supported
				 */
				break;
			}

			/*
			 * The caller may just asked for
			 * GENSEC_FEATURE_SESSION_KEY, this
			 * is only reflected in the want_features.
			 *
			 * As it will imply
			 * gensec_have_features(GENSEC_FEATURE_SIGN)
			 * to return true.
			 */
			if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
				break;
			}
			if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
				break;
			}
			/*
			 * Here we're sure our preferred mech was
			 * selected by the server and our caller doesn't
			 * need GENSEC_FEATURE_SIGN nor
			 * GENSEC_FEATURE_SEAL support.
			 *
			 * In this case we don't require
			 * a mechListMIC from the server.
			 *
			 * This works around bugs in the Azure
			 * and Apple spnego implementations.
			 *
			 * See
			 * https://bugzilla.samba.org/show_bug.cgi?id=11994
			 */
			spnego_state->may_skip_mic_check = true;
			break;

		case SPNEGO_REQUEST_MIC:
			if (ta->mechListMIC.length > 0) {
				new_spnego = true;
			}
			break;
		default:
			break;
		}

		if (spnego_state->mic_requested) {
			if (have_sign) {
				new_spnego = true;
			}
		}

		if (have_sign && new_spnego) {
			spnego_state->needs_mic_check = true;
			spnego_state->needs_mic_sign = true;
		}
	}

	if (ta->mechListMIC.length > 0) {
		status = gensec_check_packet(spnego_state->sub_sec_security,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     &ta->mechListMIC);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("failed to verify mechListMIC: %s\n",
				    nt_errstr(status));
			return status;
		}
		spnego_state->needs_mic_check = false;
		spnego_state->done_mic_check = true;
	}

	if (spnego_state->needs_mic_sign) {
		status = gensec_sign_packet(spnego_state->sub_sec_security,
					    n,
					    spnego_state->mech_types.data,
					    spnego_state->mech_types.length,
					    spnego_state->mech_types.data,
					    spnego_state->mech_types.length,
					    &mech_list_mic);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("failed to sign mechListMIC: %s\n",
				    nt_errstr(status));
			return status;
		}
		spnego_state->needs_mic_sign = false;
	}

 client_response:
	if (sub_out.length == 0 && mech_list_mic.length == 0) {
		*out = data_blob_null;

		if (!spnego_state->sub_sec_ready) {
			/* somethings wrong here... */
			DBG_ERR("gensec_update not ready without output\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (ta->negResult != SPNEGO_ACCEPT_COMPLETED) {
			/* unless of course it did not accept */
			DBG_WARNING("gensec_update ok but not accepted\n");
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!spnego_state->needs_mic_check) {
			spnego_state->state_position = SPNEGO_DONE;
			return NT_STATUS_OK;
		}
	}

	/* compose reply */
	spnego_out.type = SPNEGO_NEG_TOKEN_TARG;
	spnego_out.negTokenTarg.negResult = SPNEGO_NONE_RESULT;
	spnego_out.negTokenTarg.supportedMech = NULL;
	spnego_out.negTokenTarg.responseToken = sub_out;
	spnego_out.negTokenTarg.mechListMIC = mech_list_mic;

	if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
		DBG_WARNING("Failed to write NEG_TOKEN_TARG\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	spnego_state->num_targs++;

	/* set next state */
	spnego_state->state_position = SPNEGO_CLIENT_TARG;
	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static const struct spnego_neg_ops gensec_spnego_client_negTokenTarg_ops = {
	.name      = "client_negTokenTarg",
	.start_fn  = gensec_spnego_client_negTokenTarg_start,
	.step_fn   = gensec_spnego_client_negTokenTarg_step,
	.finish_fn = gensec_spnego_client_negTokenTarg_finish,
};

/** create a server negTokenTarg 
 *
 * This is the case, where the client is the first one who sends data
*/

static NTSTATUS gensec_spnego_server_response(struct spnego_state *spnego_state,
					      TALLOC_CTX *out_mem_ctx,
					      NTSTATUS nt_status,
					      const DATA_BLOB unwrapped_out,
					      DATA_BLOB mech_list_mic,
					      DATA_BLOB *out)
{
	struct spnego_data spnego_out;

	/* compose reply */
	spnego_out.type = SPNEGO_NEG_TOKEN_TARG;
	spnego_out.negTokenTarg.responseToken = unwrapped_out;
	spnego_out.negTokenTarg.mechListMIC = mech_list_mic;
	spnego_out.negTokenTarg.supportedMech = NULL;

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {	
		spnego_out.negTokenTarg.supportedMech = spnego_state->neg_oid;
		if (spnego_state->mic_requested) {
			spnego_out.negTokenTarg.negResult = SPNEGO_REQUEST_MIC;
			spnego_state->mic_requested = false;
		} else {
			spnego_out.negTokenTarg.negResult = SPNEGO_ACCEPT_INCOMPLETE;
		}
		spnego_state->state_position = SPNEGO_SERVER_TARG;
	} else if (NT_STATUS_IS_OK(nt_status)) {
		if (unwrapped_out.data) {
			spnego_out.negTokenTarg.supportedMech = spnego_state->neg_oid;
		}
		spnego_out.negTokenTarg.negResult = SPNEGO_ACCEPT_COMPLETED;
		spnego_state->state_position = SPNEGO_DONE;
	}

	if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
		DEBUG(1, ("Failed to write SPNEGO reply to NEG_TOKEN_TARG\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
	spnego_state->num_targs++;

	return nt_status;
}

static NTSTATUS gensec_spnego_server_negTokenInit_start(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	bool ok;

	n->mech_idx = 0;
	n->mech_types = spnego_in->negTokenInit.mechTypes;
	if (n->mech_types == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	n->all_idx = 0;
	n->all_sec = gensec_security_by_oid_list(gensec_security,
						 n, n->mech_types,
						 GENSEC_OID_SPNEGO);
	if (n->all_sec == NULL) {
		DBG_WARNING("gensec_security_by_oid_list() failed\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	ok = spnego_write_mech_types(spnego_state,
				     n->mech_types,
				     &spnego_state->mech_types);
	if (!ok) {
		DBG_ERR("Failed to write mechTypes\n");
		return NT_STATUS_NO_MEMORY;
	}

	return n->ops->step_fn(gensec_security, spnego_state, n,
			       spnego_in, NT_STATUS_OK, in_mem_ctx, in_next);
}

static NTSTATUS gensec_spnego_server_negTokenInit_step(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS last_status,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	if (!NT_STATUS_IS_OK(last_status)) {
		const struct gensec_security_ops_wrapper *cur_sec =
			&n->all_sec[n->all_idx];
		const char *next_mech = n->mech_types[n->mech_idx+1];
		const struct gensec_security_ops_wrapper *next_sec = NULL;
		const char *next = NULL;
		int dbg_level = DBGLVL_WARNING;
		bool allow_fallback = false;
		NTSTATUS status = last_status;
		size_t i;

		for (i = 0; next_mech != NULL && n->all_sec[i].op != NULL; i++) {
			if (strcmp(next_mech, n->all_sec[i].oid) != 0) {
				continue;
			}

			next_sec = &n->all_sec[i];
			break;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO))
		{
			allow_fallback = true;
		}

		if (allow_fallback && next_sec != NULL) {
			next = next_sec->op->name;
			dbg_level = DBGLVL_NOTICE;
		}

		DBG_PREFIX(dbg_level, (
			   "%s: parsing NEG_TOKEN_INIT content failed "
			   "(next[%s]): %s\n", cur_sec->op->name,
			   next, nt_errstr(status)));

		if (next == NULL) {
			/*
			 * A hard error without a possible fallback.
			 */
			return status;
		}

		/*
		 * Pretend we never started it
		 */
		gensec_spnego_reset_sub_sec(spnego_state);

		/*
		 * And try the next one, based on the clients
		 * mech type list...
		 */
		n->mech_idx += 1;
	}

	/*
	 * we always reset all_idx here, as the negotiation is
	 * done via mech_idx!
	 */
	n->all_idx = 0;

	for (; n->mech_types[n->mech_idx] != NULL; n->mech_idx++) {
		const char *cur_mech = n->mech_types[n->mech_idx];
		const struct gensec_security_ops_wrapper *cur_sec = NULL;
		NTSTATUS status;
		DATA_BLOB sub_in = data_blob_null;
		size_t i;

		for (i = 0; n->all_sec[i].op != NULL; i++) {
			if (strcmp(cur_mech, n->all_sec[i].oid) != 0) {
				continue;
			}

			cur_sec = &n->all_sec[i];
			n->all_idx = i;
			break;
		}

		if (cur_sec == NULL) {
			continue;
		}

		status = gensec_subcontext_start(spnego_state,
						 gensec_security,
						 &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* select the sub context */
		status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						  cur_sec->op);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * Pretend we never started it
			 */
			gensec_spnego_reset_sub_sec(spnego_state);
			continue;
		}

		if (n->mech_idx == 0) {
			/*
			 * We can use the optimistic token.
			 */
			sub_in = spnego_in->negTokenInit.mechToken;
		} else {
			/*
			 * Indicate the downgrade and request a
			 * mic.
			 */
			spnego_state->downgraded = true;
			spnego_state->mic_requested = true;
		}

		if (sub_in.length == 0) {
			spnego_state->no_optimistic = true;
		}

		/*
		 * Note that 'cur_sec' is temporary memory, but
		 * cur_sec->oid points to a const string in the
		 * backends gensec_security_ops structure.
		 */
		spnego_state->neg_oid = cur_sec->oid;

		/* we need some content from the mech */
		*in_next = sub_in;
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	DBG_WARNING("Could not find a suitable mechtype in NEG_TOKEN_INIT\n");
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_spnego_server_negTokenInit_finish(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS sub_status,
					const DATA_BLOB sub_out,
					TALLOC_CTX *out_mem_ctx,
					DATA_BLOB *out)
{
	DATA_BLOB mech_list_mic = data_blob_null;

	if (spnego_state->simulate_w2k) {
		/*
		 * Windows 2000 returns the unwrapped token
		 * also in the mech_list_mic field.
		 *
		 * In order to verify our client code,
		 * we need a way to have a server with this
		 * broken behaviour
		 */
		mech_list_mic = sub_out;
	}

	return gensec_spnego_server_response(spnego_state,
					     out_mem_ctx,
					     sub_status,
					     sub_out,
					     mech_list_mic,
					     out);
}

static const struct spnego_neg_ops gensec_spnego_server_negTokenInit_ops = {
	.name      = "server_negTokenInit",
	.start_fn  = gensec_spnego_server_negTokenInit_start,
	.step_fn   = gensec_spnego_server_negTokenInit_step,
	.finish_fn = gensec_spnego_server_negTokenInit_finish,
};

static NTSTATUS gensec_spnego_server_negTokenTarg_start(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	const struct spnego_negTokenTarg *ta = &spnego_in->negTokenTarg;
	NTSTATUS status;

	spnego_state->num_targs++;

	if (spnego_state->sub_sec_security == NULL) {
		DBG_ERR("SPNEGO: Did not setup a mech in NEG_TOKEN_INIT\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (spnego_state->needs_mic_check) {
		if (ta->responseToken.length != 0) {
			DBG_WARNING("non empty response token not expected\n");
			return NT_STATUS_INVALID_PARAMETER;
		}

		status = gensec_check_packet(spnego_state->sub_sec_security,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     &ta->mechListMIC);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("failed to verify mechListMIC: %s\n",
				    nt_errstr(status));
			return status;
		}

		spnego_state->needs_mic_check = false;
		spnego_state->done_mic_check = true;
		return NT_STATUS_OK;
	}

	if (!spnego_state->sub_sec_ready) {
		*in_next = ta->responseToken;
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_spnego_server_negTokenTarg_step(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS last_status,
					TALLOC_CTX *in_mem_ctx,
					DATA_BLOB *in_next)
{
	if (GENSEC_UPDATE_IS_NTERROR(last_status)) {
		DBG_NOTICE("SPNEGO(%s) login failed: %s\n",
			   spnego_state->sub_sec_security->ops->name,
			   nt_errstr(last_status));
		return last_status;
	}

	/*
	 * This should never be reached!
	 * The step function is only called on errors!
	 */
	smb_panic(__location__);
	return NT_STATUS_INTERNAL_ERROR;
}

static NTSTATUS gensec_spnego_server_negTokenTarg_finish(
					struct gensec_security *gensec_security,
					struct spnego_state *spnego_state,
					struct spnego_neg_state *n,
					struct spnego_data *spnego_in,
					NTSTATUS sub_status,
					const DATA_BLOB sub_out,
					TALLOC_CTX *out_mem_ctx,
					DATA_BLOB *out)
{
	const struct spnego_negTokenTarg *ta = &spnego_in->negTokenTarg;
	DATA_BLOB mech_list_mic = data_blob_null;
	NTSTATUS status;
	bool have_sign = true;
	bool new_spnego = false;

	status = sub_status;

	if (!spnego_state->sub_sec_ready) {
		/*
		 * We're not yet ready to deal with signatures.
		 */
		goto server_response;
	}

	if (spnego_state->done_mic_check) {
		/*
		 * We already checked the mic,
		 * either the in last round here
		 * in gensec_spnego_server_negTokenTarg_finish()
		 * or during this round in
		 * gensec_spnego_server_negTokenTarg_start().
		 *
		 * Both cases we're sure we don't have to
		 * call gensec_sign_packet().
		 */
		goto server_response;
	}

	have_sign = gensec_have_feature(spnego_state->sub_sec_security,
					GENSEC_FEATURE_SIGN);
	if (spnego_state->simulate_w2k) {
		have_sign = false;
	}
	new_spnego = gensec_have_feature(spnego_state->sub_sec_security,
					 GENSEC_FEATURE_NEW_SPNEGO);
	if (ta->mechListMIC.length > 0) {
		new_spnego = true;
	}

	if (have_sign && new_spnego) {
		spnego_state->needs_mic_check = true;
		spnego_state->needs_mic_sign = true;
	}

	if (have_sign && ta->mechListMIC.length > 0) {
		status = gensec_check_packet(spnego_state->sub_sec_security,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     spnego_state->mech_types.data,
					     spnego_state->mech_types.length,
					     &ta->mechListMIC);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("failed to verify mechListMIC: %s\n",
				    nt_errstr(status));
			return status;
		}

		spnego_state->needs_mic_check = false;
		spnego_state->done_mic_check = true;
	}

	if (spnego_state->needs_mic_sign) {
		status = gensec_sign_packet(spnego_state->sub_sec_security,
					    n,
					    spnego_state->mech_types.data,
					    spnego_state->mech_types.length,
					    spnego_state->mech_types.data,
					    spnego_state->mech_types.length,
					    &mech_list_mic);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("failed to sign mechListMIC: %s\n",
				    nt_errstr(status));
			return status;
		}
		spnego_state->needs_mic_sign = false;
	}

	if (spnego_state->needs_mic_check) {
		status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

 server_response:
	return gensec_spnego_server_response(spnego_state,
					     out_mem_ctx,
					     status,
					     sub_out,
					     mech_list_mic,
					     out);
}

static const struct spnego_neg_ops gensec_spnego_server_negTokenTarg_ops = {
	.name      = "server_negTokenTarg",
	.start_fn  = gensec_spnego_server_negTokenTarg_start,
	.step_fn   = gensec_spnego_server_negTokenTarg_step,
	.finish_fn = gensec_spnego_server_negTokenTarg_finish,
};

struct gensec_spnego_update_state {
	struct tevent_context *ev;
	struct gensec_security *gensec;
	struct spnego_state *spnego;

	DATA_BLOB full_in;
	struct spnego_data _spnego_in;
	struct spnego_data *spnego_in;

	struct {
		bool needed;
		DATA_BLOB in;
		NTSTATUS status;
		DATA_BLOB out;
	} sub;

	struct spnego_neg_state *n;

	NTSTATUS status;
	DATA_BLOB out;
};

static void gensec_spnego_update_cleanup(struct tevent_req *req,
					 enum tevent_req_state req_state)
{
	struct gensec_spnego_update_state *state =
		tevent_req_data(req,
		struct gensec_spnego_update_state);

	switch (req_state) {
	case TEVENT_REQ_USER_ERROR:
	case TEVENT_REQ_TIMED_OUT:
	case TEVENT_REQ_NO_MEMORY:
		/*
		 * A fatal error, further updates are not allowed.
		 */
		state->spnego->state_position = SPNEGO_DONE;
		break;
	default:
		break;
	}
}

static NTSTATUS gensec_spnego_update_in(struct gensec_security *gensec_security,
					const DATA_BLOB in, TALLOC_CTX *mem_ctx,
					DATA_BLOB *full_in);
static void gensec_spnego_update_pre(struct tevent_req *req);
static void gensec_spnego_update_done(struct tevent_req *subreq);
static void gensec_spnego_update_post(struct tevent_req *req);
static NTSTATUS gensec_spnego_update_out(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 DATA_BLOB *_out);

static struct tevent_req *gensec_spnego_update_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct gensec_security *gensec_security,
						    const DATA_BLOB in)
{
	struct spnego_state *spnego_state =
		talloc_get_type_abort(gensec_security->private_data,
		struct spnego_state);
	struct tevent_req *req = NULL;
	struct gensec_spnego_update_state *state = NULL;
	NTSTATUS status;
	ssize_t len;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_spnego_update_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->gensec = gensec_security;
	state->spnego = spnego_state;
	tevent_req_set_cleanup_fn(req, gensec_spnego_update_cleanup);

	if (spnego_state->out_frag.length > 0) {
		if (in.length > 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		status = gensec_spnego_update_out(gensec_security,
						  state, &state->out);
		if (GENSEC_UPDATE_IS_NTERROR(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}

		state->status = status;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	status = gensec_spnego_update_in(gensec_security, in,
					 state, &state->full_in);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	/* Check if we got a valid SPNEGO blob... */

	switch (spnego_state->state_position) {
	case SPNEGO_FALLBACK:
		break;

	case SPNEGO_CLIENT_TARG:
	case SPNEGO_SERVER_TARG:
		if (state->full_in.length == 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		FALL_THROUGH;
	case SPNEGO_CLIENT_START:
	case SPNEGO_SERVER_START:

		if (state->full_in.length == 0) {
			/* create_negTokenInit later */
			break;
		}

		len = spnego_read_data(state,
				       state->full_in,
				       &state->_spnego_in);
		if (len == -1) {
			if (spnego_state->state_position != SPNEGO_SERVER_START) {
				DEBUG(1, ("Invalid SPNEGO request:\n"));
				dump_data(1, state->full_in.data,
					  state->full_in.length);
				tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}

			/*
			 * This is the 'fallback' case, where we don't get
			 * SPNEGO, and have to try all the other options (and
			 * hope they all have a magic string they check)
			 */
			status = gensec_spnego_server_try_fallback(gensec_security,
								   spnego_state,
								   state,
								   state->full_in);
			if (tevent_req_nterror(req, status)) {
				return tevent_req_post(req, ev);
			}

			/*
			 * We'll continue with SPNEGO_FALLBACK below...
			 */
			break;
		}
		state->spnego_in = &state->_spnego_in;

		/* OK, so it's real SPNEGO, check the packet's the one we expect */
		if (state->spnego_in->type != spnego_state->expected_packet) {
			DEBUG(1, ("Invalid SPNEGO request: %d, expected %d\n",
				  state->spnego_in->type,
				  spnego_state->expected_packet));
			dump_data(1, state->full_in.data,
				  state->full_in.length);
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		break;

	default:
		smb_panic(__location__);
		return NULL;
	}

	gensec_spnego_update_pre(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	if (state->sub.needed) {
		struct tevent_req *subreq = NULL;

		/*
		 * We may need one more roundtrip...
		 */
		subreq = gensec_update_send(state, state->ev,
					    spnego_state->sub_sec_security,
					    state->sub.in);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					gensec_spnego_update_done,
					req);
		state->sub.needed = false;
		return req;
	}

	gensec_spnego_update_post(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static NTSTATUS gensec_spnego_update_in(struct gensec_security *gensec_security,
					const DATA_BLOB in, TALLOC_CTX *mem_ctx,
					DATA_BLOB *full_in)
{
	struct spnego_state *spnego_state =
		talloc_get_type_abort(gensec_security->private_data,
		struct spnego_state);
	size_t expected;
	bool ok;

	*full_in = data_blob_null;

	switch (spnego_state->state_position) {
	case SPNEGO_FALLBACK:
		*full_in = in;
		spnego_state->in_needed = 0;
		return NT_STATUS_OK;

	case SPNEGO_CLIENT_START:
	case SPNEGO_CLIENT_TARG:
	case SPNEGO_SERVER_START:
	case SPNEGO_SERVER_TARG:
		break;

	case SPNEGO_DONE:
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (spnego_state->in_needed == 0) {
		size_t size = 0;
		int ret;

		/*
		 * try to work out the size of the full
		 * input token, it might be fragmented
		 */
		ret = asn1_peek_full_tag(in,  ASN1_APPLICATION(0), &size);
		if ((ret != 0) && (ret != EAGAIN)) {
			ret = asn1_peek_full_tag(in, ASN1_CONTEXT(1), &size);
		}

		if ((ret == 0) || (ret == EAGAIN)) {
			spnego_state->in_needed = size;
		} else {
			/*
			 * If it is not an asn1 message
			 * just call the next layer.
			 */
			spnego_state->in_needed = in.length;
		}
	}

	if (spnego_state->in_needed > UINT16_MAX) {
		/*
		 * limit the incoming message to 0xFFFF
		 * to avoid DoS attacks.
		 */
		return NT_STATUS_INVALID_BUFFER_SIZE;
	}

	if ((spnego_state->in_needed > 0) && (in.length == 0)) {
		/*
		 * If we reach this, we know we got at least
		 * part of an asn1 message, getting 0 means
		 * the remote peer wants us to spin.
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	expected = spnego_state->in_needed - spnego_state->in_frag.length;
	if (in.length > expected) {
		/*
		 * we got more than expected
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in.length == spnego_state->in_needed) {
		/*
		 * if the in.length contains the full blob
		 * we are done.
		 *
		 * Note: this implies spnego_state->in_frag.length == 0,
		 *       but we do not need to check this explicitly
		 *       because we already know that we did not get
		 *       more than expected.
		 */
		*full_in = in;
		spnego_state->in_needed = 0;
		return NT_STATUS_OK;
	}

	ok = data_blob_append(spnego_state, &spnego_state->in_frag,
			      in.data, in.length);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	if (spnego_state->in_needed > spnego_state->in_frag.length) {
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}

	*full_in = spnego_state->in_frag;
	talloc_steal(mem_ctx, full_in->data);
	spnego_state->in_frag = data_blob_null;
	spnego_state->in_needed = 0;
	return NT_STATUS_OK;
}

static void gensec_spnego_update_pre(struct tevent_req *req)
{
	struct gensec_spnego_update_state *state =
		tevent_req_data(req,
		struct gensec_spnego_update_state);
	struct spnego_state *spnego_state = state->spnego;
	const struct spnego_neg_ops *ops = NULL;
	NTSTATUS status;

	state->sub.needed = false;
	state->sub.in = data_blob_null;
	state->sub.status = NT_STATUS_INTERNAL_ERROR;
	state->sub.out = data_blob_null;

	if (spnego_state->state_position == SPNEGO_FALLBACK) {
		state->sub.in = state->full_in;
		state->full_in = data_blob_null;
		state->sub.needed = true;
		return;
	}

	switch (spnego_state->state_position) {
	case SPNEGO_CLIENT_START:
		if (state->spnego_in == NULL) {
			/* client to produce negTokenInit */
			ops = &gensec_spnego_create_negTokenInit_ops;
			break;
		}

		ops = &gensec_spnego_client_negTokenInit_ops;
		break;

	case SPNEGO_CLIENT_TARG:
		ops = &gensec_spnego_client_negTokenTarg_ops;
		break;

	case SPNEGO_SERVER_START:
		if (state->spnego_in == NULL) {
			/* server to produce negTokenInit */
			ops = &gensec_spnego_create_negTokenInit_ops;
			break;
		}

		ops = &gensec_spnego_server_negTokenInit_ops;
		break;

	case SPNEGO_SERVER_TARG:
		ops = &gensec_spnego_server_negTokenTarg_ops;
		break;

	default:
		smb_panic(__location__);
		return;
	}

	state->n = gensec_spnego_neg_state(state, ops);
	if (tevent_req_nomem(state->n, req)) {
		return;
	}

	status = ops->start_fn(state->gensec, spnego_state, state->n,
			       state->spnego_in, state, &state->sub.in);
	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(status)) {
		/*
		 * Call finish_fn() with an empty
		 * blob and NT_STATUS_OK.
		 */
		state->sub.status = NT_STATUS_OK;
	} else if (spnego_state->state_position == SPNEGO_CLIENT_START &&
		   spnego_state->no_optimistic) {
		/*
		 * Skip optimistic token per conf.
		 */
		state->sub.status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	} else if (spnego_state->state_position == SPNEGO_SERVER_START &&
		   state->sub.in.length == 0 && spnego_state->no_optimistic) {
		/*
		 * If we didn't like the mechanism for which the client sent us
		 * an optimistic token, or if he didn't send any, don't call
		 * the sub mechanism just yet.
		 */
		state->sub.status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		spnego_state->no_optimistic = false;
	} else {
		/*
		 * MORE_PROCESSING_REQUIRED =>
		 * we need to call gensec_update_send().
		 */
		state->sub.needed = true;
	}
}

static void gensec_spnego_update_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct gensec_spnego_update_state *state =
		tevent_req_data(req,
		struct gensec_spnego_update_state);
	struct spnego_state *spnego_state = state->spnego;

	state->sub.status = gensec_update_recv(subreq, state, &state->sub.out);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(state->sub.status)) {
		spnego_state->sub_sec_ready = true;
	}

	gensec_spnego_update_post(req);
}

static void gensec_spnego_update_post(struct tevent_req *req)
{
	struct gensec_spnego_update_state *state =
		tevent_req_data(req,
		struct gensec_spnego_update_state);
	struct spnego_state *spnego_state = state->spnego;
	const struct spnego_neg_ops *ops = NULL;
	NTSTATUS status;

	state->sub.in = data_blob_null;
	state->sub.needed = false;

	if (spnego_state->state_position == SPNEGO_FALLBACK) {
		status = state->sub.status;
		spnego_state->out_frag = state->sub.out;
		talloc_steal(spnego_state, spnego_state->out_frag.data);
		state->sub.out = data_blob_null;
		goto respond;
	}

	ops = state->n->ops;

	if (GENSEC_UPDATE_IS_NTERROR(state->sub.status)) {


		/*
		 * gensec_update_recv() returned an error,
		 * let's see if the step_fn() want to
		 * handle it and negotiate something else.
		 */

		status = ops->step_fn(state->gensec,
				      spnego_state,
				      state->n,
				      state->spnego_in,
				      state->sub.status,
				      state,
				      &state->sub.in);
		if (GENSEC_UPDATE_IS_NTERROR(status)) {
			tevent_req_nterror(req, status);
			return;
		}

		state->sub.out = data_blob_null;
		state->sub.status = NT_STATUS_INTERNAL_ERROR;

		if (NT_STATUS_IS_OK(status)) {
			/*
			 * Call finish_fn() with an empty
			 * blob and NT_STATUS_OK.
			 */
			state->sub.status = NT_STATUS_OK;
		} else {
			/*
			 * MORE_PROCESSING_REQUIRED...
			 */
			state->sub.needed = true;
		}
	}

	if (state->sub.needed) {
		struct tevent_req *subreq = NULL;

		/*
		 * We may need one more roundtrip...
		 */
		subreq = gensec_update_send(state, state->ev,
					    spnego_state->sub_sec_security,
					    state->sub.in);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					gensec_spnego_update_done,
					req);
		state->sub.needed = false;
		return;
	}

	status = ops->finish_fn(state->gensec,
				spnego_state,
				state->n,
				state->spnego_in,
				state->sub.status,
				state->sub.out,
				spnego_state,
				&spnego_state->out_frag);
	TALLOC_FREE(state->n);
	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(status)) {
		bool reset_full = true;

		reset_full = !spnego_state->done_mic_check;

		status = gensec_may_reset_crypto(spnego_state->sub_sec_security,
						 reset_full);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

respond:
	spnego_state->out_status = status;

	status = gensec_spnego_update_out(state->gensec,
					  state, &state->out);
	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->status = status;
	tevent_req_done(req);
	return;
}

static NTSTATUS gensec_spnego_update_out(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 DATA_BLOB *_out)
{
	struct spnego_state *spnego_state =
		talloc_get_type_abort(gensec_security->private_data,
		struct spnego_state);
	DATA_BLOB out = data_blob_null;
	bool ok;

	*_out = data_blob_null;

	if (spnego_state->out_frag.length <= spnego_state->out_max_length) {
		/*
		 * Fast path, we can deliver everything
		 */

		*_out = spnego_state->out_frag;
		if (spnego_state->out_frag.length > 0) {
			talloc_steal(out_mem_ctx, _out->data);
			spnego_state->out_frag = data_blob_null;
		}

		if (!NT_STATUS_IS_OK(spnego_state->out_status)) {
			return spnego_state->out_status;
		}

		/*
		 * We're completely done, further updates are not allowed.
		 */
		spnego_state->state_position = SPNEGO_DONE;
		return gensec_child_ready(gensec_security,
					  spnego_state->sub_sec_security);
	}

	out = spnego_state->out_frag;

	/*
	 * copy the remaining bytes
	 */
	spnego_state->out_frag = data_blob_talloc(spnego_state,
					out.data + spnego_state->out_max_length,
					out.length - spnego_state->out_max_length);
	if (spnego_state->out_frag.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * truncate the buffer
	 */
	ok = data_blob_realloc(spnego_state, &out,
			       spnego_state->out_max_length);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	talloc_steal(out_mem_ctx, out.data);
	*_out = out;
	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS gensec_spnego_update_recv(struct tevent_req *req,
					  TALLOC_CTX *out_mem_ctx,
					  DATA_BLOB *out)
{
	struct gensec_spnego_update_state *state =
		tevent_req_data(req,
		struct gensec_spnego_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out = state->out;
	talloc_steal(out_mem_ctx, state->out.data);
	status = state->status;
	tevent_req_received(req);
	return status;
}

static const char *gensec_spnego_oids[] = { 
	GENSEC_OID_SPNEGO,
	NULL 
};

static const struct gensec_security_ops gensec_spnego_security_ops = {
	.name		  = "spnego",
	.sasl_name	  = "GSS-SPNEGO",
	.auth_type	  = DCERPC_AUTH_TYPE_SPNEGO,
	.oid              = gensec_spnego_oids,
	.client_start     = gensec_spnego_client_start,
	.server_start     = gensec_spnego_server_start,
	.update_send	  = gensec_spnego_update_send,
	.update_recv	  = gensec_spnego_update_recv,
	.seal_packet	  = gensec_child_seal_packet,
	.sign_packet	  = gensec_child_sign_packet,
	.sig_size	  = gensec_child_sig_size,
	.max_wrapped_size = gensec_child_max_wrapped_size,
	.max_input_size	  = gensec_child_max_input_size,
	.check_packet	  = gensec_child_check_packet,
	.unseal_packet	  = gensec_child_unseal_packet,
	.wrap             = gensec_child_wrap,
	.unwrap           = gensec_child_unwrap,
	.session_key	  = gensec_child_session_key,
	.session_info     = gensec_child_session_info,
	.want_feature     = gensec_child_want_feature,
	.have_feature     = gensec_child_have_feature,
	.expire_time      = gensec_child_expire_time,
	.final_auth_type  = gensec_child_final_auth_type,
	.enabled          = true,
	.priority         = GENSEC_SPNEGO,
	.glue             = true,
};

_PUBLIC_ NTSTATUS gensec_spnego_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	ret = gensec_register(ctx, &gensec_spnego_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_spnego_security_ops.name));
		return ret;
	}

	return ret;
}
