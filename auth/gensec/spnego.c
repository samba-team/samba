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

static void gensec_spnego_update_sub_abort(struct spnego_state *spnego_state)
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

/* 
   Parse the netTokenInit, either from the client, to the server, or
   from the server to the client.
*/

static NTSTATUS gensec_spnego_parse_negTokenInit(struct gensec_security *gensec_security,
						 struct spnego_state *spnego_state, 
						 TALLOC_CTX *out_mem_ctx, 
						 struct tevent_context *ev,
						 struct spnego_data *spnego_in,
						 DATA_BLOB *unwrapped_out)
{
	int i;
	NTSTATUS nt_status = NT_STATUS_INVALID_PARAMETER;
	const char * const *mechType = NULL;
	DATA_BLOB unwrapped_in = data_blob_null;
	bool ok;
	const struct gensec_security_ops_wrapper *all_sec = NULL;
	uint32_t j;

	if (spnego_state->state_position != SPNEGO_SERVER_START) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (spnego_in->type != SPNEGO_NEG_TOKEN_INIT) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	mechType = spnego_in->negTokenInit.mechTypes;
	if (mechType == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	unwrapped_in = spnego_in->negTokenInit.mechToken;

	all_sec = gensec_security_by_oid_list(gensec_security,
					      out_mem_ctx, 
					      mechType,
					      GENSEC_OID_SPNEGO);
	if (all_sec == NULL) {
		DBG_WARNING("gensec_security_by_oid_list() failed\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	ok = spnego_write_mech_types(spnego_state,
				     mechType,
				     &spnego_state->mech_types);
	if (!ok) {
		DEBUG(1, ("SPNEGO: Failed to write mechTypes\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (j=0; mechType && mechType[j]; j++) {
		for (i=0; all_sec && all_sec[i].op; i++) {
			if (strcmp(mechType[j], all_sec[i].oid) != 0) {
				continue;
			}

			nt_status = gensec_subcontext_start(spnego_state,
							    gensec_security,
							    &spnego_state->sub_sec_security);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}
			/* select the sub context */
			nt_status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
							     all_sec[i].op);
			if (!NT_STATUS_IS_OK(nt_status)) {
				/*
				 * Pretend we never started it
				 */
				gensec_spnego_update_sub_abort(spnego_state);
				break;
			}

			if (j > 0) {
				/* no optimistic token */
				spnego_state->neg_oid = all_sec[i].oid;
				*unwrapped_out = data_blob_null;
				nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
				/*
				 * Indicate the downgrade and request a
				 * mic.
				 */
				spnego_state->downgraded = true;
				spnego_state->mic_requested = true;
				break;
			}

			nt_status = gensec_update_ev(spnego_state->sub_sec_security,
						  out_mem_ctx,
						  ev,
						  unwrapped_in,
						  unwrapped_out);
			if (NT_STATUS_IS_OK(nt_status)) {
				spnego_state->sub_sec_ready = true;
			}
			if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_PARAMETER) ||
			    NT_STATUS_EQUAL(nt_status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO)) {

				DEBUG(1, ("SPNEGO(%s) NEG_TOKEN_INIT failed to parse contents: %s\n",
					  spnego_state->sub_sec_security->ops->name, nt_errstr(nt_status)));

				/*
				 * Pretend we never started it
				 */
				gensec_spnego_update_sub_abort(spnego_state);
				break;
			}

			spnego_state->neg_oid = all_sec[i].oid;
			break;
		}
		if (spnego_state->sub_sec_security) {
			break;
		}
	}

	if (!spnego_state->sub_sec_security) {
		DEBUG(1, ("SPNEGO: Could not find a suitable mechtype in NEG_TOKEN_INIT\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (spnego_state->sub_sec_security) {
		/* it is likely that a NULL input token will
		 * not be liked by most server mechs, but this
		 * does the right thing in the CIFS client.
		 * just push us along the merry-go-round
		 * again, and hope for better luck next
		 * time */

		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_PARAMETER)) {
			*unwrapped_out = data_blob_null;
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		}

		if (GENSEC_UPDATE_IS_NTERROR(nt_status)) {
			DEBUG(1, ("SPNEGO(%s) NEG_TOKEN_INIT failed: %s\n", 
				  spnego_state->sub_sec_security->ops->name, nt_errstr(nt_status)));

			/* We started the mech correctly, and the
			 * input from the other side was valid.
			 * Return the error (say bad password, invalid
			 * ticket) */
			gensec_spnego_update_sub_abort(spnego_state);
			return nt_status;
		}

		return nt_status; /* OK or MORE PROCESSING */
	}

	DEBUG(1, ("SPNEGO: Could not find a suitable mechtype in NEG_TOKEN_INIT\n"));
	/* we could re-negotiate here, but it would only work
	 * if the client or server lied about what it could
	 * support the first time.  Lets keep this code to
	 * reality */

	return nt_status;
}

/** create a negTokenInit 
 *
 * This is the same packet, no matter if the client or server sends it first, but it is always the first packet
*/
static NTSTATUS gensec_spnego_create_negTokenInit(struct gensec_security *gensec_security, 
						  struct spnego_state *spnego_state,
						  TALLOC_CTX *out_mem_ctx, 
						  struct tevent_context *ev,
						  DATA_BLOB *out)
{
	int i;
	NTSTATUS nt_status = NT_STATUS_INVALID_PARAMETER;
	const char **mechTypes = NULL;
	DATA_BLOB unwrapped_out = data_blob_null;
	const struct gensec_security_ops_wrapper *all_sec;

	mechTypes = gensec_security_oids(gensec_security, 
					 out_mem_ctx, GENSEC_OID_SPNEGO);

	all_sec	= gensec_security_by_oid_list(gensec_security, 
					      out_mem_ctx, 
					      mechTypes,
					      GENSEC_OID_SPNEGO);
	for (i=0; all_sec && all_sec[i].op; i++) {
		struct spnego_data spnego_out;
		const char **send_mech_types;
		bool ok;

		nt_status = gensec_subcontext_start(spnego_state,
						    gensec_security,
						    &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		/* select the sub context */
		nt_status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						     all_sec[i].op);
		if (!NT_STATUS_IS_OK(nt_status)) {
			gensec_spnego_update_sub_abort(spnego_state);
			continue;
		}

		/* In the client, try and produce the first (optimistic) packet */
		if (spnego_state->state_position == SPNEGO_CLIENT_START) {
			nt_status = gensec_update_ev(spnego_state->sub_sec_security,
						  out_mem_ctx, 
						  ev,
						  data_blob_null,
						  &unwrapped_out);
			if (NT_STATUS_IS_OK(nt_status)) {
				spnego_state->sub_sec_ready = true;
			}

			if (GENSEC_UPDATE_IS_NTERROR(nt_status)) {
				const char *next = NULL;
				const char *principal = NULL;
				int dbg_level = DBGLVL_WARNING;

				if (all_sec[i+1].op != NULL) {
					next = all_sec[i+1].op->name;
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

				DEBUG(dbg_level, ("SPNEGO(%s) creating NEG_TOKEN_INIT for %s failed (next[%s]): %s\n",
					  spnego_state->sub_sec_security->ops->name,
					  principal,
					  next, nt_errstr(nt_status)));

				/*
				 * Pretend we never started it
				 */
				gensec_spnego_update_sub_abort(spnego_state);
				continue;
			}
		}

		spnego_out.type = SPNEGO_NEG_TOKEN_INIT;

		send_mech_types = gensec_security_oids_from_ops_wrapped(out_mem_ctx,
									&all_sec[i]);

		ok = spnego_write_mech_types(spnego_state,
					     send_mech_types,
					     &spnego_state->mech_types);
		if (!ok) {
			DEBUG(1, ("SPNEGO: Failed to write mechTypes\n"));
			return NT_STATUS_NO_MEMORY;
		}

		/* List the remaining mechs as options */
		spnego_out.negTokenInit.mechTypes = send_mech_types;
		spnego_out.negTokenInit.reqFlags = data_blob_null;
		spnego_out.negTokenInit.reqFlagsPadding = 0;

		if (spnego_state->state_position == SPNEGO_SERVER_START) {
			spnego_out.negTokenInit.mechListMIC
				= data_blob_string_const(ADS_IGNORE_PRINCIPAL);
		} else {
			spnego_out.negTokenInit.mechListMIC = data_blob_null;
		}

		spnego_out.negTokenInit.mechToken = unwrapped_out;

		if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
			DEBUG(1, ("Failed to write NEG_TOKEN_INIT\n"));
				return NT_STATUS_INVALID_PARAMETER;
		}

		/* set next state */
		spnego_state->neg_oid = all_sec[i].oid;

		if (spnego_state->state_position == SPNEGO_SERVER_START) {
			spnego_state->state_position = SPNEGO_SERVER_START;
			spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
		} else {
			spnego_state->state_position = SPNEGO_CLIENT_TARG;
			spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
		}

		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	}
	gensec_spnego_update_sub_abort(spnego_state);

	DEBUG(10, ("Failed to setup SPNEGO negTokenInit request: %s\n", nt_errstr(nt_status)));
	return nt_status;
}

static NTSTATUS gensec_spnego_client_negTokenInit(struct gensec_security *gensec_security,
						  struct spnego_state *spnego_state,
						  struct tevent_context *ev,
						  struct spnego_data *spnego_in,
						  TALLOC_CTX *out_mem_ctx,
						  DATA_BLOB *out)
{
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB sub_out = data_blob_null;
	const char *tp = NULL;
	const char * const *mech_types = NULL;
	size_t all_idx = 0;
	const struct gensec_security_ops_wrapper *all_sec = NULL;
	struct spnego_data spnego_out;
	const char *my_mechs[] = {NULL, NULL};
	NTSTATUS status;
	bool ok;

	*out = data_blob_null;

	/* The server offers a list of mechanisms */

	tp = spnego_in->negTokenInit.targetPrincipal;
	if (tp != NULL && strcmp(tp, ADS_IGNORE_PRINCIPAL) != 0) {
		DBG_INFO("Server claims it's principal name is %s\n", tp);
		if (lpcfg_client_use_spnego_principal(gensec_security->settings->lp_ctx)) {
			gensec_set_target_principal(gensec_security, tp);
		}
	}

	mech_types = spnego_in->negTokenInit.mechTypes;
	if (mech_types == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	all_sec = gensec_security_by_oid_list(gensec_security,
					      frame, mech_types,
					      GENSEC_OID_SPNEGO);
	if (all_sec == NULL) {
		DBG_WARNING("gensec_security_by_oid_list() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (; all_sec[all_idx].op; all_idx++) {
		const struct gensec_security_ops_wrapper *cur_sec =
			&all_sec[all_idx];
		const char *next = NULL;
		const char *principal = NULL;
		int dbg_level = DBGLVL_WARNING;
		bool allow_fallback = false;

		status = gensec_subcontext_start(spnego_state,
						 gensec_security,
						 &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		/* select the sub context */
		status = gensec_start_mech_by_ops(spnego_state->sub_sec_security,
						  cur_sec->op);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * Pretend we never started it.
			 */
			gensec_spnego_update_sub_abort(spnego_state);
			continue;
		}

		spnego_state->neg_oid = cur_sec->oid;

		/*
		 * As client we don't use an optimistic token from the server.
		 */
		status = gensec_update_ev(spnego_state->sub_sec_security,
					  frame, ev, data_blob_null, &sub_out);
		if (NT_STATUS_IS_OK(status)) {
			spnego_state->sub_sec_ready = true;
		}

		if (!GENSEC_UPDATE_IS_NTERROR(status)) {
			/* OK or MORE_PROCESSING_REQUIRED */
			goto reply;
		}

		/*
		 * it is likely that a NULL input token will
		 * not be liked by most server mechs, but if
		 * we are in the client, we want the first
		 * update packet to be able to abort the use
		 * of this mech
		 */
		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NO_LOGON_SERVERS) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_TIME_DIFFERENCE_AT_DC) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO))
		{
			allow_fallback = true;
		}

		if (allow_fallback && cur_sec[1].op != NULL) {
			next = cur_sec[1].op->name;
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
			   "%s: creating NEG_TOKEN_INIT "
			   "for %s failed (next[%s]): %s\n",
			   spnego_state->sub_sec_security->ops->name,
			   principal, next, nt_errstr(status)));

		if (allow_fallback && next != NULL) {
			/*
			 * Pretend we never started it.
			 */
			gensec_spnego_update_sub_abort(spnego_state);
			continue;
		}

		/*
		 * Hard error.
		 */
		TALLOC_FREE(frame);
		return status;
	}

	DBG_WARNING("Could not find a suitable mechtype in NEG_TOKEN_INIT\n");
	TALLOC_FREE(frame);
	return NT_STATUS_INVALID_PARAMETER;

 reply:
	my_mechs[0] = spnego_state->neg_oid;
	/* compose reply */
	spnego_out.type = SPNEGO_NEG_TOKEN_INIT;
	spnego_out.negTokenInit.mechTypes = my_mechs;
	spnego_out.negTokenInit.reqFlags = data_blob_null;
	spnego_out.negTokenInit.reqFlagsPadding = 0;
	spnego_out.negTokenInit.mechListMIC = data_blob_null;
	spnego_out.negTokenInit.mechToken = sub_out;

	if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
		DBG_ERR("Failed to write SPNEGO reply to NEG_TOKEN_INIT\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	ok = spnego_write_mech_types(spnego_state,
				     my_mechs,
				     &spnego_state->mech_types);
	if (!ok) {
		DBG_ERR("failed to write mechTypes\n");
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* set next state */
	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
	spnego_state->state_position = SPNEGO_CLIENT_TARG;

	TALLOC_FREE(frame);
	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS gensec_spnego_client_negTokenTarg(struct gensec_security *gensec_security,
						  struct spnego_state *spnego_state,
						  struct tevent_context *ev,
						  struct spnego_data *spnego_in,
						  TALLOC_CTX *out_mem_ctx,
						  DATA_BLOB *out)
{
	struct spnego_negTokenTarg *ta = &spnego_in->negTokenTarg;
	DATA_BLOB sub_in = ta->responseToken;
	DATA_BLOB mech_list_mic = data_blob_null;
	DATA_BLOB sub_out = data_blob_null;
	struct spnego_data spnego_out;
	NTSTATUS status;

	*out = data_blob_null;

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
		gensec_spnego_update_sub_abort(spnego_state);

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
			status = NT_STATUS_OK;
			goto client_response;
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
		goto client_response;
	}

	if (!spnego_state->sub_sec_ready) {
		status = gensec_update_ev(spnego_state->sub_sec_security,
					  out_mem_ctx, ev,
					  sub_in,
					  &sub_out);
		if (NT_STATUS_IS_OK(status)) {
			spnego_state->sub_sec_ready = true;
		}
		if (!NT_STATUS_IS_OK(status)) {
			goto client_response;
		}
	} else {
		status = NT_STATUS_OK;
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
					    out_mem_ctx,
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

 client_response:
	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		DBG_WARNING("SPNEGO(%s) login failed: %s\n",
			    spnego_state->sub_sec_security->ops->name,
			    nt_errstr(status));
		return status;
	}

	if (sub_out.length || mech_list_mic.length) {
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
		spnego_state->state_position = SPNEGO_CLIENT_TARG;
		status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	} else {

		/* all done - server has accepted, and we agree */
		*out = data_blob_null;

		if (ta->negResult != SPNEGO_ACCEPT_COMPLETED) {
			/* unless of course it did not accept */
			DBG_WARNING("gensec_update ok but not accepted\n");
			status = NT_STATUS_INVALID_PARAMETER;
		}

		spnego_state->state_position = SPNEGO_DONE;
	}

	return status;
}

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
	} else {
		spnego_out.negTokenTarg.negResult = SPNEGO_REJECT;
		spnego_out.negTokenTarg.mechListMIC = data_blob_null;
		DEBUG(2, ("SPNEGO login failed: %s\n", nt_errstr(nt_status)));
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

static NTSTATUS gensec_spnego_server_negTokenInit(struct gensec_security *gensec_security,
						  struct spnego_state *spnego_state,
						  struct tevent_context *ev,
						  struct spnego_data *spnego_in,
						  TALLOC_CTX *out_mem_ctx,
						  DATA_BLOB *out)
{
	DATA_BLOB sub_out = data_blob_null;
	DATA_BLOB mech_list_mic = data_blob_null;
	NTSTATUS status;

	status = gensec_spnego_parse_negTokenInit(gensec_security,
						  spnego_state,
						  out_mem_ctx,
						  ev,
						  spnego_in,
						  &sub_out);

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
					     status,
					     sub_out,
					     mech_list_mic,
					     out);
}

static NTSTATUS gensec_spnego_server_negTokenTarg(struct gensec_security *gensec_security,
						  struct spnego_state *spnego_state,
						  struct tevent_context *ev,
						  struct spnego_data *spnego_in,
						  TALLOC_CTX *out_mem_ctx,
						  DATA_BLOB *out)
{
	const struct spnego_negTokenTarg *ta = &spnego_in->negTokenTarg;
	DATA_BLOB sub_in = ta->responseToken;
	DATA_BLOB mech_list_mic = data_blob_null;
	DATA_BLOB sub_out = data_blob_null;
	NTSTATUS status;
	bool have_sign = true;
	bool new_spnego = false;

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
			goto server_response;
		}

		spnego_state->needs_mic_check = false;
		spnego_state->done_mic_check = true;
		goto server_response;
	}

	if (!spnego_state->sub_sec_ready) {
		status = gensec_update_ev(spnego_state->sub_sec_security,
					  out_mem_ctx, ev,
					  sub_in, &sub_out);
		if (NT_STATUS_IS_OK(status)) {
			spnego_state->sub_sec_ready = true;
		}
		if (!NT_STATUS_IS_OK(status)) {
			goto server_response;
		}
	} else {
		status = NT_STATUS_OK;
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
			goto server_response;
		}

		spnego_state->needs_mic_check = false;
		spnego_state->done_mic_check = true;
	}

	if (spnego_state->needs_mic_sign) {
		status = gensec_sign_packet(spnego_state->sub_sec_security,
					    out_mem_ctx,
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

struct gensec_spnego_update_state {
	struct gensec_security *gensec;
	struct spnego_state *spnego;
	DATA_BLOB full_in;
	struct spnego_data _spnego_in;
	struct spnego_data *spnego_in;
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

		/* fall through */
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

	/* and switch into the state machine */

	switch (spnego_state->state_position) {
	case SPNEGO_FALLBACK:
		status = gensec_update_ev(spnego_state->sub_sec_security,
					  state, ev,
					  state->full_in,
					  &spnego_state->out_frag);
		break;

	case SPNEGO_CLIENT_START:
		if (state->spnego_in == NULL) {
			/* client to produce negTokenInit */
			status = gensec_spnego_create_negTokenInit(gensec_security,
							spnego_state, state, ev,
							&spnego_state->out_frag);
			break;
		}

		status = gensec_spnego_client_negTokenInit(gensec_security,
							spnego_state, ev,
							state->spnego_in, state,
							&spnego_state->out_frag);
		break;

	case SPNEGO_CLIENT_TARG:
		status = gensec_spnego_client_negTokenTarg(gensec_security,
							spnego_state, ev,
							state->spnego_in, state,
							&spnego_state->out_frag);
		break;

	case SPNEGO_SERVER_START:
		if (state->spnego_in == NULL) {
			/* server to produce negTokenInit */
			status = gensec_spnego_create_negTokenInit(gensec_security,
							spnego_state, state, ev,
							&spnego_state->out_frag);
			break;
		}

		status = gensec_spnego_server_negTokenInit(gensec_security,
							spnego_state, ev,
							state->spnego_in, state,
							&spnego_state->out_frag);
		break;

	case SPNEGO_SERVER_TARG:
		status = gensec_spnego_server_negTokenTarg(gensec_security,
							spnego_state, ev,
							state->spnego_in, state,
							&spnego_state->out_frag);
		break;

	default:
		smb_panic(__location__);
		return NULL;
	}

	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	if (NT_STATUS_IS_OK(status)) {
		bool reset_full = true;

		reset_full = !spnego_state->done_mic_check;

		status = gensec_may_reset_crypto(spnego_state->sub_sec_security,
						 reset_full);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	spnego_state->out_status = status;

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

static NTSTATUS gensec_spnego_update_in(struct gensec_security *gensec_security,
					const DATA_BLOB in, TALLOC_CTX *mem_ctx,
					DATA_BLOB *full_in)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
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

static NTSTATUS gensec_spnego_update_out(struct gensec_security *gensec_security,
					 TALLOC_CTX *out_mem_ctx,
					 DATA_BLOB *_out)
{
	struct spnego_state *spnego_state = (struct spnego_state *)gensec_security->private_data;
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
	.priority         = GENSEC_SPNEGO
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
