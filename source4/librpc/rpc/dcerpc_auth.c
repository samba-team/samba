/* 
   Unix SMB/CIFS implementation.

   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Stefan Metzmacher 2004
   
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
#include "libcli/composite/composite.h"
#include "auth/gensec/gensec.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "param/param.h"

/*
  return the rpc syntax and transfer syntax given the pipe uuid and version
*/
static NTSTATUS dcerpc_init_syntaxes(struct dcerpc_pipe *p,
				     const struct ndr_interface_table *table,
				     struct ndr_syntax_id *syntax,
				     struct ndr_syntax_id *transfer_syntax)
{
	struct GUID *object = NULL;

	p->object = dcerpc_binding_get_object(p->binding);
	if (!GUID_all_zero(&p->object)) {
		object = &p->object;
	}

	p->binding_handle = dcerpc_pipe_binding_handle(p, object, table);
	if (p->binding_handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	syntax->uuid = table->syntax_id.uuid;
	syntax->if_version = table->syntax_id.if_version;

	if (p->conn->flags & DCERPC_NDR64) {
		*transfer_syntax = ndr_transfer_syntax_ndr64;
	} else {
		*transfer_syntax = ndr_transfer_syntax_ndr;
	}

	return NT_STATUS_OK;
}


/*
  Send request to do a non-authenticated dcerpc bind
*/
static void dcerpc_bind_auth_none_done(struct tevent_req *subreq);

struct composite_context *dcerpc_bind_auth_none_send(TALLOC_CTX *mem_ctx,
						     struct dcerpc_pipe *p,
						     const struct ndr_interface_table *table)
{
	struct ndr_syntax_id syntax;
	struct ndr_syntax_id transfer_syntax;

	struct composite_context *c;
	struct tevent_req *subreq;

	c = composite_create(mem_ctx, p->conn->event_ctx);
	if (c == NULL) return NULL;

	c->status = dcerpc_init_syntaxes(p, table,
					 &syntax, &transfer_syntax);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(2,("Invalid uuid string in "
			 "dcerpc_bind_auth_none_send\n"));
		composite_error(c, c->status);
		return c;
	}

	subreq = dcerpc_bind_send(mem_ctx, p->conn->event_ctx, p,
				  &syntax, &transfer_syntax);
	if (composite_nomem(subreq, c)) return c;
	tevent_req_set_callback(subreq, dcerpc_bind_auth_none_done, c);

	return c;
}

static void dcerpc_bind_auth_none_done(struct tevent_req *subreq)
{
	struct composite_context *ctx =
		tevent_req_callback_data(subreq,
		struct composite_context);

	ctx->status = dcerpc_bind_recv(subreq);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(ctx)) return;

	composite_done(ctx);
}

/*
  Receive result of a non-authenticated dcerpc bind
*/
NTSTATUS dcerpc_bind_auth_none_recv(struct composite_context *ctx)
{
	NTSTATUS result = composite_wait(ctx);
	TALLOC_FREE(ctx);
	return result;
}


/*
  Perform sync non-authenticated dcerpc bind
*/
_PUBLIC_ NTSTATUS dcerpc_bind_auth_none(struct dcerpc_pipe *p,
			       const struct ndr_interface_table *table)
{
	struct composite_context *ctx;

	ctx = dcerpc_bind_auth_none_send(p, p, table);
	return dcerpc_bind_auth_none_recv(ctx);
}


struct bind_auth_state {
	struct dcerpc_pipe *pipe;
	struct ndr_syntax_id syntax;
	struct ndr_syntax_id transfer_syntax;
	struct dcerpc_auth out_auth_info;
	struct dcerpc_auth in_auth_info;
	bool more_processing;	/* Is there anything more to do after the
				 * first bind itself received? */
};

static void bind_auth_next_gensec_done(struct tevent_req *subreq);
static void bind_auth_recv_alter(struct tevent_req *subreq);

static void bind_auth_next_step(struct composite_context *c)
{
	struct bind_auth_state *state;
	struct dcecli_security *sec;
	struct tevent_req *subreq;

	state = talloc_get_type(c->private_data, struct bind_auth_state);
	sec = &state->pipe->conn->security_state;

	if (state->in_auth_info.auth_type != sec->auth_type) {
		composite_error(c, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	if (state->in_auth_info.auth_level != sec->auth_level) {
		composite_error(c, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	if (state->in_auth_info.auth_context_id != sec->auth_context_id) {
		composite_error(c, NT_STATUS_RPC_PROTOCOL_ERROR);
		return;
	}

	state->out_auth_info = (struct dcerpc_auth) {
		.auth_type = sec->auth_type,
		.auth_level = sec->auth_level,
		.auth_context_id = sec->auth_context_id,
	};

	/* The status value here, from GENSEC is vital to the security
	 * of the system.  Even if the other end accepts, if GENSEC
	 * claims 'MORE_PROCESSING_REQUIRED' then you must keep
	 * feeding it blobs, or else the remote host/attacker might
	 * avoid mutal authentication requirements.
	 *
	 * Likewise, you must not feed GENSEC too much (after the OK),
	 * it doesn't like that either
	 */

	state->pipe->inhibit_timeout_processing = true;
	state->pipe->timed_out = false;

	subreq = gensec_update_send(state,
				    state->pipe->conn->event_ctx,
				    sec->generic_state,
				    state->in_auth_info.credentials);
	if (composite_nomem(subreq, c)) return;
	tevent_req_set_callback(subreq, bind_auth_next_gensec_done, c);
}

static void bind_auth_next_gensec_done(struct tevent_req *subreq)
{
	struct composite_context *c =
		tevent_req_callback_data(subreq,
		struct composite_context);
	struct bind_auth_state *state =
		talloc_get_type_abort(c->private_data,
		struct bind_auth_state);
	struct dcerpc_pipe *p = state->pipe;
	struct dcecli_security *sec = &p->conn->security_state;
	bool more_processing = false;

	state->pipe->inhibit_timeout_processing = false;

	c->status = gensec_update_recv(subreq, state,
				       &state->out_auth_info.credentials);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(c->status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		more_processing = true;
		c->status = NT_STATUS_OK;
	}

	if (!composite_is_ok(c)) return;

	if (!more_processing) {
		if (state->pipe->conn->flags & DCERPC_HEADER_SIGNING) {
			gensec_want_feature(sec->generic_state,
					GENSEC_FEATURE_SIGN_PKT_HEADER);
		}
	}

	if (state->out_auth_info.credentials.length == 0) {
		composite_done(c);
		return;
	}

	state->in_auth_info = (struct dcerpc_auth) {
		.auth_type = DCERPC_AUTH_TYPE_NONE,
	};
	sec->tmp_auth_info.in = &state->in_auth_info;
	sec->tmp_auth_info.mem = state;
	sec->tmp_auth_info.out = &state->out_auth_info;

	if (!more_processing) {
		/* NO reply expected, so just send it */
		c->status = dcerpc_auth3(state->pipe, state);
		if (!composite_is_ok(c)) return;

		composite_done(c);
		return;
	}

	/* We are demanding a reply, so use a request that will get us one */

	subreq = dcerpc_alter_context_send(state, state->pipe->conn->event_ctx,
					   state->pipe,
					   &state->pipe->syntax,
					   &state->pipe->transfer_syntax);
	if (composite_nomem(subreq, c)) return;
	tevent_req_set_callback(subreq, bind_auth_recv_alter, c);
}


static void bind_auth_recv_alter(struct tevent_req *subreq)
{
	struct composite_context *c =
		tevent_req_callback_data(subreq,
		struct composite_context);
	struct bind_auth_state *state =	talloc_get_type(c->private_data,
							struct bind_auth_state);
	struct dcecli_security *sec = &state->pipe->conn->security_state;

	ZERO_STRUCT(sec->tmp_auth_info);

	c->status = dcerpc_alter_context_recv(subreq);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(c)) return;

	bind_auth_next_step(c);
}


static void bind_auth_recv_bindreply(struct tevent_req *subreq)
{
	struct composite_context *c =
		tevent_req_callback_data(subreq,
		struct composite_context);
	struct bind_auth_state *state =	talloc_get_type(c->private_data,
							struct bind_auth_state);
	struct dcecli_security *sec = &state->pipe->conn->security_state;

	ZERO_STRUCT(sec->tmp_auth_info);

	c->status = dcerpc_bind_recv(subreq);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(c)) return;

	if (!state->more_processing) {
		/* The first gensec_update has not requested a second run, so
		 * we're done here. */
		composite_done(c);
		return;
	}

	bind_auth_next_step(c);
}


static void dcerpc_bind_auth_gensec_done(struct tevent_req *subreq);

/**
   Bind to a DCE/RPC pipe, send async request
   @param mem_ctx TALLOC_CTX for the allocation of the composite_context
   @param p The dcerpc_pipe to bind (must already be connected)
   @param table The interface table to use (the DCE/RPC bind both selects and interface and authenticates)
   @param credentials The credentials of the account to connect with 
   @param auth_type Select the authentication scheme to use
   @param auth_level Chooses between unprotected (connect), signed or sealed
   @param service The service (used by Kerberos to select the service principal to contact)
   @retval A composite context describing the partial state of the bind
*/

struct composite_context *dcerpc_bind_auth_send(TALLOC_CTX *mem_ctx,
						struct dcerpc_pipe *p,
						const struct ndr_interface_table *table,
						struct cli_credentials *credentials,
						struct gensec_settings *gensec_settings,
						uint8_t auth_type, uint8_t auth_level,
						const char *service)
{
	struct composite_context *c;
	struct bind_auth_state *state;
	struct dcecli_security *sec;
	struct tevent_req *subreq;
	const char *target_principal = NULL;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, p->conn->event_ctx);
	if (c == NULL) return NULL;

	state = talloc(c, struct bind_auth_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	state->pipe = p;

	c->status = dcerpc_init_syntaxes(p, table,
					 &state->syntax,
					 &state->transfer_syntax);
	if (!composite_is_ok(c)) return c;

	sec = &p->conn->security_state;

	c->status = gensec_client_start(p, &sec->generic_state,
					gensec_settings);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(1, ("Failed to start GENSEC client mode: %s\n",
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return c;
	}

	c->status = gensec_set_credentials(sec->generic_state, credentials);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(1, ("Failed to set GENSEC client credentials: %s\n",
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return c;
	}

	c->status = gensec_set_target_hostname(sec->generic_state,
					       dcerpc_server_name(p));
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(1, ("Failed to set GENSEC target hostname: %s\n", 
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return c;
	}

	if (service != NULL) {
		c->status = gensec_set_target_service(sec->generic_state,
						      service);
		if (!NT_STATUS_IS_OK(c->status)) {
			DEBUG(1, ("Failed to set GENSEC target service: %s\n",
				  nt_errstr(c->status)));
			composite_error(c, c->status);
			return c;
		}
	}

	if (p->binding != NULL) {
		target_principal = dcerpc_binding_get_string_option(p->binding,
							"target_principal");
	}
	if (target_principal != NULL) {
		c->status = gensec_set_target_principal(sec->generic_state,
							target_principal);
		if (!NT_STATUS_IS_OK(c->status)) {
			DEBUG(1, ("Failed to set GENSEC target principal to %s: %s\n",
				  target_principal, nt_errstr(c->status)));
			composite_error(c, c->status);
			return c;
		}
	}

	c->status = gensec_start_mech_by_authtype(sec->generic_state,
						  auth_type, auth_level);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(1, ("Failed to start GENSEC client mechanism %s: %s\n",
			  gensec_get_name_by_authtype(sec->generic_state, auth_type),
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return c;
	}

	sec->auth_type = auth_type;
	sec->auth_level = auth_level,
	/*
	 * We use auth_context_id = 1 as some older
	 * Samba versions (<= 4.2.3) use that value hardcoded
	 * in a response.
	 */
	sec->auth_context_id = 1;

	state->out_auth_info = (struct dcerpc_auth) {
		.auth_type = sec->auth_type,
		.auth_level = sec->auth_level,
		.auth_context_id = sec->auth_context_id,
	};

	/* The status value here, from GENSEC is vital to the security
	 * of the system.  Even if the other end accepts, if GENSEC
	 * claims 'MORE_PROCESSING_REQUIRED' then you must keep
	 * feeding it blobs, or else the remote host/attacker might
	 * avoid mutal authentication requirements.
	 *
	 * Likewise, you must not feed GENSEC too much (after the OK),
	 * it doesn't like that either
	 */

	state->pipe->inhibit_timeout_processing = true;
	state->pipe->timed_out = false;

	subreq = gensec_update_send(state,
				    p->conn->event_ctx,
				    sec->generic_state,
				    data_blob_null);
	if (composite_nomem(subreq, c)) return c;
	tevent_req_set_callback(subreq, dcerpc_bind_auth_gensec_done, c);

	return c;
}

static void dcerpc_bind_auth_gensec_done(struct tevent_req *subreq)
{
	struct composite_context *c =
		tevent_req_callback_data(subreq,
		struct composite_context);
	struct bind_auth_state *state =
		talloc_get_type_abort(c->private_data,
		struct bind_auth_state);
	struct dcerpc_pipe *p = state->pipe;
	struct dcecli_security *sec = &p->conn->security_state;

	state->pipe->inhibit_timeout_processing = false;

	c->status = gensec_update_recv(subreq, state,
				       &state->out_auth_info.credentials);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(c->status) &&
	    !NT_STATUS_EQUAL(c->status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		composite_error(c, c->status);
		return;
	}

	state->more_processing = NT_STATUS_EQUAL(c->status,
						 NT_STATUS_MORE_PROCESSING_REQUIRED);

	if (state->out_auth_info.credentials.length == 0) {
		composite_done(c);
		return;
	}

	if (gensec_have_feature(sec->generic_state, GENSEC_FEATURE_SIGN_PKT_HEADER)) {
		if (sec->auth_level >= DCERPC_AUTH_LEVEL_PACKET) {
			state->pipe->conn->flags |= DCERPC_PROPOSE_HEADER_SIGNING;
		}
	}

	state->in_auth_info = (struct dcerpc_auth) {
		.auth_type = DCERPC_AUTH_TYPE_NONE,
	};
	sec->tmp_auth_info.in = &state->in_auth_info;
	sec->tmp_auth_info.mem = state;
	sec->tmp_auth_info.out = &state->out_auth_info;

	/* The first request always is a dcerpc_bind. The subsequent ones
	 * depend on gensec results */
	subreq = dcerpc_bind_send(state, p->conn->event_ctx, p,
				  &state->syntax, &state->transfer_syntax);
	if (composite_nomem(subreq, c)) return;
	tevent_req_set_callback(subreq, bind_auth_recv_bindreply, c);

	return;
}


/**
   Bind to a DCE/RPC pipe, receive result
   @param creq A composite context describing state of async call
   @retval NTSTATUS code
*/

NTSTATUS dcerpc_bind_auth_recv(struct composite_context *creq)
{
	NTSTATUS result = composite_wait(creq);
	struct bind_auth_state *state = talloc_get_type(creq->private_data,
							struct bind_auth_state);

	if (NT_STATUS_IS_OK(result)) {
		/*
		  after a successful authenticated bind the session
		  key reverts to the generic session key
		*/
		state->pipe->conn->security_state.session_key = dcecli_generic_session_key;
	}
	
	talloc_free(creq);
	return result;
}


/**
   Perform a GENSEC authenticated bind to a DCE/RPC pipe, sync
   @param p The dcerpc_pipe to bind (must already be connected)
   @param table The interface table to use (the DCE/RPC bind both selects and interface and authenticates)
   @param credentials The credentials of the account to connect with 
   @param auth_type Select the authentication scheme to use
   @param auth_level Chooses between unprotected (connect), signed or sealed
   @param service The service (used by Kerberos to select the service principal to contact)
   @retval NTSTATUS status code
*/

_PUBLIC_ NTSTATUS dcerpc_bind_auth(struct dcerpc_pipe *p,
			  const struct ndr_interface_table *table,
			  struct cli_credentials *credentials,
			  struct gensec_settings *gensec_settings,
			  uint8_t auth_type, uint8_t auth_level,
			  const char *service)
{
	struct composite_context *creq;
	creq = dcerpc_bind_auth_send(p, p, table, credentials, gensec_settings,
				     auth_type, auth_level, service);
	return dcerpc_bind_auth_recv(creq);
}
