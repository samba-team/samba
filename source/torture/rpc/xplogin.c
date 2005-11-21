/* 
   Unix SMB/CIFS implementation.

   Test code to simulate an XP logon.

   Copyright (C) Volker Lendecke 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/auth/credentials.h"
#include "libcli/raw/libcliraw.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_srvsvc.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/events/events.h"
#include "winbind/wb_async_helpers.h"

struct get_schannel_creds_state {
	struct composite_context *ctx;
	struct cli_credentials *wks_creds;
	struct dcerpc_pipe *p;
	struct netr_ServerReqChallenge r;

	struct creds_CredentialState *creds_state;
	struct netr_Credential netr_cred;
	uint32_t negotiate_flags;
	struct netr_ServerAuthenticate2 a;
};

static void get_schannel_creds_recv_bind(struct composite_context *ctx);
static void get_schannel_creds_recv_auth(struct rpc_request *req);
static void get_schannel_creds_recv_chal(struct rpc_request *req);
static void get_schannel_creds_recv_pipe(struct composite_context *ctx);

static struct composite_context *get_schannel_creds_send(TALLOC_CTX *mem_ctx,
							 struct cli_credentials *wks_creds,
							 struct smbcli_tree *tree,
							 struct event_context *ev)
{
	struct composite_context *result, *ctx;
	struct get_schannel_creds_state *state;

	result = talloc(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = ev;

	state = talloc(result, struct get_schannel_creds_state);
	if (state == NULL) goto failed;
	result->private_data = state;
	state->ctx = result;

	state->wks_creds = wks_creds;

	state->p = dcerpc_pipe_init(state, ev);
	if (state->p == NULL) goto failed;

	ctx = dcerpc_pipe_open_smb_send(state->p->conn, tree, "\\netlogon");
	if (ctx == NULL) goto failed;

	ctx->async.fn = get_schannel_creds_recv_pipe;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void get_schannel_creds_recv_pipe(struct composite_context *ctx)
{
	struct get_schannel_creds_state *state =
		talloc_get_type(ctx->async.private_data,
				struct get_schannel_creds_state);

	state->ctx->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	ctx = dcerpc_bind_auth_none_send(state, state->p, 
					 DCERPC_NETLOGON_UUID,
					 DCERPC_NETLOGON_VERSION);
	composite_continue(state->ctx, ctx, get_schannel_creds_recv_bind,
			   state);
}

static void get_schannel_creds_recv_bind(struct composite_context *ctx)
{
	struct get_schannel_creds_state *state =
		talloc_get_type(ctx->async.private_data,
				struct get_schannel_creds_state);
	struct rpc_request *req;

	state->ctx->status = dcerpc_bind_auth_none_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	state->r.in.computer_name =
		cli_credentials_get_workstation(state->wks_creds);
	state->r.in.server_name =
		talloc_asprintf(state, "\\\\%s",
				dcerpc_server_name(state->p));
	if (composite_nomem(state->r.in.server_name, state->ctx)) return;

	state->r.in.credentials = talloc(state, struct netr_Credential);
	if (composite_nomem(state->r.in.credentials, state->ctx)) return;

	state->r.out.credentials = talloc(state, struct netr_Credential);
	if (composite_nomem(state->r.out.credentials, state->ctx)) return;

	generate_random_buffer(state->r.in.credentials->data,
			       sizeof(state->r.in.credentials->data));

	req = dcerpc_netr_ServerReqChallenge_send(state->p, state, &state->r);
	composite_continue_rpc(state->ctx, req,
			       get_schannel_creds_recv_chal, state);
}

static void get_schannel_creds_recv_chal(struct rpc_request *req)
{
	struct get_schannel_creds_state *state =
		talloc_get_type(req->async.private,
				struct get_schannel_creds_state);
	const struct samr_Password *mach_pwd;

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->r.out.result;
	if (!composite_is_ok(state->ctx)) return;

	state->creds_state = talloc(state, struct creds_CredentialState);
	if (composite_nomem(state->creds_state, state->ctx)) return;

	mach_pwd = cli_credentials_get_nt_hash(state->wks_creds, state);
	if (composite_nomem(mach_pwd, state->ctx)) return;

	state->negotiate_flags = NETLOGON_NEG_AUTH2_FLAGS;

	creds_client_init(state->creds_state, state->r.in.credentials,
			  state->r.out.credentials, mach_pwd,
			  &state->netr_cred, state->negotiate_flags);

	state->a.in.server_name =
		talloc_reference(state, state->r.in.server_name);
	state->a.in.account_name =
		cli_credentials_get_username(state->wks_creds);
	state->a.in.secure_channel_type =
		cli_credentials_get_secure_channel_type(state->wks_creds);
	state->a.in.computer_name =
		cli_credentials_get_workstation(state->wks_creds);
	state->a.in.negotiate_flags = &state->negotiate_flags;
	state->a.out.negotiate_flags = &state->negotiate_flags;
	state->a.in.credentials = &state->netr_cred;
	state->a.out.credentials = &state->netr_cred;

	req = dcerpc_netr_ServerAuthenticate2_send(state->p, state, &state->a);
	composite_continue_rpc(state->ctx, req,
			       get_schannel_creds_recv_auth, state);
}

static void get_schannel_creds_recv_auth(struct rpc_request *req)
{
	struct get_schannel_creds_state *state =
		talloc_get_type(req->async.private,
				struct get_schannel_creds_state);

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->a.out.result;
	if (!composite_is_ok(state->ctx)) return;

	if (!creds_client_check(state->creds_state,
				state->a.out.credentials)) {
		DEBUG(5, ("Server got us invalid creds\n"));
		composite_error(state->ctx, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	cli_credentials_set_netlogon_creds(state->wks_creds,
					   state->creds_state);

	composite_done(state->ctx);
}

static NTSTATUS get_schannel_creds_recv(struct composite_context *c,
					TALLOC_CTX *mem_ctx,
					struct dcerpc_pipe **netlogon_pipe)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct get_schannel_creds_state *state =
			talloc_get_type(c->private_data,
					struct get_schannel_creds_state);
		*netlogon_pipe = talloc_steal(mem_ctx, state->p);
	}
	talloc_free(c);
	return status;
}

/*
  List trustdoms
*/

struct lsa_enumtrust_state {
	struct dcerpc_pipe *lsa_pipe;

	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_OpenPolicy2 o;
	struct lsa_Close c;
	uint32_t resume_handle;
	struct lsa_DomainList domains;
	struct lsa_EnumTrustDom e;
};

static void lsa_enumtrust_recvclose(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}

static void lsa_enumtrust_recvtrust(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct lsa_enumtrust_state *state =
		talloc_get_type(c->private_data, struct lsa_enumtrust_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->e.out.result;

	if (NT_STATUS_EQUAL(c->status, NT_STATUS_NO_MORE_ENTRIES)) {
		state->c.in.handle = &state->handle;
		state->c.out.handle = &state->handle;
		req = dcerpc_lsa_Close_send(state->lsa_pipe, state, &state->c);
		composite_continue_rpc(c, req, lsa_enumtrust_recvclose, c);
		return;
	}

	state->e.in.handle = &state->handle;
	state->e.in.resume_handle = &state->resume_handle;
	state->e.in.max_size = 1000;
	state->e.out.resume_handle = &state->resume_handle;
	ZERO_STRUCT(state->domains);
	state->e.out.domains = &state->domains;

	req = dcerpc_lsa_EnumTrustDom_send(state->lsa_pipe, state, &state->e);
	composite_continue_rpc(c, req, lsa_enumtrust_recvtrust, c);
}

static void lsa_enumtrust_recvpol(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct lsa_enumtrust_state *state =
		talloc_get_type(c->private_data, struct lsa_enumtrust_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->o.out.result;
	if (!composite_is_ok(c)) return;

	state->e.in.handle = &state->handle;
	state->resume_handle = 0;
	state->e.in.resume_handle = &state->resume_handle;
	state->e.in.max_size = 1000;
	state->e.out.resume_handle = &state->resume_handle;
	ZERO_STRUCT(state->domains);
	state->e.out.domains = &state->domains;

	req = dcerpc_lsa_EnumTrustDom_send(state->lsa_pipe, state, &state->e);
	composite_continue_rpc(c, req, lsa_enumtrust_recvtrust, c);
}

static void lsa_enumtrust_recvbind(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct lsa_enumtrust_state *state =
		talloc_get_type(c->private_data, struct lsa_enumtrust_state);
	struct rpc_request *req;

	c->status = dcerpc_bind_auth_none_recv(creq);
	if (!composite_is_ok(c)) return;

	ZERO_STRUCT(state->attr);
	state->o.in.attr = &state->attr;
	state->o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->o.in.system_name = talloc_asprintf(
		state, "\\\\%s", dcerpc_server_name(state->lsa_pipe));
	if (composite_nomem(state->o.in.system_name, c)) return;
	state->o.out.handle = &state->handle;

	req = dcerpc_lsa_OpenPolicy2_send(state->lsa_pipe, state, &state->o);
	composite_continue_rpc(c, req, lsa_enumtrust_recvpol, c);
}

static void lsa_enumtrust_recvsmb(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct lsa_enumtrust_state *state =
		talloc_get_type(c->private_data, struct lsa_enumtrust_state);

	c->status = dcerpc_pipe_open_smb_recv(creq);
	if (!composite_is_ok(c)) return;

	creq = dcerpc_bind_auth_none_send(state, state->lsa_pipe,
					  DCERPC_LSARPC_UUID,
					  DCERPC_LSARPC_VERSION);
	composite_continue(c, creq, lsa_enumtrust_recvbind, c);
}

static struct composite_context *lsa_enumtrust_send(TALLOC_CTX *mem_ctx,
						    struct smbcli_tree *tree)
{
	struct composite_context *c, *creq;
	struct lsa_enumtrust_state *state;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	state = talloc(c, struct lsa_enumtrust_state);
	if (state == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = tree->session->transport->socket->event.ctx;

	state->lsa_pipe = dcerpc_pipe_init(state, c->event_ctx);
	if (state->lsa_pipe == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq = dcerpc_pipe_open_smb_send(state->lsa_pipe->conn, tree,
					 "\\lsarpc");
	if (creq == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	composite_continue(c, creq, lsa_enumtrust_recvsmb, c);
	return c;

 failed:
	composite_trigger_error(c);
	return c;
}

static NTSTATUS lsa_enumtrust_recv(struct composite_context *creq)
{
	NTSTATUS result = composite_wait(creq);
	talloc_free(creq);
	return result;
}

/*
  Get us an schannel-bound netlogon pipe
*/

struct get_netlogon_schannel_state {
	struct cli_credentials *creds;
	struct dcerpc_pipe *pipe;
};

/*
  Receive the schannel'ed bind
*/

static void get_netlogon_schannel_bind(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);

	c->status = dcerpc_bind_auth_recv(creq);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}

/*
  Receive the pipe
*/

static void get_netlogon_schannel_pipe(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct get_netlogon_schannel_state *state =
		talloc_get_type(c->private_data,
				struct get_netlogon_schannel_state);

	c->status = dcerpc_pipe_open_smb_recv(creq);
	if (!composite_is_ok(c)) return;

	state->pipe->conn->flags |= (DCERPC_SIGN | DCERPC_SEAL);
	creq = dcerpc_bind_auth_send(state, state->pipe,
				     DCERPC_NETLOGON_UUID,
				     DCERPC_NETLOGON_VERSION, 
				     state->creds,
				     DCERPC_AUTH_TYPE_SCHANNEL,
				     NULL);
	composite_continue(c, creq, get_netlogon_schannel_bind, c);
	
}

static struct composite_context *get_netlogon_schannel_send(TALLOC_CTX *mem_ctx,
							    struct smbcli_tree *tree,
							    struct cli_credentials *creds)
{
	struct composite_context *c, *creq;
	struct get_netlogon_schannel_state *state;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	state = talloc(c, struct get_netlogon_schannel_state);
	if (state == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = tree->session->transport->socket->event.ctx;

	state->pipe = dcerpc_pipe_init(state, c->event_ctx);
	if (state->pipe == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	state->creds = creds;

	creq = dcerpc_pipe_open_smb_send(state->pipe->conn, tree,
					 "\\netlogon");
	if (creq == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}
	creq->async.fn = get_netlogon_schannel_pipe;
	creq->async.private_data = c;
	return c;

 failed:
	composite_trigger_error(c);
	return c;
}

static NTSTATUS get_netlogon_schannel_recv(struct composite_context *c,
					   TALLOC_CTX *mem_ctx,
					   struct dcerpc_pipe **pipe)
{
	NTSTATUS result = composite_wait(c);
	if (NT_STATUS_IS_OK(result)) {
		struct get_netlogon_schannel_state *state =
			talloc_get_type(c->private_data,
					struct get_netlogon_schannel_state);
		*pipe = talloc_steal(mem_ctx, state->pipe);
	}
	return result;
}

/*
  lsa_lookupsids, given just an smb tree
*/

struct lookupsids_state {
	struct dcerpc_pipe *lsa_pipe;
	int num_sids;
	const struct dom_sid **sids;
	struct wb_sid_object **names;

	struct policy_handle handle;
	struct lsa_ObjectAttribute a;
	struct lsa_OpenPolicy2 o;
	struct lsa_Close c;
};

static void lookupsids_recv_close(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct lookupsids_state *state =
		talloc_get_type(c->private_data,
				struct lookupsids_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->c.out.result;
	if (!composite_is_ok(c)) return;

	composite_done(c);
}

static void lookupsids_recv_names(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct lookupsids_state *state =
		talloc_get_type(c->private_data,
				struct lookupsids_state);
	struct rpc_request *req;

	c->status = wb_lsa_lookupsids_recv(creq, state, &state->names);
	if (!composite_is_ok(c)) return;

	state->c.in.handle = &state->handle;
	state->c.out.handle = &state->handle;

	req = dcerpc_lsa_Close_send(state->lsa_pipe, state, &state->c);
	composite_continue_rpc(c, req, lookupsids_recv_close, c);
}
	
static void lookupsids_recv_pol(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct lookupsids_state *state =
		talloc_get_type(c->private_data,
				struct lookupsids_state);
	struct composite_context *creq;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->o.out.result;
	if (!composite_is_ok(c)) return;

	creq = wb_lsa_lookupsids_send(state, state->lsa_pipe, &state->handle,
				      state->num_sids, state->sids);
	composite_continue(c, creq, lookupsids_recv_names, c);
}

static void lookupsids_recv_bind(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct lookupsids_state *state =
		talloc_get_type(c->private_data,
				struct lookupsids_state);
	struct rpc_request *req;

	c->status = dcerpc_bind_auth_none_recv(creq);
	if (!composite_is_ok(c)) return;

	ZERO_STRUCT(state->a);
	ZERO_STRUCT(state->handle);

	state->o.in.attr = &state->a;
	state->o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->o.out.handle = &state->handle;
	state->o.in.system_name = 
		talloc_asprintf(state, "\\\\%s",
				dcerpc_server_name(state->lsa_pipe));
	if (composite_nomem(state->o.in.system_name, c)) return;

	req = dcerpc_lsa_OpenPolicy2_send(state->lsa_pipe, state,
					  &state->o);
	composite_continue_rpc(c, req, lookupsids_recv_pol, c);
}

static void lookupsids_recv_pipe(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct lookupsids_state *state =
		talloc_get_type(c->private_data,
				struct lookupsids_state);

	c->status = dcerpc_pipe_open_smb_recv(creq);
	if (!composite_is_ok(c)) return;

	creq = dcerpc_bind_auth_none_send(state, state->lsa_pipe,
					  DCERPC_LSARPC_UUID,
					  DCERPC_LSARPC_VERSION);
	composite_continue(c, creq, lookupsids_recv_bind, c);
}

static struct composite_context *lookupsids_send(TALLOC_CTX *mem_ctx,
						 struct smbcli_tree *tree,
						 int num_sids,
						 const struct dom_sid **sids)
{
	struct composite_context *c, *creq;
	struct lookupsids_state *state;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	state = talloc(c, struct lookupsids_state);
	if (state == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = tree->session->transport->socket->event.ctx;

	state->num_sids = num_sids;
	state->sids = talloc_reference(state, sids);

	state->lsa_pipe = dcerpc_pipe_init(state, c->event_ctx);
	if (state->lsa_pipe == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq = dcerpc_pipe_open_smb_send(state->lsa_pipe->conn, tree,
					 "\\lsarpc");
	if (creq == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq->async.fn = lookupsids_recv_pipe;
	creq->async.private_data = c;
	return c;

 failed:
	composite_trigger_error(c);
	return c;
}

static NTSTATUS lookupsids_recv(struct composite_context *creq,
				TALLOC_CTX *mem_ctx,
				int *num_names,
				struct wb_sid_object ***names)
{
	NTSTATUS result = composite_wait(creq);
	if (NT_STATUS_IS_OK(result)) {
		struct lookupsids_state *state =
			talloc_get_type(creq->private_data,
					struct lookupsids_state);
		*num_names = state->num_sids;
		*names = talloc_steal(mem_ctx, state->names);
	}
	talloc_free(creq);
	return result;
}

/*
  Get me a samr pipe and a domain handle on the main domain (not the builtin
  one)
*/

struct get_samr_domain_state {
	struct dcerpc_pipe *samr_pipe;
	struct policy_handle connect_handle;
	struct policy_handle domain_handle;
	struct policy_handle group_handle;
	struct samr_Connect2 conn;

	uint32_t resume_handle;
	struct samr_EnumDomains e;
	struct samr_LookupDomain l;
	struct samr_OpenDomain o;
	struct samr_Close c;
};

static void get_samr_domain_recv_connclose(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct get_samr_domain_state *state =
		talloc_get_type(c->private_data,
				struct get_samr_domain_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->c.out.result;
	if (!composite_is_ok(c)) return;

	composite_done(c);
}

static void get_samr_domain_recv_domopen(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct get_samr_domain_state *state =
		talloc_get_type(c->private_data,
				struct get_samr_domain_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->o.out.result;
	if (!composite_is_ok(c)) return;

	state->c.in.handle = &state->connect_handle;
	state->c.out.handle = &state->connect_handle;

	req = dcerpc_samr_Close_send(state->samr_pipe, state,
				     &state->c);
	composite_continue_rpc(c, req, get_samr_domain_recv_connclose, c);
}

static void get_samr_domain_recv_domsid(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct get_samr_domain_state *state =
		talloc_get_type(c->private_data,
				struct get_samr_domain_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->l.out.result;
	if (!composite_is_ok(c)) return;

	state->o.in.connect_handle = &state->connect_handle;
	state->o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->o.in.sid = state->l.out.sid;
	state->o.out.domain_handle = &state->domain_handle;

	req = dcerpc_samr_OpenDomain_send(state->samr_pipe, state,
					  &state->o);
	composite_continue_rpc(c, req, get_samr_domain_recv_domopen, c);
}

static void get_samr_domain_recv_domains(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct get_samr_domain_state *state =
		talloc_get_type(c->private_data,
				struct get_samr_domain_state);
	int entry = 0;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->e.out.result;
	if (!composite_is_ok(c)) return;

	if ((state->e.out.num_entries != 2) ||
	    (state->e.out.sam->count != 2)) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	if (strcasecmp(state->e.out.sam->entries[0].name.string,
		       "Builtin") == 0) {
		entry = 1;
	}

	state->l.in.connect_handle = &state->connect_handle;
	state->l.in.domain_name = &state->e.out.sam->entries[entry].name;

	req = dcerpc_samr_LookupDomain_send(state->samr_pipe, state,
					    &state->l);

	composite_continue_rpc(c, req, get_samr_domain_recv_domsid, c);
}

static void get_samr_domain_recv_conn(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct get_samr_domain_state *state =
		talloc_get_type(c->private_data,
				struct get_samr_domain_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->conn.out.result;
	if (!composite_is_ok(c)) return;

	state->resume_handle = 0;
	state->e.in.connect_handle = &state->connect_handle;
	state->e.in.resume_handle = &state->resume_handle;
	state->e.in.buf_size = 8192;
	state->e.out.resume_handle = &state->resume_handle;

	req = dcerpc_samr_EnumDomains_send(state->samr_pipe, state,
					   &state->e);
	composite_continue_rpc(c, req, get_samr_domain_recv_domains, c);
}

static void get_samr_domain_recv_bind(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct get_samr_domain_state *state =
		talloc_get_type(c->private_data,
				struct get_samr_domain_state);
	struct rpc_request *req;

	c->status = dcerpc_bind_auth_none_recv(creq);
	if (!composite_is_ok(c)) return;

	state->conn.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->conn.in.system_name = talloc_asprintf(
		state, "\\\\%s", dcerpc_server_name(state->samr_pipe));
	if (composite_nomem(state->conn.in.system_name, c)) return;
	state->conn.out.connect_handle = &state->connect_handle;

	req = dcerpc_samr_Connect2_send(state->samr_pipe, state,
					&state->conn);

	composite_continue_rpc(c, req, get_samr_domain_recv_conn, c);
}

static void get_samr_domain_recv_pipe(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct get_samr_domain_state *state =
		talloc_get_type(c->private_data,
				struct get_samr_domain_state);

	c->status = dcerpc_pipe_open_smb_recv(creq);
	if (!composite_is_ok(c)) return;

	creq = dcerpc_bind_auth_none_send(state, state->samr_pipe,
					  DCERPC_SAMR_UUID,
					  DCERPC_SAMR_VERSION);
	composite_continue(c, creq, get_samr_domain_recv_bind, c);
}

static struct composite_context *get_samr_domain_send(TALLOC_CTX *mem_ctx,
						      struct smbcli_tree *tree)
{
	struct composite_context *c, *creq;
	struct get_samr_domain_state *state;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	state = talloc(c, struct get_samr_domain_state);
	if (state == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = tree->session->transport->socket->event.ctx;

	state->samr_pipe = dcerpc_pipe_init(state, c->event_ctx);
	if (state->samr_pipe == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq = dcerpc_pipe_open_smb_send(state->samr_pipe->conn, tree,
					 "\\samr");
	if (creq == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq->async.fn = get_samr_domain_recv_pipe;
	creq->async.private_data = c;
	return c;

 failed:
	composite_trigger_error(c);
	return c;
}

static NTSTATUS get_samr_domain_recv(struct composite_context *creq,
				     TALLOC_CTX *mem_ctx,
				     struct dcerpc_pipe **pipe,
				     struct policy_handle *handle,
				     struct dom_sid **domain_sid)
{
	NTSTATUS result = composite_wait(creq);
	if (NT_STATUS_IS_OK(result)) {
		struct get_samr_domain_state *state =
			talloc_get_type(creq->private_data,
					struct get_samr_domain_state);
		*pipe = talloc_steal(mem_ctx, state->samr_pipe);
		*handle = state->domain_handle;
		*domain_sid = talloc_steal(mem_ctx, state->l.out.sid);
	}
	talloc_free(creq);
	return result;
}

/*
  Get us the names & types of the members of the domain admins group.
  Yes, I've got a workstation setup that does it. Twice. -- VL
*/

struct domadmins_state {
	struct dcerpc_pipe *samr_pipe;

	struct dom_sid *domain_sid;
	struct policy_handle domain_handle;
	struct policy_handle group_handle;

	uint32_t resume_handle;
	struct samr_Close c;
	struct samr_OpenGroup og;
	struct samr_QueryGroupMember m;

	int num_names;
	struct wb_sid_object **names;
};

static void domadmins_recv_domclose(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct domadmins_state *state =
		talloc_get_type(c->private_data,
				struct domadmins_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->c.out.result;
	if (!composite_is_ok(c)) return;

	composite_done(c);
}

static void domadmins_recv_groupclose(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct domadmins_state *state =
		talloc_get_type(c->private_data,
				struct domadmins_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->c.out.result;
	if (!composite_is_ok(c)) return;

	state->c.in.handle = &state->domain_handle;
	state->c.out.handle = &state->domain_handle;
	req = dcerpc_samr_Close_send(state->samr_pipe, state,
				     &state->c);
	composite_continue_rpc(c, req, domadmins_recv_domclose, c);
}

static void domadmins_recv_names(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct domadmins_state *state =
		talloc_get_type(c->private_data,
				struct domadmins_state);
	struct rpc_request *req;

	c->status = lookupsids_recv(creq, state, &state->num_names,
				    &state->names);
	if (!composite_is_ok(c)) return;

	state->c.in.handle = &state->group_handle;
	state->c.out.handle = &state->group_handle;
	req = dcerpc_samr_Close_send(state->samr_pipe, state,
				     &state->c);
	composite_continue_rpc(c, req, domadmins_recv_groupclose, c);
}

static void domadmins_recv_members(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct domadmins_state *state =
		talloc_get_type(c->private_data,
				struct domadmins_state);
	struct composite_context *creq;
	const struct dom_sid **sids;
	int i;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->m.out.result;
	if (!composite_is_ok(c)) return;

	state->num_names = state->m.out.rids->count;
	sids = talloc_array(state, const struct dom_sid *, state->num_names);
	if (composite_nomem(sids, c)) return;

	for (i=0; i<state->num_names; i++) {
		sids[i] = dom_sid_add_rid(sids, state->domain_sid,
					  state->m.out.rids->rids[i]);
		if (composite_nomem(sids[i], c)) return;
	}

	creq = lookupsids_send(state, dcerpc_smb_tree(state->samr_pipe->conn),
			       state->num_names, sids);
	composite_continue(c, creq, domadmins_recv_names, c);
}

static void domadmins_recv_group(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct domadmins_state *state =
		talloc_get_type(c->private_data,
				struct domadmins_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->og.out.result;
	if (!composite_is_ok(c)) return;

	state->m.in.group_handle = &state->group_handle;

	req = dcerpc_samr_QueryGroupMember_send(state->samr_pipe, state,
						&state->m);
	composite_continue_rpc(c, req, domadmins_recv_members, c);
}

static void domadmins_recv_domain(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct domadmins_state *state =
		talloc_get_type(c->private_data,
				struct domadmins_state);
	struct rpc_request *req;

	c->status = get_samr_domain_recv(creq, state, &state->samr_pipe,
					 &state->domain_handle,
					 &state->domain_sid);
	if (!composite_is_ok(c)) return;

	state->og.in.domain_handle = &state->domain_handle;
	state->og.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->og.in.rid = 512;
	state->og.out.group_handle = &state->group_handle;

	req = dcerpc_samr_OpenGroup_send(state->samr_pipe, state,
					 &state->og);
	composite_continue_rpc(c, req, domadmins_recv_group, c);
}

static struct composite_context *domadmins_send(TALLOC_CTX *mem_ctx,
						struct smbcli_tree *tree)
{
	struct composite_context *c, *creq;
	struct domadmins_state *state;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	state = talloc(c, struct domadmins_state);
	if (state == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = tree->session->transport->socket->event.ctx;

	creq = get_samr_domain_send(state, tree);
	if (creq == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq->async.fn = domadmins_recv_domain;
	creq->async.private_data = c;
	return c;

 failed:
	composite_trigger_error(c);
	return c;
}

static NTSTATUS domadmins_recv(struct composite_context *creq,
			       TALLOC_CTX *mem_ctx,
			       int *num_names, struct wb_sid_object ***names)
{
	NTSTATUS result = composite_wait(creq);
	if (NT_STATUS_IS_OK(result)) {
		struct domadmins_state *state =
			talloc_get_type(creq->private_data,
					struct domadmins_state);
		*num_names = state->num_names;
		*names = talloc_steal(mem_ctx, state->names);
	}
	talloc_free(creq);
	return result;
}

/*
  Get us the groups a user is in
*/

struct memberships_state {
	const char *username;
	struct dcerpc_pipe *samr_pipe;
	struct dom_sid *domain_sid;
	struct policy_handle domain_handle;
	struct policy_handle user_handle;

	struct lsa_String name;
	struct samr_LookupNames l;

	struct samr_OpenUser o;
	struct samr_Close c;
	struct samr_GetGroupsForUser g;

	uint32_t *rids;
	struct samr_LookupRids r;
};

static void memberships_recv_closedom(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct memberships_state *state =
		talloc_get_type(c->private_data,
				struct memberships_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->c.out.result;
	if (!composite_is_ok(c)) return;

	composite_done(c);
}

static void memberships_recv_closeuser(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct memberships_state *state =
		talloc_get_type(c->private_data,
				struct memberships_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->c.out.result;
	if (!composite_is_ok(c)) return;

	state->c.in.handle = &state->domain_handle;
	state->c.out.handle = &state->domain_handle;

	req = dcerpc_samr_Close_send(state->samr_pipe, state,
				     &state->c);

	composite_continue_rpc(c, req, memberships_recv_closedom, c);
}

static void memberships_recv_names(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct memberships_state *state =
		talloc_get_type(c->private_data,
				struct memberships_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->r.out.result;
	if (!composite_is_ok(c)) return;

	state->c.in.handle = &state->user_handle;
	state->c.out.handle = &state->user_handle;

	req = dcerpc_samr_Close_send(state->samr_pipe, state,
				     &state->c);

	composite_continue_rpc(c, req, memberships_recv_closeuser, c);
}

static void memberships_recv_mem(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct memberships_state *state =
		talloc_get_type(c->private_data,
				struct memberships_state);
	int i, num_rids;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->g.out.result;
	if (!composite_is_ok(c)) return;

	num_rids = state->g.out.rids->count;
	state->rids = talloc_array(state, uint32_t, num_rids);
	if (composite_nomem(state->rids, c)) return;

	for (i=0; i<num_rids; i++) {
		state->rids[i] = state->g.out.rids->rids[i].rid;
	}

	state->r.in.domain_handle = &state->domain_handle;
	state->r.in.num_rids = state->g.out.rids->count;
	state->r.in.rids = state->rids;

	req = dcerpc_samr_LookupRids_send(state->samr_pipe, state,
					  &state->r);
	composite_continue_rpc(c, req, memberships_recv_names, c);
}

static void memberships_recv_user(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct memberships_state *state =
		talloc_get_type(c->private_data,
				struct memberships_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->o.out.result;
	if (!composite_is_ok(c)) return;

	state->g.in.user_handle = &state->user_handle;

	req = dcerpc_samr_GetGroupsForUser_send(state->samr_pipe, state,
						&state->g);

	composite_continue_rpc(c, req, memberships_recv_mem, c);
}

static void memberships_recv_rid(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct memberships_state *state =
		talloc_get_type(c->private_data,
				struct memberships_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	c->status = state->l.out.result;
	if (!composite_is_ok(c)) return;

	if (state->l.out.rids.count != 1) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	state->o.in.domain_handle = &state->domain_handle;
	state->o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->o.in.rid = state->l.out.rids.ids[0];
	state->o.out.user_handle = &state->user_handle;

	req = dcerpc_samr_OpenUser_send(state->samr_pipe, state,
					&state->o);

	composite_continue_rpc(c, req, memberships_recv_user, c);
}

static void memberships_recv_domain(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct memberships_state *state =
		talloc_get_type(c->private_data,
				struct memberships_state);
	struct rpc_request *req;

	c->status = get_samr_domain_recv(creq, state, &state->samr_pipe,
					 &state->domain_handle,
					 &state->domain_sid);
	if (!composite_is_ok(c)) return;

	state->l.in.domain_handle = &state->domain_handle;
	state->l.in.num_names = 1;
	state->name.string = state->username;
	state->l.in.names = &state->name;

	req = dcerpc_samr_LookupNames_send(state->samr_pipe, state,
					   &state->l);

	composite_continue_rpc(c, req, memberships_recv_rid, c);
}

static struct composite_context *memberships_send(TALLOC_CTX *mem_ctx,
						  struct smbcli_tree *tree,
						  const char *username)
{
	struct composite_context *c, *creq;
	struct memberships_state *state;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	state = talloc(c, struct memberships_state);
	if (state == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = tree->session->transport->socket->event.ctx;

	state->username = talloc_strdup(state, username);
	if (state->username == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq = get_samr_domain_send(state, tree);
	if (creq == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	creq->async.fn = memberships_recv_domain;
	creq->async.private_data = c;
	return c;

 failed:
	composite_trigger_error(c);
	return c;
}

static NTSTATUS memberships_recv(struct composite_context *creq)
{
	NTSTATUS result = composite_wait(creq);
	talloc_free(creq);
	return result;
}

struct xp_login_state {
	struct timeval timeout;

	const char *dc_name;
	const char *dc_ip;
	const char *wks_domain;
	const char *wks_name;
	const char *wks_pwd;
	const char *user_domain;
	const char *user_name;
	const char *user_pwd;

	int num_sids;
	const struct dom_sid **sids;

	int num_names;
	struct wb_sid_object **names;

	int num_domadmins;
	struct wb_sid_object **domadmins;

	struct smb_composite_connect conn;
	struct cli_credentials *wks_creds;
	struct dcerpc_pipe *netlogon_pipe;
	struct dcerpc_pipe *netlogon_schannel_pipe;
	struct dcerpc_pipe *lsa_pipe;

        struct creds_CredentialState *creds_state;
        struct netr_Authenticator auth, auth2;
        struct netr_NetworkInfo ninfo;
        struct netr_LogonSamLogon r;
};

static void xp_login_recv_conn(struct composite_context *ctx);
static void xp_login_start(struct event_context *ev, struct timed_event *te,
			   struct timeval tv, void *p);
static void xp_login_recv_auth2(struct composite_context *ctx);
static void xp_login_recv_trusts(struct composite_context *creq);
static void xp_login_recv_schannel(struct composite_context *creq);
static void xp_login_recv_samlogon(struct rpc_request *req);
static void xp_login_recv_names(struct composite_context *creq);
static void xp_login_recv_domadmins(struct composite_context *creq);
static void xp_login_recv_memberships(struct composite_context *creq);

static struct composite_context *xp_login_send(TALLOC_CTX *mem_ctx,
					       struct timeval timeout,
					       struct event_context *event_ctx,
					       const char *dc_name,
					       const char *dc_ip,
					       const char *wks_domain,
					       const char *wks_name,
					       const char *wks_pwd,
					       const char *user_domain,
					       const char *user_name,
					       const char *user_pwd)
{
	struct composite_context *c;
	struct xp_login_state *state;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	state = talloc(c, struct xp_login_state);
	if (state == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = state;
	c->event_ctx = event_ctx;

	state->timeout = timeout;
	state->dc_name = dc_name;
	state->dc_ip = dc_ip;
	state->wks_domain = wks_domain;
	state->wks_name = wks_name;
	state->wks_pwd = wks_pwd;
	state->user_domain = user_domain;
	state->user_name = user_name;
	state->user_pwd = user_pwd;

	state->wks_creds = cli_credentials_init(state);
	if (state->wks_creds == NULL) goto failed;

	cli_credentials_set_conf(state->wks_creds);
	cli_credentials_set_domain(state->wks_creds, wks_domain,
				   CRED_SPECIFIED);
	cli_credentials_set_username(state->wks_creds,
				     talloc_asprintf(state, "%s$", wks_name),
				     CRED_SPECIFIED);
	cli_credentials_set_password(state->wks_creds, wks_pwd,
				     CRED_SPECIFIED);
	cli_credentials_set_secure_channel_type(state->wks_creds,
						SEC_CHAN_WKSTA);

	state->conn.in.dest_host = dc_name;
	state->conn.in.port = 0;
	state->conn.in.called_name = dc_name;
	state->conn.in.service = "IPC$";
	state->conn.in.service_type = "IPC";
	state->conn.in.credentials = cli_credentials_init(state);
	if (state->conn.in.credentials == NULL) goto failed;
	cli_credentials_set_conf(state->conn.in.credentials);
	cli_credentials_set_anonymous(state->conn.in.credentials);
	state->conn.in.fallback_to_anonymous = False;
	state->conn.in.workgroup = wks_domain;

	event_add_timed(c->event_ctx, state,
			timeval_current_ofs(state->timeout.tv_sec,
					    state->timeout.tv_usec),
			xp_login_start, c);
	return c;

 failed:
	composite_trigger_error(c);
	return c;
}

static void xp_login_start(struct event_context *ev, struct timed_event *te,
			   struct timeval tv, void *p)
{
	struct composite_context *c =
		talloc_get_type(p, struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);
	struct composite_context *creq;

	creq = smb_composite_connect_send(&state->conn, state, c->event_ctx);
	composite_continue(c, creq, xp_login_recv_conn, c);
}

static void xp_login_recv_conn(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);

	c->status = smb_composite_connect_recv(creq, state);
	if (!composite_is_ok(c)) return;

	creq = get_schannel_creds_send(state, state->wks_creds,
				       state->conn.out.tree, c->event_ctx);
	composite_continue(c, creq, xp_login_recv_auth2, c);
}

static void xp_login_recv_auth2(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);

	c->status = get_schannel_creds_recv(creq, state,
					    &state->netlogon_pipe);
	if (!composite_is_ok(c)) return;

	creq = lsa_enumtrust_send(state,
				  dcerpc_smb_tree(state->netlogon_pipe->conn));
	composite_continue(c, creq, xp_login_recv_trusts, c);
}

static void xp_login_recv_trusts(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);

	c->status = lsa_enumtrust_recv(creq);
	if (!composite_is_ok(c)) return;

	creq = get_netlogon_schannel_send(
		state, dcerpc_smb_tree(state->netlogon_pipe->conn),
		state->wks_creds);

	composite_continue(c, creq, xp_login_recv_schannel, c);
}

static void xp_login_recv_schannel(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);
	struct rpc_request *req;

	struct cli_credentials *credentials;
	const char *workstation;
	DATA_BLOB chal, nt_resp, lm_resp, names_blob;
	int flags = CLI_CRED_NTLM_AUTH;

	c->status = get_netlogon_schannel_recv(creq, state,
					       &state->netlogon_schannel_pipe);
	if (!composite_is_ok(c)) return;

	if (lp_client_lanman_auth()) {
		flags |= CLI_CRED_LANMAN_AUTH;
	}

	if (lp_client_ntlmv2_auth()) {
		flags |= CLI_CRED_NTLMv2_AUTH;
	}

	credentials = cli_credentials_init(state);
	if (composite_nomem(credentials, c)) return;

	cli_credentials_set_conf(credentials);
	cli_credentials_set_workstation(credentials, state->wks_name, CRED_SPECIFIED);
	cli_credentials_set_domain(credentials, state->user_domain, CRED_SPECIFIED);
	cli_credentials_set_username(credentials, state->user_name, CRED_SPECIFIED);

	cli_credentials_set_password(credentials, state->user_pwd, CRED_SPECIFIED);

	chal = data_blob_talloc(state, NULL, 8);
	if (composite_nomem(chal.data, c)) return;

	generate_random_buffer(chal.data, chal.length);
	cli_credentials_get_ntlm_username_domain(credentials, state,
						 &state->user_name,
						 &state->user_domain);
	/* for best compatability with multiple vitual netbios names
	 * on the host, this should be generated from the
	 * cli_credentials associated with the machine account */
	workstation = cli_credentials_get_workstation(credentials);

	names_blob = NTLMv2_generate_names_blob(
		state,
		cli_credentials_get_workstation(credentials), 
		cli_credentials_get_domain(credentials));

	c->status = cli_credentials_get_ntlm_response(
		credentials, state, &flags, chal, names_blob,
		&lm_resp, &nt_resp, NULL, NULL);
	if (!composite_is_ok(c)) return;

	state->creds_state =
		cli_credentials_get_netlogon_creds(state->wks_creds);
	creds_client_authenticator(state->creds_state, &state->auth);

	state->ninfo.identity_info.account_name.string = state->user_name;
	state->ninfo.identity_info.domain_name.string =  state->user_domain;
	state->ninfo.identity_info.parameter_control = 0;
	state->ninfo.identity_info.logon_id_low = 0;
	state->ninfo.identity_info.logon_id_high = 0;
	state->ninfo.identity_info.workstation.string = state->wks_name;
	state->ninfo.nt.length = nt_resp.length;
	state->ninfo.nt.data = nt_resp.data;
	state->ninfo.lm.length = lm_resp.length;
	state->ninfo.lm.data = lm_resp.data;

	memcpy(state->ninfo.challenge, chal.data,
	       sizeof(state->ninfo.challenge));

	state->r.in.server_name = talloc_asprintf(
		state, "\\\\%s", dcerpc_server_name(state->netlogon_pipe));
	if (composite_nomem(state->r.in.server_name, c)) return;

	ZERO_STRUCT(state->auth2);

	state->r.in.workstation =
		cli_credentials_get_workstation(state->wks_creds);
	state->r.in.credential = &state->auth;
	state->r.in.return_authenticator = &state->auth2;
	state->r.in.logon_level = 2;
	state->r.in.validation_level = 3;
	state->r.in.logon.network = &state->ninfo;
	state->r.out.return_authenticator = NULL;

	req = dcerpc_netr_LogonSamLogon_send(state->netlogon_schannel_pipe,
					     state, &state->r);
	composite_continue_rpc(c, req, xp_login_recv_samlogon, c);
}

static void xp_login_recv_samlogon(struct rpc_request *req)
{
	struct composite_context *c =
		talloc_get_type(req->async.private,
				struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);
	struct composite_context *creq;
	struct netr_SamInfo3 *sam3;
	int i;

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	if ((state->r.out.return_authenticator == NULL) ||
	    (!creds_client_check(state->creds_state,
				 &state->r.out.return_authenticator->cred))) {
		DEBUG(0, ("Credentials check failed!\n"));
		composite_error(c, NT_STATUS_ACCESS_DENIED);
		return;
	}

	c->status = state->r.out.result;
	if (!composite_is_ok(c)) return;

	sam3 = state->r.out.validation.sam3;

	state->num_sids = sam3->base.groups.count + 1;
	state->sids = talloc_array(state, const struct dom_sid *, state->num_sids);
	if (composite_nomem(state->sids, c)) return;

	state->sids[0] = dom_sid_add_rid(state->sids, sam3->base.domain_sid,
					 sam3->base.rid);
	if (composite_nomem(state->sids[0], c)) return;

	for (i=0; i<sam3->base.groups.count; i++) {
		state->sids[i+1] = dom_sid_add_rid(state->sids,
						   sam3->base.domain_sid,
						   sam3->base.groups.rids[i].rid);
		if (composite_nomem(state->sids[i+1], c)) return;
	}

	creq = lookupsids_send(state, dcerpc_smb_tree(state->netlogon_pipe->conn),
			       state->num_sids, state->sids);
	composite_continue(c, creq, xp_login_recv_names, c);
}

static void xp_login_recv_names(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);

	c->status = lookupsids_recv(creq, state, &state->num_names,
				    &state->names);
	if (!composite_is_ok(c)) return;

	creq = domadmins_send(state,
			      dcerpc_smb_tree(state->netlogon_pipe->conn));
	composite_continue(c, creq, xp_login_recv_domadmins, c);
}
	
static void xp_login_recv_domadmins(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct xp_login_state *state =
		talloc_get_type(c->private_data, struct xp_login_state);

	c->status = domadmins_recv(creq, state, &state->num_domadmins,
				   &state->domadmins);
	if (!composite_is_ok(c)) return;

	creq = memberships_send(state,
				dcerpc_smb_tree(state->netlogon_pipe->conn),
				state->user_name);
	composite_continue(c, creq, xp_login_recv_memberships, c);
}

static void xp_login_recv_memberships(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);

	c->status = memberships_recv(creq);
				
	if (!composite_is_ok(c)) return;

	composite_done(c);
}

static NTSTATUS xp_login_recv(struct composite_context *ctx)
{
	NTSTATUS status = composite_wait(ctx);
	talloc_free(ctx);
	return status;
}

static void xp_login_done(struct composite_context *ctx)
{
	int *count = (int *)(ctx->async.private_data);
	*count += 1;
}

BOOL torture_rpc_login(void)
{
	TALLOC_CTX *mem_ctx;
	struct event_context *event_ctx;
	BOOL result = False;
	extern int torture_numops;
	int i, num_events;
	int num_finished = 0;
	struct composite_context **ctx;

	mem_ctx = talloc_init("rpc_login");
	if (mem_ctx == NULL) {
		DEBUG(0, ("talloc_init failed\n"));
		return False;
	}

	event_ctx = event_context_init(mem_ctx);
	if (event_ctx == NULL) {
		DEBUG(0, ("event_context_init failed\n"));
		goto done;
	}

	ctx = talloc_array(mem_ctx, struct composite_context *,
			   torture_numops);
	if (ctx == NULL) {
		DEBUG(0, ("talloc_array failed\n"));
		goto done;
	}

	for (i=0; i<torture_numops; i++) {
		ctx[i] = xp_login_send(
			mem_ctx, timeval_set(0, i*lp_parm_int(-1, "torture",
							      "timeout", 0)),
			event_ctx,
			lp_parm_string(-1, "torture", "host"),
			lp_parm_string(-1, "torture", "host"),
			lp_workgroup(),
			lp_netbios_name(), "5,eEp_D2",
			lp_workgroup(), "vl", "asdf");
		if (ctx[i] == NULL) {
			DEBUG(0, ("xp_login_send failed\n"));
			goto done;
		}
		ctx[i]->async.fn = xp_login_done;
		ctx[i]->async.private_data = &num_finished;
	}

	num_events = 0;
	while (num_finished < torture_numops) {
		event_loop_once(event_ctx);
		num_events += 1;
	}

	DEBUG(0, ("num_events = %d\n", num_events));

	for (i=0; i<torture_numops; i++) {
		DEBUG(0, ("login %3d returned %s\n", i,
			  nt_errstr(xp_login_recv(ctx[i]))));
	}

	result = True;
 done:
	talloc_free(mem_ctx);
	return result;
}
