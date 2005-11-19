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
	struct rpc_request *req;

	state->ctx->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	state->ctx->status = dcerpc_bind_auth_none(state->p,
						   DCERPC_NETLOGON_UUID,
						   DCERPC_NETLOGON_VERSION);
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

static void lsa_enumtrust_recvsmb(struct composite_context *creq)
{
	struct composite_context *c =
		talloc_get_type(creq->async.private_data,
				struct composite_context);
	struct lsa_enumtrust_state *state =
		talloc_get_type(c->private_data, struct lsa_enumtrust_state);
	struct rpc_request *req;

	c->status = dcerpc_pipe_open_smb_recv(creq);
	if (!composite_is_ok(c)) return;

	c->status = dcerpc_bind_auth_none(state->lsa_pipe,
					  DCERPC_LSARPC_UUID,
					  DCERPC_LSARPC_VERSION);
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

struct xp_login_state {
	struct composite_context *ctx;
	const char *dc_name;
	const char *dc_ip;
	const char *wks_domain;
	const char *wks_name;
	const char *wks_pwd;
	const char *user_domain;
	const char *user_name;
	const char *user_pwd;

	struct smb_composite_connect conn;
	struct cli_credentials *wks_creds;
	struct dcerpc_pipe *netlogon_pipe;
	struct dcerpc_pipe *lsa_pipe;
};

static void xp_login_recv_conn(struct composite_context *ctx);
static void xp_login_recv_auth2(struct composite_context *ctx);
static void xp_login_recv_trusts(struct composite_context *creq);

static struct composite_context *xp_login_send(TALLOC_CTX *mem_ctx,
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
	struct composite_context *c, *creq;
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

	creq = smb_composite_connect_send(&state->conn, state, event_ctx);
	composite_continue(c, creq, xp_login_recv_conn, c);
	return c;

 failed:
	composite_trigger_error(c);
	return c;
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

	c->status = lsa_enumtrust_recv(creq);
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
		ctx[i] = xp_login_send(mem_ctx, event_ctx,
				       lp_parm_string(-1, "torture", "host"),
				       lp_parm_string(-1, "torture", "host"),
				       lp_workgroup(),
				       lp_netbios_name(), "password",
				       lp_workgroup(), NULL, NULL);
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
