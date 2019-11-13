/* 
   Unix SMB/CIFS implementation.

   dcerpc schannel operations

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Rafal Szczesniak 2006

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
#include "auth/auth.h"
#include "libcli/composite/composite.h"
#include "libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "auth/credentials/credentials.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "param/param.h"

struct schannel_key_state {
	struct dcerpc_pipe *pipe;
	struct dcerpc_pipe *pipe2;
	struct dcerpc_binding *binding;
	bool dcerpc_schannel_auto;
	struct cli_credentials *credentials;
	struct netlogon_creds_CredentialState *creds;
	uint32_t local_negotiate_flags;
	uint32_t remote_negotiate_flags;
	struct netr_Credential credentials1;
	struct netr_Credential credentials2;
	struct netr_Credential credentials3;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	const struct samr_Password *mach_pwd;
};


static void continue_secondary_connection(struct composite_context *ctx);
static void continue_bind_auth_none(struct composite_context *ctx);
static void continue_srv_challenge(struct tevent_req *subreq);
static void continue_srv_auth2(struct tevent_req *subreq);
static void continue_get_capabilities(struct tevent_req *subreq);


/*
  Stage 2 of schannel_key: Receive endpoint mapping and request secondary
  rpc connection
*/
static void continue_epm_map_binding(struct composite_context *ctx)
{
	struct composite_context *c;
	struct schannel_key_state *s;
	struct composite_context *sec_conn_req;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct schannel_key_state);

	/* receive endpoint mapping */
	c->status = dcerpc_epm_map_binding_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0,("Failed to map DCERPC/TCP NCACN_NP pipe for '%s' - %s\n",
			 NDR_NETLOGON_UUID, nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	/* send a request for secondary rpc connection */
	sec_conn_req = dcerpc_secondary_connection_send(s->pipe,
							s->binding);
	if (composite_nomem(sec_conn_req, c)) return;

	composite_continue(c, sec_conn_req, continue_secondary_connection, c);
}


/*
  Stage 3 of schannel_key: Receive secondary rpc connection and perform
  non-authenticated bind request
*/
static void continue_secondary_connection(struct composite_context *ctx)
{
	struct composite_context *c;
	struct schannel_key_state *s;
	struct composite_context *auth_none_req;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct schannel_key_state);

	/* receive secondary rpc connection */
	c->status = dcerpc_secondary_connection_recv(ctx, &s->pipe2);
	if (!composite_is_ok(c)) return;

	talloc_steal(s, s->pipe2);

	/* initiate a non-authenticated bind */
	auth_none_req = dcerpc_bind_auth_none_send(c, s->pipe2, &ndr_table_netlogon);
	if (composite_nomem(auth_none_req, c)) return;

	composite_continue(c, auth_none_req, continue_bind_auth_none, c);
}


/*
  Stage 4 of schannel_key: Receive non-authenticated bind and get
  a netlogon challenge
*/
static void continue_bind_auth_none(struct composite_context *ctx)
{
	struct composite_context *c;
	struct schannel_key_state *s;
	struct tevent_req *subreq;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct schannel_key_state);

	/* receive result of non-authenticated bind request */
	c->status = dcerpc_bind_auth_none_recv(ctx);
	if (!composite_is_ok(c)) return;
	
	/* prepare a challenge request */
	s->r.in.server_name   = talloc_asprintf(c, "\\\\%s", dcerpc_server_name(s->pipe));
	if (composite_nomem(s->r.in.server_name, c)) return;
	s->r.in.computer_name = cli_credentials_get_workstation(s->credentials);
	s->r.in.credentials   = &s->credentials1;
	s->r.out.return_credentials  = &s->credentials2;
	
	generate_random_buffer(s->credentials1.data, sizeof(s->credentials1.data));

	/*
	  request a netlogon challenge - a rpc request over opened secondary pipe
	*/
	subreq = dcerpc_netr_ServerReqChallenge_r_send(s, c->event_ctx,
						       s->pipe2->binding_handle,
						       &s->r);
	if (composite_nomem(subreq, c)) return;

	tevent_req_set_callback(subreq, continue_srv_challenge, c);
}


/*
  Stage 5 of schannel_key: Receive a challenge and perform authentication
  on the netlogon pipe
*/
static void continue_srv_challenge(struct tevent_req *subreq)
{
	struct composite_context *c;
	struct schannel_key_state *s;

	c = tevent_req_callback_data(subreq, struct composite_context);
	s = talloc_get_type(c->private_data, struct schannel_key_state);

	/* receive rpc request result - netlogon challenge */
	c->status = dcerpc_netr_ServerReqChallenge_r_recv(subreq, s);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(c)) return;

	/* prepare credentials for auth2 request */
	s->mach_pwd = cli_credentials_get_nt_hash(s->credentials, c);

	/* auth2 request arguments */
	s->a.in.server_name      = s->r.in.server_name;
	s->a.in.account_name     = cli_credentials_get_username(s->credentials);
	s->a.in.secure_channel_type =
		cli_credentials_get_secure_channel_type(s->credentials);
	s->a.in.computer_name    = cli_credentials_get_workstation(s->credentials);
	s->a.in.negotiate_flags  = &s->local_negotiate_flags;
	s->a.in.credentials      = &s->credentials3;
	s->a.out.negotiate_flags = &s->remote_negotiate_flags;
	s->a.out.return_credentials     = &s->credentials3;

	s->creds = netlogon_creds_client_init(s, 
					      s->a.in.account_name, 
					      s->a.in.computer_name,
					      s->a.in.secure_channel_type,
					      &s->credentials1, &s->credentials2,
					      s->mach_pwd, &s->credentials3,
					      s->local_negotiate_flags);
	if (composite_nomem(s->creds, c)) {
		return;
	}
	/*
	  authenticate on the netlogon pipe - a rpc request over secondary pipe
	*/
	subreq = dcerpc_netr_ServerAuthenticate2_r_send(s, c->event_ctx,
							s->pipe2->binding_handle,
							&s->a);
	if (composite_nomem(subreq, c)) return;

	tevent_req_set_callback(subreq, continue_srv_auth2, c);
}


/*
  Stage 6 of schannel_key: Receive authentication request result and verify
  received credentials
*/
static void continue_srv_auth2(struct tevent_req *subreq)
{
	struct composite_context *c;
	struct schannel_key_state *s;

	c = tevent_req_callback_data(subreq, struct composite_context);
	s = talloc_get_type(c->private_data, struct schannel_key_state);

	/* receive rpc request result - auth2 credentials */ 
	c->status = dcerpc_netr_ServerAuthenticate2_r_recv(subreq, s);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(c)) return;

	if (!NT_STATUS_EQUAL(s->a.out.result, NT_STATUS_ACCESS_DENIED) &&
	    !NT_STATUS_IS_OK(s->a.out.result)) {
		composite_error(c, s->a.out.result);
		return;
	}

	/*
	 * Strong keys could be unsupported (NT4) or disables. So retry with the
	 * flags returned by the server. - asn
	 */
	if (NT_STATUS_EQUAL(s->a.out.result, NT_STATUS_ACCESS_DENIED)) {
		uint32_t lf = s->local_negotiate_flags;
		const char *ln = NULL;
		uint32_t rf = s->remote_negotiate_flags;
		const char *rn = NULL;

		if (!s->dcerpc_schannel_auto) {
			composite_error(c, s->a.out.result);
			return;
		}
		s->dcerpc_schannel_auto = false;

		if (lf & NETLOGON_NEG_SUPPORTS_AES)  {
			ln = "aes";
			if (rf & NETLOGON_NEG_SUPPORTS_AES) {
				composite_error(c, s->a.out.result);
				return;
			}
		} else if (lf & NETLOGON_NEG_STRONG_KEYS) {
			ln = "strong";
			if (rf & NETLOGON_NEG_STRONG_KEYS) {
				composite_error(c, s->a.out.result);
				return;
			}
		} else {
			ln = "des";
		}

		if (rf & NETLOGON_NEG_SUPPORTS_AES)  {
			rn = "aes";
		} else if (rf & NETLOGON_NEG_STRONG_KEYS) {
			rn = "strong";
		} else {
			rn = "des";
		}

		DEBUG(3, ("Server doesn't support %s keys, downgrade to %s"
			  "and retry! local[0x%08X] remote[0x%08X]\n",
			  ln, rn, lf, rf));

		s->local_negotiate_flags = s->remote_negotiate_flags;

		generate_random_buffer(s->credentials1.data,
				       sizeof(s->credentials1.data));

		subreq = dcerpc_netr_ServerReqChallenge_r_send(s,
							       c->event_ctx,
							       s->pipe2->binding_handle,
							       &s->r);
		if (composite_nomem(subreq, c)) return;

		tevent_req_set_callback(subreq, continue_srv_challenge, c);
		return;
	}

	s->creds->negotiate_flags = s->remote_negotiate_flags;

	/* verify credentials */
	if (!netlogon_creds_client_check(s->creds, s->a.out.return_credentials)) {
		composite_error(c, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	composite_done(c);
}

/*
  Initiate establishing a schannel key using netlogon challenge
  on a secondary pipe
*/
static struct composite_context *dcerpc_schannel_key_send(TALLOC_CTX *mem_ctx,
						   struct dcerpc_pipe *p,
						   struct cli_credentials *credentials,
						   struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	struct schannel_key_state *s;
	struct composite_context *epm_map_req;
	enum netr_SchannelType schannel_type = cli_credentials_get_secure_channel_type(credentials);
	struct cli_credentials *epm_creds = NULL;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, p->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct schannel_key_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* store parameters in the state structure */
	s->pipe        = p;
	s->credentials = credentials;
	s->local_negotiate_flags = NETLOGON_NEG_AUTH2_FLAGS;

	/* allocate credentials */
	if (s->pipe->conn->flags & DCERPC_SCHANNEL_128) {
		s->local_negotiate_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
	}
	if (s->pipe->conn->flags & DCERPC_SCHANNEL_AES) {
		s->local_negotiate_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
		s->local_negotiate_flags |= NETLOGON_NEG_SUPPORTS_AES;
	}
	if (s->pipe->conn->flags & DCERPC_SCHANNEL_AUTO) {
		s->local_negotiate_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
		s->local_negotiate_flags |= NETLOGON_NEG_SUPPORTS_AES;
		s->dcerpc_schannel_auto = true;
	}

	/* type of authentication depends on schannel type */
	if (schannel_type == SEC_CHAN_RODC) {
		s->local_negotiate_flags |= NETLOGON_NEG_RODC_PASSTHROUGH;
	}

	epm_creds = cli_credentials_init_anon(s);
	if (composite_nomem(epm_creds, c)) return c;

	/* allocate binding structure */
	s->binding = dcerpc_binding_dup(s, s->pipe->binding);
	if (composite_nomem(s->binding, c)) return c;

	/* request the netlogon endpoint mapping */
	epm_map_req = dcerpc_epm_map_binding_send(c, s->binding,
						  &ndr_table_netlogon,
						  epm_creds,
						  s->pipe->conn->event_ctx,
						  lp_ctx);
	if (composite_nomem(epm_map_req, c)) return c;

	composite_continue(c, epm_map_req, continue_epm_map_binding, c);
	return c;
}


/*
  Receive result of schannel key request
 */
static NTSTATUS dcerpc_schannel_key_recv(struct composite_context *c,
				TALLOC_CTX *mem_ctx,
				struct netlogon_creds_CredentialState **creds)
{
	NTSTATUS status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct schannel_key_state *s =
			talloc_get_type_abort(c->private_data,
			struct schannel_key_state);
		*creds = talloc_move(mem_ctx, &s->creds);
	}

	talloc_free(c);
	return status;
}


struct auth_schannel_state {
	struct dcerpc_pipe *pipe;
	struct cli_credentials *credentials;
	const struct ndr_interface_table *table;
	struct loadparm_context *lp_ctx;
	uint8_t auth_level;
	struct netlogon_creds_CredentialState *creds_state;
	struct netlogon_creds_CredentialState save_creds_state;
	struct netr_Authenticator auth;
	struct netr_Authenticator return_auth;
	union netr_Capabilities capabilities;
	struct netr_LogonGetCapabilities c;
};


static void continue_bind_auth(struct composite_context *ctx);


/*
  Stage 2 of auth_schannel: Receive schannel key and intitiate an
  authenticated bind using received credentials
 */
static void continue_schannel_key(struct composite_context *ctx)
{
	struct composite_context *auth_req;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct auth_schannel_state *s = talloc_get_type(c->private_data,
							struct auth_schannel_state);
	NTSTATUS status;

	/* receive schannel key */
	status = c->status = dcerpc_schannel_key_recv(ctx, s, &s->creds_state);
	if (!composite_is_ok(c)) {
		DEBUG(1, ("Failed to setup credentials: %s\n", nt_errstr(status)));
		return;
	}

	/* send bind auth request with received creds */
	cli_credentials_set_netlogon_creds(s->credentials, s->creds_state);

	auth_req = dcerpc_bind_auth_send(c, s->pipe, s->table, s->credentials, 
					 lpcfg_gensec_settings(c, s->lp_ctx),
					 DCERPC_AUTH_TYPE_SCHANNEL, s->auth_level,
					 NULL);
	if (composite_nomem(auth_req, c)) return;
	
	composite_continue(c, auth_req, continue_bind_auth, c);
}


/*
  Stage 3 of auth_schannel: Receivce result of authenticated bind
  and say if we're done ok.
*/
static void continue_bind_auth(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct auth_schannel_state *s = talloc_get_type(c->private_data,
							struct auth_schannel_state);
	struct tevent_req *subreq;

	c->status = dcerpc_bind_auth_recv(ctx);
	if (!composite_is_ok(c)) return;

	/* if we have a AES encrypted connection, verify the capabilities */
	if (ndr_syntax_id_equal(&s->table->syntax_id,
				&ndr_table_netlogon.syntax_id)) {
		NTSTATUS status;
		ZERO_STRUCT(s->return_auth);

		s->save_creds_state = *s->creds_state;
		status = netlogon_creds_client_authenticator(&s->save_creds_state,
							     &s->auth);
		if (!NT_STATUS_IS_OK(status)) {
			composite_error(c, status);
			return;
		}

		s->c.in.server_name = talloc_asprintf(c,
						      "\\\\%s",
						      dcerpc_server_name(s->pipe));
		if (composite_nomem(s->c.in.server_name, c)) return;
		s->c.in.computer_name         = cli_credentials_get_workstation(s->credentials);
		s->c.in.credential            = &s->auth;
		s->c.in.return_authenticator  = &s->return_auth;
		s->c.in.query_level           = 1;

		s->c.out.capabilities         = &s->capabilities;
		s->c.out.return_authenticator = &s->return_auth;

		DEBUG(5, ("We established a AES connection, verifying logon "
			  "capabilities\n"));

		subreq = dcerpc_netr_LogonGetCapabilities_r_send(s,
								 c->event_ctx,
								 s->pipe->binding_handle,
								 &s->c);
		if (composite_nomem(subreq, c)) return;

		tevent_req_set_callback(subreq, continue_get_capabilities, c);
		return;
	}

	composite_done(c);
}

/*
  Stage 4 of auth_schannel: Get the Logon Capablities and verify them.
*/
static void continue_get_capabilities(struct tevent_req *subreq)
{
	struct composite_context *c;
	struct auth_schannel_state *s;

	c = tevent_req_callback_data(subreq, struct composite_context);
	s = talloc_get_type(c->private_data, struct auth_schannel_state);

	/* receive rpc request result */
	c->status = dcerpc_netr_LogonGetCapabilities_r_recv(subreq, s);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(c->status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
		if (s->creds_state->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
			composite_error(c, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		} else {
			/* This is probably NT */
			composite_done(c);
			return;
		}
	} else if (!composite_is_ok(c)) {
		return;
	}

	if (NT_STATUS_EQUAL(s->c.out.result, NT_STATUS_NOT_IMPLEMENTED)) {
		if (s->creds_state->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
			/* This means AES isn't supported. */
			composite_error(c, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		/* This is probably an old Samba version */
		composite_done(c);
		return;
	}

	/* verify credentials */
	if (!netlogon_creds_client_check(&s->save_creds_state,
					 &s->c.out.return_authenticator->cred)) {
		composite_error(c, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	*s->creds_state = s->save_creds_state;
	cli_credentials_set_netlogon_creds(s->credentials, s->creds_state);

	if (!NT_STATUS_IS_OK(s->c.out.result)) {
		composite_error(c, s->c.out.result);
		return;
	}

	/* compare capabilities */
	if (s->creds_state->negotiate_flags != s->capabilities.server_capabilities) {
		DEBUG(2, ("The client capabilities don't match the server "
			  "capabilities: local[0x%08X] remote[0x%08X]\n",
			  s->creds_state->negotiate_flags,
			  s->capabilities.server_capabilities));
		composite_error(c, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	/* TODO: Add downgrade dectection. */

	composite_done(c);
}


/*
  Initiate schannel authentication request
*/
struct composite_context *dcerpc_bind_auth_schannel_send(TALLOC_CTX *tmp_ctx, 
							 struct dcerpc_pipe *p,
							 const struct ndr_interface_table *table,
							 struct cli_credentials *credentials,
							 struct loadparm_context *lp_ctx,
							 uint8_t auth_level)
{
	struct composite_context *c;
	struct auth_schannel_state *s;
	struct composite_context *schan_key_req;

	/* composite context allocation and setup */
	c = composite_create(tmp_ctx, p->conn->event_ctx);
	if (c == NULL) return NULL;
	
	s = talloc_zero(c, struct auth_schannel_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* store parameters in the state structure */
	s->pipe        = p;
	s->credentials = credentials;
	s->table       = table;
	s->auth_level  = auth_level;
	s->lp_ctx      = lp_ctx;

	/* start getting schannel key first */
	schan_key_req = dcerpc_schannel_key_send(c, p, credentials, lp_ctx);
	if (composite_nomem(schan_key_req, c)) return c;

	composite_continue(c, schan_key_req, continue_schannel_key, c);
	return c;
}


/*
  Receive result of schannel authentication request
*/
NTSTATUS dcerpc_bind_auth_schannel_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}
