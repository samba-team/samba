/* 
   Unix SMB/CIFS implementation.

   dcerpc schannel operations

   Copyright (C) Andrew Tridgell 2004
   
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
#include "librpc/gen_ndr/ndr_schannel.h"
#include "auth/auth.h"

enum schannel_position {
	DCERPC_SCHANNEL_STATE_START = 0,
	DCERPC_SCHANNEL_STATE_UPDATE_1
};

struct dcerpc_schannel_state {
	enum schannel_position state;
	struct schannel_state *schannel_state;
	struct creds_CredentialState *creds;
	char *account_name;
};

static NTSTATUS dcerpc_schannel_key(struct dcerpc_pipe *p,
				    const char *domain,
				    const char *username,
				    const char *password,
				    int chan_type,
				    struct creds_CredentialState *creds);

/*
  wrappers for the schannel_*() functions

  These will become static again, when we get dynamic registration, and
  decrpc_schannel_security_ops come back here.
*/
static NTSTATUS dcerpc_schannel_unseal_packet(struct gensec_security *gensec_security, 
					      TALLOC_CTX *mem_ctx, 
					      uint8_t *data, size_t length, 
					      const uint8_t *whole_pdu, size_t pdu_length, 
					      DATA_BLOB *sig)
{
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;
	
	return schannel_unseal_packet(dce_schan_state->schannel_state, mem_ctx, data, length, sig);
}

static NTSTATUS dcerpc_schannel_check_packet(struct gensec_security *gensec_security, 
					     TALLOC_CTX *mem_ctx, 
					     const uint8_t *data, size_t length, 
					     const uint8_t *whole_pdu, size_t pdu_length, 
					     const DATA_BLOB *sig)
{
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;

	return schannel_check_packet(dce_schan_state->schannel_state, data, length, sig);
}

static NTSTATUS dcerpc_schannel_seal_packet(struct gensec_security *gensec_security, 
					    TALLOC_CTX *mem_ctx, 
					    uint8_t *data, size_t length, 
					    const uint8_t *whole_pdu, size_t pdu_length, 
					    DATA_BLOB *sig)
{
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;

	return schannel_seal_packet(dce_schan_state->schannel_state, mem_ctx, data, length, sig);
}

static NTSTATUS dcerpc_schannel_sign_packet(struct gensec_security *gensec_security, 
					    TALLOC_CTX *mem_ctx, 
					    const uint8_t *data, size_t length, 
					    const uint8_t *whole_pdu, size_t pdu_length, 
					    DATA_BLOB *sig)
{
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;

	return schannel_sign_packet(dce_schan_state->schannel_state, mem_ctx, data, length, sig);
}

static size_t dcerpc_schannel_sig_size(struct gensec_security *gensec_security)
{
	return 32;
}

static NTSTATUS dcerpc_schannel_session_key(struct gensec_security *gensec_security, 
					    DATA_BLOB *session_key)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS dcerpc_schannel_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx, 
				       const DATA_BLOB in, DATA_BLOB *out) 
{
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;
	NTSTATUS status;
	struct schannel_bind bind_schannel;
	struct schannel_bind_ack bind_schannel_ack;
	const char *account_name;
	*out = data_blob(NULL, 0);

	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		if (dce_schan_state->state != DCERPC_SCHANNEL_STATE_START) {
			/* we could parse the bind ack, but we don't know what it is yet */
			return NT_STATUS_OK;
		}
		
		status = schannel_start(&dce_schan_state->schannel_state, 
					dce_schan_state->creds->session_key,
					True);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start schannel client\n"));
			return status;
		}
		talloc_steal(dce_schan_state, dce_schan_state->schannel_state);
	
		bind_schannel.unknown1 = 0;
#if 0
		/* to support this we'd need to have access to the full domain name */
		bind_schannel.bind_type = 23;
		bind_schannel.u.info23.domain = gensec_security->user.domain;
		bind_schannel.u.info23.account_name = gensec_security->user.name;
		bind_schannel.u.info23.dnsdomain = str_format_nbt_domain(out_mem_ctx, fulldomainname);
		bind_schannel.u.info23.workstation = str_format_nbt_domain(out_mem_ctx, gensec_security->user.name);
#else
		bind_schannel.bind_type = 3;
		bind_schannel.u.info3.domain = gensec_security->user.domain;
		bind_schannel.u.info3.account_name = gensec_security->user.name;
#endif
		
		status = ndr_push_struct_blob(out, out_mem_ctx, &bind_schannel,
					      (ndr_push_flags_fn_t)ndr_push_schannel_bind);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not create schannel bind: %s\n",
				  nt_errstr(status)));
			return status;
		}
		
		dce_schan_state->state = DCERPC_SCHANNEL_STATE_UPDATE_1;

		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	case GENSEC_SERVER:
		
		if (dce_schan_state->state != DCERPC_SCHANNEL_STATE_START) {
			/* no third leg on this protocol */
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		/* parse the schannel startup blob */
		status = ndr_pull_struct_blob(&in, out_mem_ctx, &bind_schannel, 
					      (ndr_pull_flags_fn_t)ndr_pull_schannel_bind);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		
		if (bind_schannel.bind_type == 23) {
			account_name = bind_schannel.u.info23.account_name;
		} else {
			account_name = bind_schannel.u.info3.account_name;
		}
		
		/* pull the session key for this client */
		status = schannel_fetch_session_key(out_mem_ctx, account_name, &dce_schan_state->creds);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not find session key for attempted schannel connection on %s: %s\n",
				  account_name, nt_errstr(status)));
			return status;
		}

		dce_schan_state->account_name = talloc_strdup(dce_schan_state, account_name);
		
		/* start up the schannel server code */
		status = schannel_start(&dce_schan_state->schannel_state, 
					dce_schan_state->creds->session_key, False);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not initialise schannel state for account %s: %s\n",
				  account_name, nt_errstr(status)));
			return status;
		}
		talloc_steal(dce_schan_state, dce_schan_state->schannel_state);
		
		bind_schannel_ack.unknown1 = 1;
		bind_schannel_ack.unknown2 = 0;
		bind_schannel_ack.unknown3 = 0x6c0000;
		
		status = ndr_push_struct_blob(out, out_mem_ctx, &bind_schannel_ack, 
					      (ndr_push_flags_fn_t)ndr_push_schannel_bind_ack);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not return schannel bind ack for account %s: %s\n",
				  account_name, nt_errstr(status)));
			return status;
		}

		dce_schan_state->state = DCERPC_SCHANNEL_STATE_UPDATE_1;

		return NT_STATUS_OK;
	}
	return NT_STATUS_INVALID_PARAMETER;
}

/** 
 * Return the credentials of a logged on user, including session keys
 * etc.
 *
 * Only valid after a successful authentication
 *
 * May only be called once per authentication.
 *
 */

NTSTATUS dcerpc_schannel_session_info(struct gensec_security *gensec_security,
				      struct auth_session_info **session_info)
{ 
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;

	(*session_info) = talloc_p(gensec_security, struct auth_session_info);
	if (*session_info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*session_info);
	(*session_info)->refcount = 1;
	
	(*session_info)->workstation = talloc_strdup(*session_info, dce_schan_state->account_name);
	if ((*session_info)->workstation == NULL) {
		talloc_free(*session_info);
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}
		

/**
 * Return the struct creds_CredentialState.
 *
 * Make sure not to call this unless gensec is using schannel...
 */

NTSTATUS dcerpc_schannel_creds(struct gensec_security *gensec_security,
			       TALLOC_CTX *mem_ctx,
			       struct creds_CredentialState **creds)
{ 
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;

	*creds = dce_schan_state->creds;
	return NT_STATUS_OK;
}
		

static NTSTATUS dcerpc_schannel_start(struct gensec_security *gensec_security)
{
	struct dcerpc_schannel_state *dce_schan_state;

	dce_schan_state = talloc_p(gensec_security, struct dcerpc_schannel_state);
	if (!dce_schan_state) {
		return NT_STATUS_NO_MEMORY;
	}

	dce_schan_state->state = DCERPC_SCHANNEL_STATE_START;
	gensec_security->private_data = dce_schan_state;
	
	return NT_STATUS_OK;
}

static NTSTATUS dcerpc_schannel_server_start(struct gensec_security *gensec_security) 
{
	NTSTATUS status;

	status = dcerpc_schannel_start(gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dcerpc_schannel_client_start(struct gensec_security *gensec_security) 
{
	NTSTATUS status;

	status = dcerpc_schannel_start(gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/*
  end crypto state
*/
static void dcerpc_schannel_end(struct gensec_security *gensec_security)
{
	struct dcerpc_schannel_state *dce_schan_state = gensec_security->private_data;

	schannel_end(&dce_schan_state->schannel_state);

	talloc_free(dce_schan_state);

	gensec_security->private_data = NULL;
}


/*
  get a schannel key using a netlogon challenge on a secondary pipe
*/
static NTSTATUS dcerpc_schannel_key(struct dcerpc_pipe *p,
				    const char *domain,
				    const char *username,
				    const char *password,
				    int chan_type,
				    struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct dcerpc_pipe *p2;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct samr_Password mach_pwd;
	const char *workgroup, *workstation;
	uint32_t negotiate_flags;

	if (p->flags & DCERPC_SCHANNEL_128) {
		negotiate_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
	} else {
		negotiate_flags = NETLOGON_NEG_AUTH2_FLAGS;
	}

	workstation = username;
	workgroup = domain;

	/*
	  step 1 - establish a netlogon connection, with no authentication
	*/
	status = dcerpc_secondary_connection(p, &p2, 
					     DCERPC_NETLOGON_NAME, 
					     DCERPC_NETLOGON_UUID, 
					     DCERPC_NETLOGON_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}


	/*
	  step 2 - request a netlogon challenge
	*/
	r.in.server_name = talloc_asprintf(p, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = workstation;
	r.in.credentials = &credentials1;
	r.out.credentials = &credentials2;

	generate_random_buffer(credentials1.data, sizeof(credentials1.data));

	status = dcerpc_netr_ServerReqChallenge(p2, p, &r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	  step 3 - authenticate on the netlogon pipe
	*/
	E_md4hash(password, mach_pwd.hash);
	creds_client_init(creds, &credentials1, &credentials2, &mach_pwd, &credentials3,
			  negotiate_flags);

	a.in.server_name = r.in.server_name;
	a.in.account_name = talloc_asprintf(p, "%s$", workstation);
	a.in.secure_channel_type = chan_type;
	a.in.computer_name = workstation;
	a.in.negotiate_flags = &negotiate_flags;
	a.out.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;

	status = dcerpc_netr_ServerAuthenticate2(p2, p, &a);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!creds_client_check(creds, a.out.credentials)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/*
	  the schannel session key is now in creds.session_key

	  we no longer need the netlogon pipe open
	*/
	dcerpc_pipe_close(p2);

	return NT_STATUS_OK;
}

/*
  do a schannel style bind on a dcerpc pipe. The username is usually
  of the form HOSTNAME$ and the password is the domain trust password
*/
NTSTATUS dcerpc_bind_auth_schannel_withkey(struct dcerpc_pipe *p,
					   const char *uuid, uint_t version,
					   const char *domain,
					   const char *username,
					   const char *password,
					   struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct dcerpc_schannel_state *dce_schan_state;

	status = gensec_client_start(p, &p->security_state.generic_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gensec_set_username(p->security_state.generic_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set schannel username to %s: %s\n", username, nt_errstr(status)));
		gensec_end(&p->security_state.generic_state);
		return status;
	}
	
	status = gensec_set_domain(p->security_state.generic_state, domain);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set schannel domain to %s: %s\n", domain, nt_errstr(status)));
		gensec_end(&p->security_state.generic_state);
		return status;
	}
	
	status = gensec_start_mech_by_authtype(p->security_state.generic_state, DCERPC_AUTH_TYPE_SCHANNEL, dcerpc_auth_level(p));

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start SCHANNEL GENSEC backend: %s\n", nt_errstr(status)));
		gensec_end(&p->security_state.generic_state);
		return status;
	}

	dce_schan_state = p->security_state.generic_state->private_data;
	dce_schan_state->creds = talloc_reference(dce_schan_state, creds);

	status = dcerpc_bind_auth3(p, DCERPC_AUTH_TYPE_SCHANNEL, dcerpc_auth_level(p),
				  uuid, version);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to bind to pipe with SCHANNEL: %s\n", nt_errstr(status)));
		gensec_end(&p->security_state.generic_state);
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_bind_auth_schannel(struct dcerpc_pipe *p,
				   const char *uuid, uint_t version,
				   const char *domain,
				   const char *username,
				   const char *password)
{
	NTSTATUS status;
	int chan_type = 0;
	struct creds_CredentialState *creds;
	creds = talloc_p(p, struct creds_CredentialState);
	if (!creds) {
		return NT_STATUS_NO_MEMORY;
	}

	if (p->flags & DCERPC_SCHANNEL_BDC) {
		chan_type = SEC_CHAN_BDC;
	} else if (p->flags & DCERPC_SCHANNEL_WORKSTATION) {
		chan_type = SEC_CHAN_WKSTA;
	} else if (p->flags & DCERPC_SCHANNEL_DOMAIN) {
		chan_type = SEC_CHAN_DOMAIN;
	}

	status = dcerpc_schannel_key(p, domain, 
				     username,
				     password, 
				     chan_type,
				     creds);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to fetch schannel session key: %s\n",
			  nt_errstr(status)));
		return status;
	}

	return dcerpc_bind_auth_schannel_withkey(p, uuid, version, domain,
						 username, password,
						 creds);
}

static const struct gensec_security_ops gensec_dcerpc_schannel_security_ops = {
	.name		= "dcerpc_schannel",
	.auth_type	= DCERPC_AUTH_TYPE_SCHANNEL,
	.client_start   = dcerpc_schannel_client_start,
	.server_start   = dcerpc_schannel_server_start,
	.update 	= dcerpc_schannel_update,
	.seal_packet 	= dcerpc_schannel_seal_packet,
	.sign_packet   	= dcerpc_schannel_sign_packet,
	.check_packet	= dcerpc_schannel_check_packet,
	.unseal_packet 	= dcerpc_schannel_unseal_packet,
	.session_key	= dcerpc_schannel_session_key,
	.session_info	= dcerpc_schannel_session_info,
	.sig_size	= dcerpc_schannel_sig_size,
	.end		= dcerpc_schannel_end
};

NTSTATUS gensec_dcerpc_schannel_init(void)
{
	NTSTATUS ret;
	ret = gensec_register(&gensec_dcerpc_schannel_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_dcerpc_schannel_security_ops.name));
		return ret;
	}

	return ret;
}
