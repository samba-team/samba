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

/*
  wrappers for the schannel_*() functions
*/
static NTSTATUS schan_unseal_packet(struct dcerpc_security *dcerpc_security, 
				    TALLOC_CTX *mem_ctx, 
				    uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct schannel_state *schannel_state = dcerpc_security->private;
	return schannel_unseal_packet(schannel_state, mem_ctx, data, length, sig);
}

static NTSTATUS schan_check_packet(struct dcerpc_security *dcerpc_security, 
				   TALLOC_CTX *mem_ctx, 
				   const uint8_t *data, size_t length, 
				   const DATA_BLOB *sig)
{
	struct schannel_state *schannel_state = dcerpc_security->private;
	return schannel_check_packet(schannel_state, data, length, sig);
}

static NTSTATUS schan_seal_packet(struct dcerpc_security *dcerpc_security, 
				  TALLOC_CTX *mem_ctx, 
				  uint8_t *data, size_t length, 
				  DATA_BLOB *sig)
{
	struct schannel_state *schannel_state = dcerpc_security->private;
	return schannel_seal_packet(schannel_state, mem_ctx, data, length, sig);
}

static NTSTATUS schan_sign_packet(struct dcerpc_security *dcerpc_security, 
				 TALLOC_CTX *mem_ctx, 
				 const uint8_t *data, size_t length, 
				 DATA_BLOB *sig)
{
	struct schannel_state *schannel_state = dcerpc_security->private;
	return schannel_sign_packet(schannel_state, mem_ctx, data, length, sig);
}

static NTSTATUS schan_session_key(struct dcerpc_security *dcerpc_security, 
				  DATA_BLOB *session_key)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static void schan_security_end(struct dcerpc_security *dcerpc_security)
{
	struct schannel_state *schannel_state = dcerpc_security->private;
	schannel_end(&schannel_state);
}


/*
  get a schannel key using a netlogon challenge on a secondary pipe
*/
NTSTATUS dcerpc_schannel_key(struct dcerpc_pipe *p,
			     const char *domain,
			     const char *username,
			     const char *password,
			     int chan_type,
			     uint8_t new_session_key[8])
{
	NTSTATUS status;
	struct dcerpc_pipe *p2;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	uint8_t mach_pwd[16];
	struct creds_CredentialState creds;
	const char *workgroup, *workstation;
	uint32_t negotiate_flags = 0;

	workstation = username;
	workgroup = domain;

	/*
	  step 1 - establish a netlogon connection, with no authentication
	*/
	status = dcerpc_secondary_smb(p, &p2, 
				      DCERPC_NETLOGON_NAME, 
				      DCERPC_NETLOGON_UUID, 
				      DCERPC_NETLOGON_VERSION);


	/*
	  step 2 - request a netlogon challenge
	*/
	r.in.server_name = talloc_asprintf(p->mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = workstation;
	r.in.credentials = &credentials1;
	r.out.credentials = &credentials2;

	generate_random_buffer(credentials1.data, sizeof(credentials1.data), False);

	status = dcerpc_netr_ServerReqChallenge(p2, p->mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	  step 3 - authenticate on the netlogon pipe
	*/
	E_md4hash(password, mach_pwd);
	creds_client_init(&creds, &credentials1, &credentials2, mach_pwd, &credentials3,
			  negotiate_flags);

	a.in.server_name = r.in.server_name;
	a.in.account_name = talloc_asprintf(p->mem_ctx, "%s$", workstation);
	a.in.secure_channel_type = chan_type;
	a.in.computer_name = workstation;
	a.in.negotiate_flags = &negotiate_flags;
	a.out.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;

	status = dcerpc_netr_ServerAuthenticate2(p2, p->mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!creds_client_check(&creds, a.out.credentials)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/*
	  the schannel session key is now in creds.session_key

	  we no longer need the netlogon pipe open
	*/
	dcerpc_pipe_close(p2);

	memcpy(new_session_key, creds.session_key, 8);

	return NT_STATUS_OK;
}


/*
  do a schannel style bind on a dcerpc pipe with the given schannel
  key. The username is usually of the form HOSTNAME$ and the password
  is the domain trust password
*/
NTSTATUS dcerpc_bind_auth_schannel_key(struct dcerpc_pipe *p,
				       const char *uuid, uint_t version,
				       const char *domain,
				       const char *username,
				       const uint8_t session_key[8])
{
	NTSTATUS status;
	uint8_t full_session_key[16];
	struct schannel_state *schannel_state;
	const char *workgroup, *workstation;
	struct dcerpc_bind_schannel bind_schannel;

	memcpy(full_session_key, session_key, 8);
	memset(full_session_key+8, 0, 8);

	workstation = username;
	workgroup = domain;

	/*
	  perform a bind with security type schannel
	*/
	p->auth_info = talloc(p->mem_ctx, sizeof(*p->auth_info));
	if (!p->auth_info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	p->auth_info->auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
	
	if (p->flags & DCERPC_SEAL) {
		p->auth_info->auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	} else {
		/* note that DCERPC_AUTH_LEVEL_NONE does not make any 
		   sense, and would be rejected by the server */
		p->auth_info->auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	}
	p->auth_info->auth_pad_length = 0;
	p->auth_info->auth_reserved = 0;
	p->auth_info->auth_context_id = random();
	p->security_state = NULL;

	/* TODO: what are these?? */
	bind_schannel.unknown1 = 0;
	bind_schannel.unknown2 = 3;
	bind_schannel.domain = workgroup;
	bind_schannel.hostname = workstation;

	status = ndr_push_struct_blob(&p->auth_info->credentials, p->mem_ctx, &bind_schannel,
				      (ndr_push_flags_fn_t)ndr_push_dcerpc_bind_schannel);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* send the authenticated bind request */
	status = dcerpc_bind_byuuid(p, p->mem_ctx, uuid, version);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	p->security_state = talloc_p(p->mem_ctx, struct dcerpc_security);
	if (!p->security_state) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	schannel_state = talloc_p(p->mem_ctx, struct schannel_state);
	if (!schannel_state) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = schannel_start(&schannel_state, full_session_key, True);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	dump_data_pw("session key:\n", schannel_state->session_key, 16);

	p->security_state->private = schannel_state;
	p->security_state->unseal_packet = schan_unseal_packet;
	p->security_state->check_packet = schan_check_packet;
	p->security_state->seal_packet = schan_seal_packet;
	p->security_state->sign_packet = schan_sign_packet;
	p->security_state->session_key = schan_session_key;
	p->security_state->security_end = schan_security_end;

done:
	return status;
}


/*
  do a schannel style bind on a dcerpc pipe. The username is usually
  of the form HOSTNAME$ and the password is the domain trust password
*/
NTSTATUS dcerpc_bind_auth_schannel(struct dcerpc_pipe *p,
				   const char *uuid, uint_t version,
				   const char *domain,
				   const char *username,
				   const char *password)
{
	NTSTATUS status;
	uint8_t session_key[8];

	status = dcerpc_schannel_key(p, domain, username, password, 
				     lp_server_role() == ROLE_DOMAIN_BDC? SEC_CHAN_BDC:SEC_CHAN_WKSTA,
				     session_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_bind_auth_schannel_key(p, uuid, version, domain, username, session_key);

	return status;
}

