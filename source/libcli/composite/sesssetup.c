/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2005
   
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
/*
  a composite API for making handling a generic async session setup
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "auth/auth.h"


struct sesssetup_state {
	union smb_sesssetup setup;
	NTSTATUS session_key_err;
	struct smb_composite_sesssetup *io;
	struct smbcli_request *req;
};


/*
  form an encrypted lanman password from a plaintext password
  and the server supplied challenge
*/
static DATA_BLOB lanman_blob(TALLOC_CTX *mem_ctx, const char *pass, DATA_BLOB challenge)
{
	DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, 24);
	SMBencrypt(pass, challenge.data, blob.data);
	return blob;
}

/*
  form an encrypted NT password from a plaintext password
  and the server supplied challenge
*/
static DATA_BLOB nt_blob(TALLOC_CTX *mem_ctx, const char *pass, DATA_BLOB challenge)
{
	DATA_BLOB blob = data_blob_talloc(mem_ctx, NULL, 24);
	SMBNTencrypt(pass, challenge.data, blob.data);
	return blob;
}

/*
  store the user session key for a transport
*/
static void set_user_session_key(struct smbcli_session *session,
				 const DATA_BLOB *session_key)
{
	session->user_session_key = data_blob_talloc(session, 
						     session_key->data, 
						     session_key->length);
}

/*
  setup signing for a NT1 style session setup
*/
static void use_nt1_session_keys(struct smbcli_session *session, 
				 const char *password, const DATA_BLOB *nt_response)
{
	struct smbcli_transport *transport = session->transport; 
	uint8_t nt_hash[16];
	DATA_BLOB session_key = data_blob_talloc(session, NULL, 16);

	E_md4hash(password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, session_key.data);

	smbcli_transport_simple_set_signing(transport, session_key, *nt_response);

	set_user_session_key(session, &session_key);
	data_blob_free(&session_key);
}


/*
  handler for completion of a smbcli_request sub-request
*/
static void request_handler(struct smbcli_request *req)
{
	struct composite_context *c = req->async.private;
	struct sesssetup_state *state = talloc_get_type(c->private, struct sesssetup_state);
	struct smbcli_session *session = req->session;
	DATA_BLOB session_key = data_blob(NULL, 0);
	DATA_BLOB null_data_blob = data_blob(NULL, 0);

	c->status = smb_raw_session_setup_recv(req, state, &state->setup);

	switch (state->setup.old.level) {
	case RAW_SESSSETUP_OLD:
		state->io->out.vuid = state->setup.old.out.vuid;
		break;

	case RAW_SESSSETUP_NT1:
		state->io->out.vuid = state->setup.nt1.out.vuid;
		break;

	case RAW_SESSSETUP_SPNEGO:
		session->vuid = state->io->out.vuid = state->setup.spnego.out.vuid;
		if (!NT_STATUS_EQUAL(c->status, NT_STATUS_MORE_PROCESSING_REQUIRED) && 
		    !NT_STATUS_IS_OK(c->status)) {
			break;
		}
		c->status = gensec_update(session->gensec, state,
					  state->setup.spnego.out.secblob,
					  &state->setup.spnego.in.secblob);
		if (!NT_STATUS_EQUAL(c->status, NT_STATUS_MORE_PROCESSING_REQUIRED) && 
		    !NT_STATUS_IS_OK(c->status)) {
			break;
		}
		if (state->setup.spnego.in.secblob.length == 0) {
			break;
		}

		/* we need to do another round of session setup. We keep going until both sides
		   are happy */
		state->session_key_err = gensec_session_key(session->gensec, &session_key);
		if (NT_STATUS_IS_OK(state->session_key_err)) {
			set_user_session_key(session, &session_key);
			smbcli_transport_simple_set_signing(session->transport, session_key, null_data_blob);
		}

		state->req = smb_raw_session_setup_send(session, &state->setup);
		state->req->async.fn = request_handler;
		state->req->async.private = c;
		return;
	}

	/* enforce the local signing required flag */
	if (NT_STATUS_IS_OK(c->status) && !cli_credentials_is_anonymous(state->io->in.credentials)) {
		if (!session->transport->negotiate.sign_info.doing_signing 
		    && session->transport->negotiate.sign_info.mandatory_signing) {
			DEBUG(0, ("SMB signing required, but server does not support it\n"));
			c->status = NT_STATUS_ACCESS_DENIED;
		}
	}

	if (NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_DONE;
	} else {
		c->state = SMBCLI_REQUEST_ERROR;
	}
	if (c->async.fn) {
		c->async.fn(c);
	}
}


/*
  send a nt1 style session setup
*/
static struct smbcli_request *session_setup_nt1(struct composite_context *c,
						struct smbcli_session *session, 
						struct smb_composite_sesssetup *io) 
{
	struct sesssetup_state *state = talloc_get_type(c->private, struct sesssetup_state);
	const char *password = cli_credentials_get_password(io->in.credentials);

	state->setup.nt1.level           = RAW_SESSSETUP_NT1;
	state->setup.nt1.in.bufsize      = session->transport->options.max_xmit;
	state->setup.nt1.in.mpx_max      = session->transport->options.max_mux;
	state->setup.nt1.in.vc_num       = 1;
	state->setup.nt1.in.sesskey      = io->in.sesskey;
	state->setup.nt1.in.capabilities = io->in.capabilities;
	state->setup.nt1.in.os           = "Unix";
	state->setup.nt1.in.lanman       = "Samba";

	state->setup.old.in.domain  = cli_credentials_get_domain(io->in.credentials);
	state->setup.old.in.user    = cli_credentials_get_username(io->in.credentials);
	if (!password) {
		state->setup.nt1.in.password1 = data_blob(NULL, 0);
		state->setup.nt1.in.password2 = data_blob(NULL, 0);
	} else if (session->transport->negotiate.sec_mode & 
		   NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		state->setup.nt1.in.password1 = lanman_blob(state, password, 
							    session->transport->negotiate.secblob);
		state->setup.nt1.in.password2 = nt_blob(state, password, 
							session->transport->negotiate.secblob);
		use_nt1_session_keys(session, password, &state->setup.nt1.in.password2);
	} else {
		state->setup.nt1.in.password1 = data_blob_talloc(state, password, strlen(password));
		state->setup.nt1.in.password2 = data_blob(NULL, 0);
	}

	return smb_raw_session_setup_send(session, &state->setup);
}


/*
  old style session setup (pre NT1 protocol level)
*/
static struct smbcli_request *session_setup_old(struct composite_context *c,
						struct smbcli_session *session,
						struct smb_composite_sesssetup *io)
{
	struct sesssetup_state *state = talloc_get_type(c->private, struct sesssetup_state);
	const char *password = cli_credentials_get_password(io->in.credentials);

	state->setup.old.level      = RAW_SESSSETUP_OLD;
	state->setup.old.in.bufsize = session->transport->options.max_xmit;
	state->setup.old.in.mpx_max = session->transport->options.max_mux;
	state->setup.old.in.vc_num  = 1;
	state->setup.old.in.sesskey = io->in.sesskey;
	state->setup.old.in.domain  = cli_credentials_get_domain(io->in.credentials);
	state->setup.old.in.user    = cli_credentials_get_username(io->in.credentials);
	state->setup.old.in.os      = "Unix";
	state->setup.old.in.lanman  = "Samba";
	
	if (!password) {
		state->setup.old.in.password = data_blob(NULL, 0);
	} else if (session->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		state->setup.old.in.password = lanman_blob(state, password, 
							   session->transport->negotiate.secblob);
	} else {
		state->setup.old.in.password = data_blob_talloc(state,
								password, 
								strlen(password));
	}
	
	return smb_raw_session_setup_send(session, &state->setup);
}


/*
  old style session setup (pre NT1 protocol level)
*/
static struct smbcli_request *session_setup_spnego(struct composite_context *c, 
						   struct smbcli_session *session,
						   struct smb_composite_sesssetup *io)
{
	struct sesssetup_state *state = talloc_get_type(c->private, struct sesssetup_state);
	NTSTATUS status;
	DATA_BLOB session_key = data_blob(NULL, 0);
	DATA_BLOB null_data_blob = data_blob(NULL, 0);
	const char *chosen_oid = NULL;

	state->setup.spnego.level           = RAW_SESSSETUP_SPNEGO;
	state->setup.spnego.in.bufsize      = session->transport->options.max_xmit;
	state->setup.spnego.in.mpx_max      = session->transport->options.max_mux;
	state->setup.spnego.in.vc_num       = 1;
	state->setup.spnego.in.sesskey      = io->in.sesskey;
	state->setup.spnego.in.capabilities = io->in.capabilities;
	state->setup.spnego.in.os           = "Unix";
	state->setup.spnego.in.lanman       = "Samba";
	state->setup.spnego.in.workgroup    = io->in.workgroup;

	state->setup.spnego.out.vuid        = session->vuid;

	smbcli_temp_set_signing(session->transport);

	status = gensec_client_start(session, &session->gensec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC client mode: %s\n", nt_errstr(status)));
		return NULL;
	}

	gensec_want_feature(session->gensec, GENSEC_FEATURE_SESSION_KEY);

	status = gensec_set_credentials(session->gensec, io->in.credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client credentails: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_set_target_hostname(session->gensec, session->transport->socket->hostname);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target hostname: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_set_target_service(session->gensec, "cifs");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target service: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	if (session->transport->negotiate.secblob.length) {
		chosen_oid = GENSEC_OID_SPNEGO;
	} else {
		/* without a sec blob, means raw NTLMSSP */
		chosen_oid = GENSEC_OID_NTLMSSP;
	}

	status = gensec_start_mech_by_oid(session->gensec, chosen_oid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client SPNEGO mechanism %s: %s\n",
			  gensec_get_name_by_oid(chosen_oid), nt_errstr(status)));
		return NULL;
	}
	
	status = gensec_update(session->gensec, state,
			       session->transport->negotiate.secblob,
			       &state->setup.spnego.in.secblob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(1, ("Failed initial gensec_update with mechanism %s: %s\n",
			  gensec_get_name_by_oid(chosen_oid), nt_errstr(status)));
		return NULL;
	}

	state->session_key_err = gensec_session_key(session->gensec, &session_key);
	if (NT_STATUS_IS_OK(state->session_key_err)) {
		smbcli_transport_simple_set_signing(session->transport, session_key, null_data_blob);
	}

	return smb_raw_session_setup_send(session, &state->setup);
}


/*
  composite session setup function that hides the details of all the
  different session setup varients, including the multi-pass nature of
  the spnego varient
*/
struct composite_context *smb_composite_sesssetup_send(struct smbcli_session *session, 
						      struct smb_composite_sesssetup *io)
{
	struct composite_context *c;
	struct sesssetup_state *state;

	c = talloc_zero(session, struct composite_context);
	if (c == NULL) goto failed;

	state = talloc(c, struct sesssetup_state);
	if (state == NULL) goto failed;

	state->io = io;

	c->state = SMBCLI_REQUEST_SEND;
	c->private = state;
	c->event_ctx = session->transport->socket->event.ctx;

	/* no session setup at all in earliest protocol varients */
	if (session->transport->negotiate.protocol < PROTOCOL_LANMAN1) {
		ZERO_STRUCT(io->out);
		c->state = SMBCLI_REQUEST_DONE;
		return c;
	}

	/* see what session setup interface we will use */
	if (session->transport->negotiate.protocol < PROTOCOL_NT1) {
		state->req = session_setup_old(c, session, io);
	} else if (!session->transport->options.use_spnego ||
		   !(io->in.capabilities & CAP_EXTENDED_SECURITY)) {
		state->req = session_setup_nt1(c, session, io);
	} else {
		state->req = session_setup_spnego(c, session, io);
	}

	if (state->req == NULL) goto failed;

	state->req->async.fn = request_handler;
	state->req->async.private = c;

	return c;

failed:
	talloc_free(c);
	return NULL;
}


/*
  receive a composite session setup reply
*/
NTSTATUS smb_composite_sesssetup_recv(struct composite_context *c)
{
	NTSTATUS status;
	status = composite_wait(c);
	talloc_free(c);
	return status;
}

/*
  sync version of smb_composite_sesssetup 
*/
NTSTATUS smb_composite_sesssetup(struct smbcli_session *session, struct smb_composite_sesssetup *io)
{
	struct composite_context *c = smb_composite_sesssetup_send(session, io);
	return smb_composite_sesssetup_recv(c);
}
