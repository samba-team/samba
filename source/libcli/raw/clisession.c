/* 
   Unix SMB/CIFS implementation.
   SMB client session context management functions
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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

#define SETUP_REQUEST_SESSION(cmd, wct, buflen) do { \
	req = cli_request_setup_session(session, cmd, wct, buflen); \
	if (!req) return NULL; \
} while (0)

/****************************************************************************
 Initialize the session context
****************************************************************************/
struct cli_session *cli_session_init(struct cli_transport *transport)
{
	struct cli_session *session;
	TALLOC_CTX *mem_ctx = talloc_init("cli_session");
	if (mem_ctx == NULL) {
		return NULL;
	}

	session = talloc_zero(mem_ctx, sizeof(*session));
	if (!session) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	session->mem_ctx = mem_ctx;
	session->transport = transport;
	session->pid = (uint16_t)getpid();
	session->vuid = UID_FIELD_INVALID;
	session->transport->reference_count++;

	return session;
}

/****************************************************************************
reduce reference_count and destroy is <= 0
****************************************************************************/
void cli_session_close(struct cli_session *session)
{
	session->reference_count--;
	if (session->reference_count <= 0) {
		cli_transport_close(session->transport);
		talloc_destroy(session->mem_ctx);
	}
}

/****************************************************************************
 Perform a session setup (async send)
****************************************************************************/
struct cli_request *smb_raw_session_setup_send(struct cli_session *session, union smb_sesssetup *parms) 
{
	struct cli_request *req;

	switch (parms->generic.level) {
	case RAW_SESSSETUP_GENERIC:
		/* handled elsewhere */
		return NULL;

	case RAW_SESSSETUP_OLD:
		SETUP_REQUEST_SESSION(SMBsesssetupX, 10, 0);
		SSVAL(req->out.vwv, VWV(0), SMB_CHAIN_NONE);
		SSVAL(req->out.vwv, VWV(1), 0);
		SSVAL(req->out.vwv,VWV(2),parms->old.in.bufsize);
		SSVAL(req->out.vwv,VWV(3),parms->old.in.mpx_max);
		SSVAL(req->out.vwv,VWV(4),parms->old.in.vc_num);
		SIVAL(req->out.vwv,VWV(5),parms->old.in.sesskey);
		SSVAL(req->out.vwv,VWV(7),parms->old.in.password.length);
		cli_req_append_blob(req, &parms->old.in.password);
		cli_req_append_string(req, parms->old.in.user, STR_TERMINATE);
		cli_req_append_string(req, parms->old.in.domain, STR_TERMINATE|STR_UPPER);
		cli_req_append_string(req, parms->old.in.os, STR_TERMINATE);
		cli_req_append_string(req, parms->old.in.lanman, STR_TERMINATE);
		break;

	case RAW_SESSSETUP_NT1:
		SETUP_REQUEST_SESSION(SMBsesssetupX, 13, 0);
		SSVAL(req->out.vwv, VWV(0), SMB_CHAIN_NONE);
		SSVAL(req->out.vwv, VWV(1), 0);
		SSVAL(req->out.vwv, VWV(2), parms->nt1.in.bufsize);
		SSVAL(req->out.vwv, VWV(3), parms->nt1.in.mpx_max);
		SSVAL(req->out.vwv, VWV(4), parms->nt1.in.vc_num);
		SIVAL(req->out.vwv, VWV(5), parms->nt1.in.sesskey);
		SSVAL(req->out.vwv, VWV(7), parms->nt1.in.password1.length);
		SSVAL(req->out.vwv, VWV(8), parms->nt1.in.password2.length);
		SIVAL(req->out.vwv, VWV(9), 0); /* reserved */
		SIVAL(req->out.vwv, VWV(11), parms->nt1.in.capabilities);
		cli_req_append_blob(req, &parms->nt1.in.password1);
		cli_req_append_blob(req, &parms->nt1.in.password2);
		cli_req_append_string(req, parms->nt1.in.user, STR_TERMINATE);
		cli_req_append_string(req, parms->nt1.in.domain, STR_TERMINATE|STR_UPPER);
		cli_req_append_string(req, parms->nt1.in.os, STR_TERMINATE);
		cli_req_append_string(req, parms->nt1.in.lanman, STR_TERMINATE);
		break;

	case RAW_SESSSETUP_SPNEGO:
		SETUP_REQUEST_SESSION(SMBsesssetupX, 12, 0);
		SSVAL(req->out.vwv, VWV(0), SMB_CHAIN_NONE);
		SSVAL(req->out.vwv, VWV(1), 0);
		SSVAL(req->out.vwv, VWV(2), parms->spnego.in.bufsize);
		SSVAL(req->out.vwv, VWV(3), parms->spnego.in.mpx_max);
		SSVAL(req->out.vwv, VWV(4), parms->spnego.in.vc_num);
		SIVAL(req->out.vwv, VWV(5), parms->spnego.in.sesskey);
		SSVAL(req->out.vwv, VWV(7), parms->spnego.in.secblob.length);
		SIVAL(req->out.vwv, VWV(8), 0); /* reserved */
		SIVAL(req->out.vwv, VWV(10), parms->spnego.in.capabilities);
		cli_req_append_blob(req, &parms->spnego.in.secblob);
		cli_req_append_string(req, parms->spnego.in.os, STR_TERMINATE);
		cli_req_append_string(req, parms->spnego.in.lanman, STR_TERMINATE);
		cli_req_append_string(req, parms->spnego.in.domain, STR_TERMINATE);
		break;
	}

	if (!cli_request_send(req)) {
		cli_request_destroy(req);
		return NULL;
	}

	return req;
}


/****************************************************************************
 Perform a session setup (async recv)
****************************************************************************/
NTSTATUS smb_raw_session_setup_recv(struct cli_request *req, 
				    TALLOC_CTX *mem_ctx, 
				    union smb_sesssetup *parms) 
{
	uint16_t len;
	char *p;

	if (!cli_request_receive(req)) {
		return cli_request_destroy(req);
	}
	
	if (!NT_STATUS_IS_OK(req->status) &&
	    !NT_STATUS_EQUAL(req->status,NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return cli_request_destroy(req);
	}

	switch (parms->generic.level) {
	case RAW_SESSSETUP_GENERIC:
		/* handled elsewhere */
		return NT_STATUS_INVALID_LEVEL;

	case RAW_SESSSETUP_OLD:
		CLI_CHECK_WCT(req, 3);
		ZERO_STRUCT(parms->old.out);
		parms->old.out.vuid = SVAL(req->in.hdr, HDR_UID);
		parms->old.out.action = SVAL(req->in.vwv, VWV(2));
		p = req->in.data;
		if (p) {
			p += cli_req_pull_string(req, mem_ctx, &parms->old.out.os, p, -1, STR_TERMINATE);
			p += cli_req_pull_string(req, mem_ctx, &parms->old.out.lanman, p, -1, STR_TERMINATE);
			p += cli_req_pull_string(req, mem_ctx, &parms->old.out.domain, p, -1, STR_TERMINATE);
		}
		break;

	case RAW_SESSSETUP_NT1:
		CLI_CHECK_WCT(req, 3);
		ZERO_STRUCT(parms->nt1.out);
		parms->nt1.out.vuid   = SVAL(req->in.hdr, HDR_UID);
		parms->nt1.out.action = SVAL(req->in.vwv, VWV(2));
		p = req->in.data;
		if (p) {
			p += cli_req_pull_string(req, mem_ctx, &parms->nt1.out.os, p, -1, STR_TERMINATE);
			p += cli_req_pull_string(req, mem_ctx, &parms->nt1.out.lanman, p, -1, STR_TERMINATE);
			if (p < (req->in.data + req->in.data_size)) {
				p += cli_req_pull_string(req, mem_ctx, &parms->nt1.out.domain, p, -1, STR_TERMINATE);
			}
		}
		break;

	case RAW_SESSSETUP_SPNEGO:
		CLI_CHECK_WCT(req, 4);
		ZERO_STRUCT(parms->spnego.out);
		parms->spnego.out.vuid   = SVAL(req->in.hdr, HDR_UID);
		parms->spnego.out.action = SVAL(req->in.vwv, VWV(2));
		len                      = SVAL(req->in.vwv, VWV(3));
		p = req->in.data;
		if (!p) {
			break;
		}

		parms->spnego.out.secblob = cli_req_pull_blob(req, mem_ctx, p, len);
		p += parms->spnego.out.secblob.length;
		p += cli_req_pull_string(req, mem_ctx, &parms->spnego.out.os, p, -1, STR_TERMINATE);
		p += cli_req_pull_string(req, mem_ctx, &parms->spnego.out.lanman, p, -1, STR_TERMINATE);
		p += cli_req_pull_string(req, mem_ctx, &parms->spnego.out.domain, p, -1, STR_TERMINATE);
		break;
	}

failed:
	return cli_request_destroy(req);
}

/*
  form an encrypted lanman password from a plaintext password
  and the server supplied challenge
*/
static DATA_BLOB lanman_blob(const char *pass, DATA_BLOB challenge)
{
	DATA_BLOB blob = data_blob(NULL, 24);
	SMBencrypt(pass, challenge.data, blob.data);
	return blob;
}

/*
  form an encrypted NT password from a plaintext password
  and the server supplied challenge
*/
static DATA_BLOB nt_blob(const char *pass, DATA_BLOB challenge)
{
	DATA_BLOB blob = data_blob(NULL, 24);
	SMBNTencrypt(pass, challenge.data, blob.data);
	return blob;
}

/*
  store the user session key for a transport
*/
void cli_session_set_user_session_key(struct cli_session *session,
				   const DATA_BLOB *session_key)
{
	session->user_session_key = data_blob_talloc(session->mem_ctx, 
						     session_key->data, 
						     session_key->length);
}

/*
  setup signing for a NT1 style session setup
*/
static void use_nt1_session_keys(struct cli_session *session, 
				 const char *password, const DATA_BLOB  *nt_response)
{
	struct cli_transport *transport = session->transport; 
	uint8_t nt_hash[16];
	DATA_BLOB session_key = data_blob(NULL, 16);

	E_md4hash(password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, session_key.data);

	cli_transport_simple_set_signing(transport, session_key, *nt_response);

	cli_session_set_user_session_key(session, &session_key);
	data_blob_free(&session_key);
}

/****************************************************************************
 Perform a session setup (sync interface) using generic interface and the old
 style sesssetup call
****************************************************************************/
static NTSTATUS smb_raw_session_setup_generic_old(struct cli_session *session, 
						  TALLOC_CTX *mem_ctx, 
						  union smb_sesssetup *parms) 
{
	NTSTATUS status;
	union smb_sesssetup s2;

	/* use the old interface */
	s2.generic.level = RAW_SESSSETUP_OLD;
	s2.old.in.bufsize = ~0;
	s2.old.in.mpx_max = 50;
	s2.old.in.vc_num = 1;
	s2.old.in.sesskey = parms->generic.in.sesskey;
	s2.old.in.domain = parms->generic.in.domain;
	s2.old.in.user = parms->generic.in.user;
	s2.old.in.os = "Unix";
	s2.old.in.lanman = "Samba";
	
	if (!parms->generic.in.password) {
		s2.old.in.password = data_blob(NULL, 0);
	} else if (session->transport->negotiate.sec_mode & 
		   NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		s2.old.in.password = lanman_blob(parms->generic.in.password, 
						 session->transport->negotiate.secblob);
	} else {
		s2.old.in.password = data_blob(parms->generic.in.password, 
					       strlen(parms->generic.in.password));
	}
	
	status = smb_raw_session_setup(session, mem_ctx, &s2);
	
	data_blob_free(&s2.old.in.password);
	
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	parms->generic.out.vuid = s2.old.out.vuid;
	parms->generic.out.os = s2.old.out.os;
	parms->generic.out.lanman = s2.old.out.lanman;
	parms->generic.out.domain = s2.old.out.domain;
	
	return NT_STATUS_OK;
}

/****************************************************************************
 Perform a session setup (sync interface) using generic interface and the NT1
 style sesssetup call
****************************************************************************/
static NTSTATUS smb_raw_session_setup_generic_nt1(struct cli_session *session, 
						  TALLOC_CTX *mem_ctx,
						  union smb_sesssetup *parms) 
{
	NTSTATUS status;
	union smb_sesssetup s2;

	s2.generic.level = RAW_SESSSETUP_NT1;
	s2.nt1.in.bufsize = ~0;
	s2.nt1.in.mpx_max = 50;
	s2.nt1.in.vc_num = 1;
	s2.nt1.in.sesskey = parms->generic.in.sesskey;
	s2.nt1.in.capabilities = parms->generic.in.capabilities;
	s2.nt1.in.domain = parms->generic.in.domain;
	s2.nt1.in.user = parms->generic.in.user;
	s2.nt1.in.os = "Unix";
	s2.nt1.in.lanman = "Samba";

	if (!parms->generic.in.password) {
		s2.nt1.in.password1 = data_blob(NULL, 0);
		s2.nt1.in.password2 = data_blob(NULL, 0);
	} else if (session->transport->negotiate.sec_mode & 
		   NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		s2.nt1.in.password1 = lanman_blob(parms->generic.in.password, 
						  session->transport->negotiate.secblob);
		s2.nt1.in.password2 = nt_blob(parms->generic.in.password, 
					      session->transport->negotiate.secblob);
		use_nt1_session_keys(session, parms->generic.in.password, &s2.nt1.in.password2);

	} else {
		s2.nt1.in.password1 = data_blob(parms->generic.in.password, 
						strlen(parms->generic.in.password));
		s2.nt1.in.password2 = data_blob(NULL, 0);
	}

	status = smb_raw_session_setup(session, mem_ctx, &s2);
		
	data_blob_free(&s2.nt1.in.password1);
	data_blob_free(&s2.nt1.in.password2);
		
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	parms->generic.out.vuid = s2.nt1.out.vuid;
	parms->generic.out.os = s2.nt1.out.os;
	parms->generic.out.lanman = s2.nt1.out.lanman;
	parms->generic.out.domain = s2.nt1.out.domain;

	return NT_STATUS_OK;
}

/****************************************************************************
 Perform a session setup (sync interface) using generic interface and the SPNEGO
 style sesssetup call
****************************************************************************/
static NTSTATUS smb_raw_session_setup_generic_spnego(struct cli_session *session, 
						  TALLOC_CTX *mem_ctx,
						  union smb_sesssetup *parms) 
{
	NTSTATUS status;
	union smb_sesssetup s2;

	s2.generic.level = RAW_SESSSETUP_SPNEGO;
	s2.spnego.in.bufsize = ~0;
	s2.spnego.in.mpx_max = 50;
	s2.spnego.in.vc_num = 1;
	s2.spnego.in.sesskey = parms->generic.in.sesskey;
	s2.spnego.in.capabilities = parms->generic.in.capabilities;
	s2.spnego.in.domain = parms->generic.in.domain;
	s2.spnego.in.os = "Unix";
	s2.spnego.in.lanman = "Samba";
	s2.spnego.out.vuid = UID_FIELD_INVALID;

	cli_temp_set_signing(session->transport);

	status = gensec_client_start(&session->gensec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC client mode: %s\n", nt_errstr(status)));
		goto done;
	}

	status = gensec_set_domain(session->gensec, parms->generic.in.domain);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client domain to %s: %s\n", 
			  parms->generic.in.domain, nt_errstr(status)));
		goto done;
	}

	status = gensec_set_username(session->gensec, parms->generic.in.user);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client username to %s: %s\n", 
			  parms->generic.in.user, nt_errstr(status)));
		goto done;
	}

	status = gensec_set_password(session->gensec, parms->generic.in.password);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client password: %s\n", 
			  nt_errstr(status)));
		goto done;
	}

	status = gensec_start_mech_by_oid(session->gensec, OID_SPNEGO);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client SPNEGO mechanism: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	status = gensec_update(session->gensec, mem_ctx,
			       session->transport->negotiate.secblob,
			       &s2.spnego.in.secblob);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto done;
	}

	while(1) {
		session->vuid = s2.spnego.out.vuid;
		status = smb_raw_session_setup(session, mem_ctx, &s2);
		session->vuid = UID_FIELD_INVALID;
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			goto done;
		}

		status = gensec_update(session->gensec, mem_ctx,
				       s2.spnego.out.secblob,
				       &s2.spnego.in.secblob);

		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			goto done;
		}
	}

done:
	if (NT_STATUS_IS_OK(status)) {
		DATA_BLOB null_data_blob = data_blob(NULL, 0);
		DATA_BLOB session_key = data_blob(NULL, 0);
		
		status = gensec_session_key(session->gensec, &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		cli_transport_simple_set_signing(session->transport, session_key, null_data_blob);

		cli_session_set_user_session_key(session, &session_key);

		parms->generic.out.vuid = s2.spnego.out.vuid;
		parms->generic.out.os = s2.spnego.out.os;
		parms->generic.out.lanman = s2.spnego.out.lanman;
		parms->generic.out.domain = s2.spnego.out.domain;
	}

	return status;
}

/****************************************************************************
 Perform a session setup (sync interface) using generic interface
****************************************************************************/
static NTSTATUS smb_raw_session_setup_generic(struct cli_session *session, 
					      TALLOC_CTX *mem_ctx,
					      union smb_sesssetup *parms) 
{
	if (session->transport->negotiate.protocol < PROTOCOL_LANMAN1) {
		/* no session setup at all in earliest protocols */
		ZERO_STRUCT(parms->generic.out);
		return NT_STATUS_OK;
	}

	/* see if we need to use the original session setup interface */
	if (session->transport->negotiate.protocol < PROTOCOL_NT1) {
		return smb_raw_session_setup_generic_old(session, mem_ctx, parms);
	}

	/* see if we should use the NT1 interface */
	if (!(parms->generic.in.capabilities & CAP_EXTENDED_SECURITY)) {
		return smb_raw_session_setup_generic_nt1(session, mem_ctx, parms);
	}

	/* default to using SPNEGO/NTLMSSP */
	return smb_raw_session_setup_generic_spnego(session, mem_ctx, parms);
}


/****************************************************************************
 Perform a session setup (sync interface)
this interface allows for RAW_SESSSETUP_GENERIC to auto-select session
setup variant based on negotiated protocol options
****************************************************************************/
NTSTATUS smb_raw_session_setup(struct cli_session *session, TALLOC_CTX *mem_ctx, 
			       union smb_sesssetup *parms) 
{
	struct cli_request *req;

	if (parms->generic.level == RAW_SESSSETUP_GENERIC) {
		return smb_raw_session_setup_generic(session, mem_ctx, parms);
	}

	req = smb_raw_session_setup_send(session, parms);
	return smb_raw_session_setup_recv(req, mem_ctx, parms);
}


/****************************************************************************
 Send a uloggoff (async send)
*****************************************************************************/
struct cli_request *smb_raw_ulogoff_send(struct cli_session *session)
{
	struct cli_request *req;

	SETUP_REQUEST_SESSION(SMBulogoffX, 2, 0);

	SSVAL(req->out.vwv, VWV(0), SMB_CHAIN_NONE);
	SSVAL(req->out.vwv, VWV(1), 0);

	if (!cli_request_send(req)) {
		cli_request_destroy(req);
		return NULL;
	}

	return req;
}

/****************************************************************************
 Send a uloggoff (sync interface)
*****************************************************************************/
NTSTATUS smb_raw_ulogoff(struct cli_session *session)
{
	struct cli_request *req = smb_raw_ulogoff_send(session);
	return cli_request_simple_recv(req);
}


/****************************************************************************
 Send a SMBexit
****************************************************************************/
NTSTATUS smb_raw_exit(struct cli_session *session)
{
	struct cli_request *req;

	req = cli_request_setup_session(session, SMBexit, 0, 0);

	if (cli_request_send(req)) {
		cli_request_receive(req);
	}
	return cli_request_destroy(req);
}
