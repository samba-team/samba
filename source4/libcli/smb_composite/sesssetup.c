/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2005
   
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
/*
  a composite API for making handling a generic async session setup
*/

#include "includes.h"
#include <tevent.h>
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/auth/libcli_auth.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "version.h"
#include "param/param.h"
#include "libcli/smb/smbXcli_base.h"

struct sesssetup_state {
	struct smbcli_session *session;
	union smb_sesssetup setup;
	const char *chosen_oid;
	NTSTATUS remote_status;
	NTSTATUS gensec_status;
	struct smb_composite_sesssetup *io;
	struct smbcli_request *req;
	struct smbcli_request *check_req;
	unsigned int logon_retries;
};

static int sesssetup_state_destructor(struct sesssetup_state *state)
{
	if (state->req) {
		talloc_free(state->req);
		state->req = NULL;
	}

	return 0;
}

static NTSTATUS session_setup_old(struct composite_context *c,
				  struct smbcli_session *session, 
				  struct smb_composite_sesssetup *io,
				  struct smbcli_request **req); 
static NTSTATUS session_setup_nt1(struct composite_context *c,
				  struct smbcli_session *session, 
				  struct smb_composite_sesssetup *io,
				  struct smbcli_request **req); 
static NTSTATUS session_setup_spnego_restart(struct composite_context *c,
					     struct smbcli_session *session,
					     struct smb_composite_sesssetup *io);
static NTSTATUS session_setup_spnego(struct composite_context *c,
				     struct smbcli_session *session, 
				     struct smb_composite_sesssetup *io,
				     struct smbcli_request **req);
static void smb_composite_sesssetup_spnego_done1(struct tevent_req *subreq);
static void smb_composite_sesssetup_spnego_done2(struct tevent_req *subreq);


/*
  handler for completion of a smbcli_request sub-request
*/
static void request_handler(struct smbcli_request *req)
{
	struct composite_context *c = (struct composite_context *)req->async.private_data;
	struct sesssetup_state *state = talloc_get_type(c->private_data, struct sesssetup_state);
	struct smbcli_session *session = req->session;
	DATA_BLOB null_data_blob = data_blob(NULL, 0);
	NTSTATUS session_key_err, nt_status;
	struct smbcli_request *check_req = NULL;
	const char *os = NULL;
	const char *lanman = NULL;

	if (req->sign_caller_checks) {
		req->do_not_free = true;
		check_req = req;
	}

	state->remote_status = smb_raw_sesssetup_recv(req, state, &state->setup);
	c->status = state->remote_status;
	state->req = NULL;

	/*
	 * we only need to check the signature if the
	 * NT_STATUS_OK is returned
	 */
	if (!NT_STATUS_IS_OK(state->remote_status)) {
		talloc_free(check_req);
		check_req = NULL;
	}

	switch (state->setup.old.level) {
	case RAW_SESSSETUP_OLD:
		state->io->out.vuid = state->setup.old.out.vuid;
		/* This doesn't work, as this only happens on old
		 * protocols, where this comparison won't match. */
		if (NT_STATUS_EQUAL(c->status, NT_STATUS_LOGON_FAILURE)) {
			/* we neet to reset the vuid for a new try */
			session->vuid = 0;
			if (cli_credentials_wrong_password(state->io->in.credentials)) {
				nt_status = session_setup_old(c, session, 
							      state->io, 
							      &state->req);
				if (NT_STATUS_IS_OK(nt_status)) {
					talloc_free(check_req);
					c->status = nt_status;
					composite_continue_smb(c, state->req, request_handler, c);
					return;
				}
			}
		}
		if (!NT_STATUS_IS_OK(c->status)) {
			composite_error(c, c->status);
			return;
		}
		os = state->setup.old.out.os;
		lanman = state->setup.old.out.lanman;
		break;

	case RAW_SESSSETUP_NT1:
		state->io->out.vuid = state->setup.nt1.out.vuid;
		if (NT_STATUS_EQUAL(c->status, NT_STATUS_LOGON_FAILURE)) {
			/* we need to reset the vuid for a new try */
			session->vuid = 0;
			if (cli_credentials_wrong_password(state->io->in.credentials)) {
				nt_status = session_setup_nt1(c, session, 
							      state->io, 
							      &state->req);
				if (NT_STATUS_IS_OK(nt_status)) {
					talloc_free(check_req);
					c->status = nt_status;
					composite_continue_smb(c, state->req, request_handler, c);
					return;
				}
			}
		}
		if (!NT_STATUS_IS_OK(c->status)) {
			composite_error(c, c->status);
			return;
		}
		os = state->setup.nt1.out.os;
		lanman = state->setup.nt1.out.lanman;
		break;

	case RAW_SESSSETUP_SPNEGO:
		state->io->out.vuid = state->setup.spnego.out.vuid;
		if (NT_STATUS_EQUAL(c->status, NT_STATUS_LOGON_FAILURE)) {
			const char *principal;

			/* we need to reset the vuid for a new try */
			session->vuid = 0;

			principal = gensec_get_target_principal(session->gensec);
			if (principal == NULL) {
				const char *hostname = gensec_get_target_hostname(session->gensec);
				const char *service  = gensec_get_target_service(session->gensec);
				if (hostname != NULL && service != NULL) {
					principal = talloc_asprintf(state, "%s/%s", service, hostname);
				}
			}
			if (cli_credentials_failed_kerberos_login(state->io->in.credentials, principal, &state->logon_retries) ||
			    cli_credentials_wrong_password(state->io->in.credentials)) {
				struct tevent_req *subreq = NULL;

				nt_status = session_setup_spnego_restart(c, session, state->io);
				if (!NT_STATUS_IS_OK(nt_status)) {
					DEBUG(1, ("session_setup_spnego_restart() failed: %s\n",
						  nt_errstr(nt_status)));
					c->status = nt_status;
					composite_error(c, c->status);
					return;
				}

				subreq = gensec_update_send(state, c->event_ctx,
							    session->gensec,
							    state->setup.spnego.out.secblob);
				if (composite_nomem(subreq, c)) {
					return;
				}
				tevent_req_set_callback(subreq,
							smb_composite_sesssetup_spnego_done1,
							c);
				return;
			}
		}
		if (GENSEC_UPDATE_IS_NTERROR(c->status)) {
			composite_error(c, c->status);
			return;
		}
		if (NT_STATUS_EQUAL(state->gensec_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			struct tevent_req *subreq = NULL;

			/* The status value here, from the earlier pass at GENSEC is
			 * vital to the security of the system.  Even if the other end
			 * accepts, if GENSEC claims 'MORE_PROCESSING_REQUIRED' then
			 * you must keep feeding it blobs, or else the remote
			 * host/attacker might avoid mutal authentication
			 * requirements */

			subreq = gensec_update_send(state, c->event_ctx,
						    session->gensec,
						    state->setup.spnego.out.secblob);
			if (composite_nomem(subreq, c)) {
				return;
			}
			tevent_req_set_callback(subreq,
						smb_composite_sesssetup_spnego_done2,
						c);
			if (NT_STATUS_IS_OK(state->remote_status)) {
				state->check_req = check_req;
			} else {
				TALLOC_FREE(check_req);
			}
			return;
		} else {
			state->setup.spnego.in.secblob = data_blob(NULL, 0);
		}

		if (cli_credentials_is_anonymous(state->io->in.credentials)) {
			/*
			 * anonymous => no signing
			 */
		} else if (NT_STATUS_IS_OK(state->remote_status)) {
			DATA_BLOB session_key;

			if (state->setup.spnego.in.secblob.length) {
				c->status = NT_STATUS_INTERNAL_ERROR;
				composite_error(c, c->status);
				return;
			}
			session_key_err = gensec_session_key(session->gensec, session, &session_key);
			if (NT_STATUS_IS_OK(session_key_err)) {
				smb1cli_conn_activate_signing(session->transport->conn,
							      session_key,
							      null_data_blob);
			}

			c->status = smb1cli_session_set_session_key(session->smbXcli,
								    session_key);
			data_blob_free(&session_key);
			if (!NT_STATUS_IS_OK(c->status)) {
				composite_error(c, c->status);
				return;
			}
		}

		os = state->setup.spnego.out.os;
		lanman = state->setup.spnego.out.lanman;
		break;

	case RAW_SESSSETUP_SMB2:
		c->status = NT_STATUS_INTERNAL_ERROR;
		composite_error(c, c->status);
		return;
	}

	if (check_req) {
		bool ok;

		check_req->sign_caller_checks = false;

		ok = smb1cli_conn_check_signing(check_req->transport->conn,
						check_req->in.buffer, 1);
		TALLOC_FREE(check_req);
		if (!ok) {
			c->status = NT_STATUS_ACCESS_DENIED;
			composite_error(c, c->status);
			return;
		}
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		composite_error(c, c->status);
		return;
	}

	if (os) {
		session->os = talloc_strdup(session, os);
		if (composite_nomem(session->os, c)) return;
	} else {
		session->os = NULL;
	}
	if (lanman) {
		session->lanman = talloc_strdup(session, lanman);
		if (composite_nomem(session->lanman, c)) return;
	} else {
		session->lanman = NULL;
	}

	composite_done(c);
}


/*
  send a nt1 style session setup
*/
static NTSTATUS session_setup_nt1(struct composite_context *c,
				  struct smbcli_session *session, 
				  struct smb_composite_sesssetup *io,
				  struct smbcli_request **req) 
{
	NTSTATUS nt_status = NT_STATUS_INTERNAL_ERROR;
	struct sesssetup_state *state = talloc_get_type(c->private_data,
							struct sesssetup_state);
	const char *domain = cli_credentials_get_domain(io->in.credentials);

	/*
	 * domain controllers tend to reject the NTLM v2 blob
	 * if the netbiosname is not valid (e.g. IP address or FQDN)
	 * so just leave it away (as Windows client do)
	 */
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(state, NULL, domain);

	DATA_BLOB session_key = data_blob(NULL, 0);
	int flags = CLI_CRED_NTLM_AUTH;

	if (session->options.lanman_auth) {
		flags |= CLI_CRED_LANMAN_AUTH;
	}

	if (session->options.ntlmv2_auth) {
		flags |= CLI_CRED_NTLMv2_AUTH;
	}

	state->setup.nt1.level           = RAW_SESSSETUP_NT1;
	state->setup.nt1.in.bufsize      = session->transport->options.max_xmit;
	state->setup.nt1.in.mpx_max      = session->transport->options.max_mux;
	state->setup.nt1.in.vc_num       = 1;
	state->setup.nt1.in.sesskey      = io->in.sesskey;
	state->setup.nt1.in.capabilities = io->in.capabilities;
	state->setup.nt1.in.os           = "Unix";
	state->setup.nt1.in.lanman       = talloc_asprintf(state, "Samba %s", SAMBA_VERSION_STRING);

	cli_credentials_get_ntlm_username_domain(io->in.credentials, state, 
						 &state->setup.nt1.in.user,
						 &state->setup.nt1.in.domain);
	

	if (session->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		if (!cli_credentials_is_anonymous(io->in.credentials) &&
		    session->options.ntlmv2_auth &&
		    session->transport->options.use_spnego)
		{
			/*
			 * Don't send an NTLMv2_RESPONSE without NTLMSSP
			 * if we want to use spnego
			 */
			return NT_STATUS_INVALID_PARAMETER;
		}

		nt_status = cli_credentials_get_ntlm_response(io->in.credentials, state, 
							      &flags, 
							      session->transport->negotiate.secblob, 
							      NULL, /* server_timestamp */
							      names_blob,
							      &state->setup.nt1.in.password1,
							      &state->setup.nt1.in.password2,
							      NULL, &session_key);
		NT_STATUS_NOT_OK_RETURN(nt_status);
	} else if (session->options.plaintext_auth) {
		const char *password = cli_credentials_get_password(io->in.credentials);
		state->setup.nt1.in.password1 = data_blob_talloc(state, password, strlen(password));
		state->setup.nt1.in.password2 = data_blob(NULL, 0);
	} else {
		/* could match windows client and return 'cannot logon from this workstation', but it just confuses everybody */
		return NT_STATUS_INVALID_PARAMETER;
	}

	*req = smb_raw_sesssetup_send(session, &state->setup);
	if (!*req) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		/*
		 * plain text => no signing
		 */
		return (*req)->status;
	}

	if (cli_credentials_is_anonymous(io->in.credentials)) {
		/*
		 * anonymous => no signing
		 */
		return (*req)->status;
	}

	smb1cli_conn_activate_signing(session->transport->conn,
				      session_key,
				      state->setup.nt1.in.password2);

	nt_status = smb1cli_session_set_session_key(session->smbXcli,
						    session_key);
	data_blob_free(&session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	return (*req)->status;
}


/*
  old style session setup (pre NT1 protocol level)
*/
static NTSTATUS session_setup_old(struct composite_context *c,
				  struct smbcli_session *session, 
				  struct smb_composite_sesssetup *io,
				  struct smbcli_request **req) 
{
	NTSTATUS nt_status;
	struct sesssetup_state *state = talloc_get_type(c->private_data,
							struct sesssetup_state);
	const char *password = cli_credentials_get_password(io->in.credentials);

	/*
	 * domain controllers tend to reject the NTLM v2 blob
	 * if the netbiosname is not valid (e.g. IP address or FQDN)
	 * so just leave it away (as Windows client do)
	 */
	DATA_BLOB session_key;

	state->setup.old.level      = RAW_SESSSETUP_OLD;
	state->setup.old.in.bufsize = session->transport->options.max_xmit;
	state->setup.old.in.mpx_max = session->transport->options.max_mux;
	state->setup.old.in.vc_num  = 1;
	state->setup.old.in.sesskey = io->in.sesskey;
	state->setup.old.in.os      = "Unix";
	state->setup.old.in.lanman  = talloc_asprintf(state, "Samba %s", SAMBA_VERSION_STRING);
	cli_credentials_get_ntlm_username_domain(io->in.credentials, state, 
						 &state->setup.old.in.user,
						 &state->setup.old.in.domain);
	
	if (session->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		DATA_BLOB names_blob = data_blob_null;
		int flags = 0;

		if (!cli_credentials_is_anonymous(io->in.credentials) &&
		    !session->options.lanman_auth)
		{
			return NT_STATUS_INVALID_PARAMETER;
		}

		flags |= CLI_CRED_LANMAN_AUTH;

		nt_status = cli_credentials_get_ntlm_response(io->in.credentials, state, 
							      &flags, 
							      session->transport->negotiate.secblob, 
							      NULL, /* server_timestamp */
							      names_blob,
							      &state->setup.old.in.password,
							      NULL,
							      NULL, &session_key);
		NT_STATUS_NOT_OK_RETURN(nt_status);

		nt_status = smb1cli_session_set_session_key(session->smbXcli,
							    session_key);
		data_blob_free(&session_key);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	} else if (session->options.plaintext_auth) {
		state->setup.old.in.password = data_blob_talloc(state, password, strlen(password));
	} else {
		/* could match windows client and return 'cannot logon from this workstation', but it just confuses everybody */
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	*req = smb_raw_sesssetup_send(session, &state->setup);
	if (!*req) {
		return NT_STATUS_NO_MEMORY;
	}
	return (*req)->status;
}

static NTSTATUS session_setup_spnego_restart(struct composite_context *c,
					     struct smbcli_session *session,
					     struct smb_composite_sesssetup *io)
{
	struct sesssetup_state *state = talloc_get_type(c->private_data, struct sesssetup_state);
	NTSTATUS status;

	status = gensec_client_start(session, &session->gensec,
				     io->in.gensec_settings);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC client mode: %s\n", nt_errstr(status)));
		return status;
	}

	gensec_want_feature(session->gensec, GENSEC_FEATURE_SESSION_KEY);

	status = gensec_set_credentials(session->gensec, io->in.credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client credentials: %s\n", 
			  nt_errstr(status)));
		return status;
	}

	status = gensec_set_target_hostname(session->gensec,
			smbXcli_conn_remote_name(session->transport->conn));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target hostname: %s\n", 
			  nt_errstr(status)));
		return status;
	}

	status = gensec_set_target_service(session->gensec, "cifs");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target service: %s\n", 
			  nt_errstr(status)));
		return status;
	}

	state->setup.spnego.out.secblob =
			session->transport->negotiate.secblob;
	if (session->transport->negotiate.secblob.length) {
		state->chosen_oid = GENSEC_OID_SPNEGO;
		status = gensec_start_mech_by_oid(session->gensec,
						  state->chosen_oid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start set GENSEC client mechanism %s: %s\n",
				  gensec_get_name_by_oid(session->gensec,
							 state->chosen_oid),
				  nt_errstr(status)));
			state->setup.spnego.out.secblob = data_blob_null;
			state->chosen_oid = GENSEC_OID_NTLMSSP;
			status = gensec_start_mech_by_oid(session->gensec,
							  state->chosen_oid);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(1, ("Failed to start set (fallback) GENSEC client mechanism %s: %s\n",
					  gensec_get_name_by_oid(session->gensec,
								 state->chosen_oid),
					  nt_errstr(status)));
				return status;
			}
		}
	} else {
		/* without a sec blob, means raw NTLMSSP */
		state->chosen_oid = GENSEC_OID_NTLMSSP;
		status = gensec_start_mech_by_oid(session->gensec,
						  state->chosen_oid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start set GENSEC client mechanism %s: %s\n",
				  gensec_get_name_by_oid(session->gensec,
							 state->chosen_oid),
				  nt_errstr(status)));
			return status;
		}
	}

	state->gensec_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	state->remote_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	return NT_STATUS_OK;
}

/*
  Modern, all singing, all dancing extended security (and possibly SPNEGO) request
*/
static NTSTATUS session_setup_spnego(struct composite_context *c,
				     struct smbcli_session *session,
				     struct smb_composite_sesssetup *io,
				     struct smbcli_request **req)
{
	struct sesssetup_state *state = talloc_get_type(c->private_data, struct sesssetup_state);

	state->setup.spnego.level           = RAW_SESSSETUP_SPNEGO;
	state->setup.spnego.in.bufsize      = session->transport->options.max_xmit;
	state->setup.spnego.in.mpx_max      = session->transport->options.max_mux;
	state->setup.spnego.in.vc_num       = 1;
	state->setup.spnego.in.sesskey      = io->in.sesskey;
	state->setup.spnego.in.capabilities = io->in.capabilities;
	state->setup.spnego.in.os           = "Unix";
	state->setup.spnego.in.lanman       = talloc_asprintf(state, "Samba %s", SAMBA_VERSION_STRING);
	state->setup.spnego.in.workgroup    = io->in.workgroup;

	*req = smb_raw_sesssetup_send(session, &state->setup);
	if (!*req) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * we need to check the signature ourself
	 * as the session key might be the acceptor subkey
	 * which comes within the response itself
	 */
	if (!smb1cli_conn_signing_is_active((*req)->transport->conn)) {
		(*req)->sign_caller_checks = true;
	}

	return (*req)->status;
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
	NTSTATUS status;

	c = composite_create(session, session->transport->ev);
	if (c == NULL) return NULL;

	state = talloc_zero(c, struct sesssetup_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	state->session = session;
	state->io = io;

	talloc_set_destructor(state, sesssetup_state_destructor);

	/* no session setup at all in earliest protocol varients */
	if (session->transport->negotiate.protocol < PROTOCOL_LANMAN1) {
		ZERO_STRUCT(io->out);
		composite_done(c);
		return c;
	}

	/* see what session setup interface we will use */
	if (session->transport->negotiate.protocol < PROTOCOL_NT1) {
		status = session_setup_old(c, session, io, &state->req);
	} else if (!session->transport->options.use_spnego ||
		   !(io->in.capabilities & CAP_EXTENDED_SECURITY)) {
		status = session_setup_nt1(c, session, io, &state->req);
	} else {
		struct tevent_req *subreq = NULL;

		status = session_setup_spnego_restart(c, session, io);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("session_setup_spnego_restart() failed: %s\n",
				  nt_errstr(status)));
			c->status = status;
			composite_error(c, c->status);
			return c;
		}

		subreq = gensec_update_send(state, c->event_ctx,
					    session->gensec,
					    state->setup.spnego.out.secblob);
		if (composite_nomem(subreq, c)) {
			return c;
		}
		tevent_req_set_callback(subreq,
					smb_composite_sesssetup_spnego_done1,
					c);
		return c;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) || 
	    NT_STATUS_IS_OK(status)) {
		composite_continue_smb(c, state->req, request_handler, c);	
		return c;
	}

	composite_error(c, status);
	return c;
}

static void smb_composite_sesssetup_spnego_done1(struct tevent_req *subreq)
{
	struct composite_context *c =
		tevent_req_callback_data(subreq,
		struct composite_context);
	struct sesssetup_state *state =
		talloc_get_type_abort(c->private_data,
		struct sesssetup_state);
	NTSTATUS status;

	status = gensec_update_recv(subreq, state,
				    &state->setup.spnego.in.secblob);
	TALLOC_FREE(subreq);
	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		DEBUG(1, ("Failed initial gensec_update with mechanism %s: %s\n",
			  gensec_get_name_by_oid(state->session->gensec,
						 state->chosen_oid),
			  nt_errstr(status)));
		c->status = status;
		composite_error(c, c->status);
		return;
	}
	state->gensec_status = status;

	status = session_setup_spnego(c, state->session, state->io, &state->req);
	if (!NT_STATUS_IS_OK(status)) {
		c->status = status;
		composite_error(c, c->status);
		return;
	}

	composite_continue_smb(c, state->req, request_handler, c);
}

static void smb_composite_sesssetup_spnego_done2(struct tevent_req *subreq)
{
	struct composite_context *c =
		tevent_req_callback_data(subreq,
		struct composite_context);
	struct sesssetup_state *state =
		talloc_get_type_abort(c->private_data,
		struct sesssetup_state);
	struct smbcli_session *session = state->session;
	NTSTATUS status;
	const char *os = NULL;
	const char *lanman = NULL;

	status = gensec_update_recv(subreq, state,
				    &state->setup.spnego.in.secblob);
	TALLOC_FREE(subreq);
	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		DEBUG(1, ("Failed initial gensec_update with mechanism %s: %s\n",
			  gensec_get_name_by_oid(state->session->gensec,
						 state->chosen_oid),
			  nt_errstr(status)));
		c->status = status;
		composite_error(c, c->status);
		return;
	}
	state->gensec_status = status;

	if (NT_STATUS_IS_OK(state->remote_status)) {
		if (state->setup.spnego.in.secblob.length) {
			c->status = NT_STATUS_INTERNAL_ERROR;
			composite_error(c, c->status);
			return;
		}
	}

	if (state->setup.spnego.in.secblob.length) {
		/*
		 * set the session->vuid value only for calling
		 * smb_raw_sesssetup_send()
		 */
		uint16_t vuid = session->vuid;
		session->vuid = state->io->out.vuid;
		state->req = smb_raw_sesssetup_send(session, &state->setup);
		session->vuid = vuid;
		if (state->req &&
		    !smb1cli_conn_signing_is_active(state->req->transport->conn)) {
			state->req->sign_caller_checks = true;
		}
		composite_continue_smb(c, state->req, request_handler, c);
		return;
	}

	if (cli_credentials_is_anonymous(state->io->in.credentials)) {
		/*
		 * anonymous => no signing
		 */
	} else if (NT_STATUS_IS_OK(state->remote_status)) {
		NTSTATUS session_key_err;
		DATA_BLOB session_key;

		session_key_err = gensec_session_key(session->gensec, session, &session_key);
		if (NT_STATUS_IS_OK(session_key_err)) {
			smb1cli_conn_activate_signing(session->transport->conn,
						      session_key,
						      data_blob_null);
		}

		c->status = smb1cli_session_set_session_key(session->smbXcli,
							    session_key);
		data_blob_free(&session_key);
		if (!NT_STATUS_IS_OK(c->status)) {
			composite_error(c, c->status);
			return;
		}
	}

	os = state->setup.spnego.out.os;
	lanman = state->setup.spnego.out.lanman;

	if (state->check_req) {
		struct smbcli_request *check_req = state->check_req;
		bool ok;

		check_req->sign_caller_checks = false;

		ok = smb1cli_conn_check_signing(check_req->transport->conn,
						check_req->in.buffer, 1);
		TALLOC_FREE(check_req);
		if (!ok) {
			c->status = NT_STATUS_ACCESS_DENIED;
			composite_error(c, c->status);
			return;
		}
	}

	if (os) {
		session->os = talloc_strdup(session, os);
		if (composite_nomem(session->os, c)) return;
	} else {
		session->os = NULL;
	}
	if (lanman) {
		session->lanman = talloc_strdup(session, lanman);
		if (composite_nomem(session->lanman, c)) return;
	} else {
		session->lanman = NULL;
	}

	composite_done(c);
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
