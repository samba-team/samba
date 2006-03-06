
/* 
   Unix SMB/CIFS implementation.
   handle SMBsessionsetup
   Copyright (C) Andrew Tridgell                      1998-2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2005
   Copyright (C) Jim McDonough                        2002
   Copyright (C) Luke Howard                          2003
   Copyright (C) Stefan Metzmacher                    2005
   
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
#include "version.h"
#include "auth/auth.h"
#include "smb_server/smb_server.h"
#include "smbd/service_stream.h"

/*
  setup the OS, Lanman and domain portions of a session setup reply
*/
static void sesssetup_common_strings(struct smbsrv_request *req,
				     char **os, char **lanman, char **domain)
{
	(*os) = talloc_asprintf(req, "Unix");
	(*lanman) = talloc_asprintf(req, "Samba %s", SAMBA_VERSION_STRING);
	(*domain) = talloc_asprintf(req, "%s", lp_workgroup());
}


/*
  handler for old style session setup
*/
static NTSTATUS sesssetup_old(struct smbsrv_request *req, union smb_sesssetup *sess)
{
	NTSTATUS status;
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info;
	struct smbsrv_session *smb_sess;
	struct socket_address *remote_address;
	const char *remote_machine = NULL;

	sess->old.out.vuid = 0;
	sess->old.out.action = 0;

	if (!req->smb_conn->negotiate.done_sesssetup) {
		req->smb_conn->negotiate.max_send = sess->old.in.bufsize;
	}
	
	if (req->smb_conn->negotiate.calling_name) {
		remote_machine = req->smb_conn->negotiate.calling_name->name;
	}
	
	remote_address = socket_get_peer_addr(req->smb_conn->connection->socket, req);
	NT_STATUS_HAVE_NO_MEMORY(remote_address);

	if (!remote_machine) {
		remote_machine = remote_address->addr;
	}

	user_info = talloc(req, struct auth_usersupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(user_info);
	
	user_info->mapped_state = False;
	user_info->logon_parameters = 0;
	user_info->flags = 0;
	user_info->client.account_name = sess->old.in.user;
	user_info->client.domain_name = sess->old.in.domain;
	user_info->workstation_name = remote_machine;
	user_info->remote_host = talloc_steal(user_info, remote_address);
	
	user_info->password_state = AUTH_PASSWORD_RESPONSE;
	user_info->password.response.lanman = sess->old.in.password;
	user_info->password.response.lanman.data = talloc_steal(user_info, sess->old.in.password.data);
	user_info->password.response.nt = data_blob(NULL, 0);

	status = auth_check_password(req->smb_conn->negotiate.auth_context,
				     req, user_info, &server_info);
	if (!NT_STATUS_IS_OK(status)) {
		return auth_nt_status_squash(status);
	}

	/* This references server_info into session_info */
	status = auth_generate_session_info(req, server_info, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return auth_nt_status_squash(status);
	}

	/* allocate a new session */
	smb_sess = smbsrv_session_new(req->smb_conn, NULL);
	if (!smb_sess) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Ensure this is marked as a 'real' vuid, not one
	 * simply valid for the session setup leg */
	status = smbsrv_session_sesssetup_finished(smb_sess, session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return auth_nt_status_squash(status);
	}

	/* To correctly process any AndX packet (like a tree connect)
	 * we need to fill in the session on the request here */
	req->session = smb_sess;
	sess->old.out.vuid = smb_sess->vuid;

	sesssetup_common_strings(req, 
				 &sess->old.out.os,
				 &sess->old.out.lanman,
				 &sess->old.out.domain);

	return NT_STATUS_OK;
}


/*
  handler for NT1 style session setup
*/
static NTSTATUS sesssetup_nt1(struct smbsrv_request *req, union smb_sesssetup *sess)
{
	NTSTATUS status;
	struct auth_context *auth_context;
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info;
	struct smbsrv_session *smb_sess;
	struct socket_address *remote_address;
	const char *remote_machine = NULL;
	
	sess->nt1.out.vuid = 0;
	sess->nt1.out.action = 0;

	if (!req->smb_conn->negotiate.done_sesssetup) {
		req->smb_conn->negotiate.max_send = sess->nt1.in.bufsize;
		req->smb_conn->negotiate.client_caps = sess->nt1.in.capabilities;
	}

	if (req->smb_conn->negotiate.oid) {
		if (sess->nt1.in.user && *sess->nt1.in.user) {
			/* We can't accept a normal login, because we
			 * don't have a challenge */
			return NT_STATUS_LOGON_FAILURE;
		}

		/* TODO: should we use just "anonymous" here? */
		status = auth_context_create(req, lp_auth_methods(), 
					     &auth_context, 
					     req->smb_conn->connection->event.ctx);
		NT_STATUS_NOT_OK_RETURN(status);
	} else {
		auth_context = req->smb_conn->negotiate.auth_context;
	}

	if (req->smb_conn->negotiate.calling_name) {
		remote_machine = req->smb_conn->negotiate.calling_name->name;
	}

	remote_address = socket_get_peer_addr(req->smb_conn->connection->socket, req);
	NT_STATUS_HAVE_NO_MEMORY(remote_address);

	if (!remote_machine) {
		remote_machine = remote_address->addr;
	}

	user_info = talloc(req, struct auth_usersupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(user_info);
	
	user_info->mapped_state = False;
	user_info->logon_parameters = 0;
	user_info->flags = 0;
	user_info->client.account_name = sess->nt1.in.user;
	user_info->client.domain_name = sess->nt1.in.domain;
	user_info->workstation_name = remote_machine;
	user_info->remote_host = talloc_steal(user_info, remote_address);
	
	user_info->password_state = AUTH_PASSWORD_RESPONSE;
	user_info->password.response.lanman = sess->nt1.in.password1;
	user_info->password.response.lanman.data = talloc_steal(user_info, sess->nt1.in.password1.data);
	user_info->password.response.nt = sess->nt1.in.password2;
	user_info->password.response.nt.data = talloc_steal(user_info, sess->nt1.in.password2.data);

	status = auth_check_password(auth_context, req, user_info, &server_info);
	if (!NT_STATUS_IS_OK(status)) {
		return auth_nt_status_squash(status);
	}

	/* This references server_info into session_info */
	status = auth_generate_session_info(req, server_info, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return auth_nt_status_squash(status);
	}

	/* allocate a new session */
	smb_sess = smbsrv_session_new(req->smb_conn, NULL);
	if (!smb_sess) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Ensure this is marked as a 'real' vuid, not one
	 * simply valid for the session setup leg */
	status = smbsrv_session_sesssetup_finished(smb_sess, session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return auth_nt_status_squash(status);
	}

	/* To correctly process any AndX packet (like a tree connect)
	 * we need to fill in the session on the request here */
	req->session = smb_sess;
	sess->nt1.out.vuid = smb_sess->vuid;

	sesssetup_common_strings(req, 
				 &sess->nt1.out.os,
				 &sess->nt1.out.lanman,
				 &sess->nt1.out.domain);

	if (!session_info->server_info->authenticated) {
		return NT_STATUS_OK;
	}

 	if (!srv_setup_signing(req->smb_conn, &session_info->session_key, &sess->nt1.in.password2)) {
		/* Already signing, or disabled */
		return NT_STATUS_OK;
	}

	/* Force check of the request packet, now we know the session key */
	req_signing_check_incoming(req);
/* TODO: why don't we check the result here? */

	/* Unfortunetly win2k3 as a client doesn't sign the request
	 * packet here, so we have to force signing to start again */

	srv_signing_restart(req->smb_conn,  &session_info->session_key, &sess->nt1.in.password2);

	return NT_STATUS_OK;
}


/*
  handler for SPNEGO style session setup
*/
static NTSTATUS sesssetup_spnego(struct smbsrv_request *req, union smb_sesssetup *sess)
{
	NTSTATUS status;
	NTSTATUS skey_status;
	struct smbsrv_session *smb_sess = NULL;
	struct auth_session_info *session_info = NULL;
	DATA_BLOB session_key;
	uint16_t vuid;

	sess->spnego.out.vuid = 0;
	sess->spnego.out.action = 0;

	sesssetup_common_strings(req, 
				 &sess->spnego.out.os,
				 &sess->spnego.out.lanman,
				 &sess->spnego.out.workgroup);

	if (!req->smb_conn->negotiate.done_sesssetup) {
		req->smb_conn->negotiate.max_send = sess->nt1.in.bufsize;
		req->smb_conn->negotiate.client_caps = sess->nt1.in.capabilities;
	}

	vuid = SVAL(req->in.hdr,HDR_UID);

	/* lookup an existing session */
	smb_sess = smbsrv_session_find_sesssetup(req->smb_conn, vuid);
	if (!smb_sess) {
		struct gensec_security *gensec_ctx;

		status = gensec_server_start(req, &gensec_ctx,
					     req->smb_conn->connection->event.ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC server code: %s\n", nt_errstr(status)));
			return status;
		}

		gensec_set_credentials(gensec_ctx, req->smb_conn->negotiate.server_credentials);

		gensec_set_target_service(gensec_ctx, "cifs");

		gensec_want_feature(gensec_ctx, GENSEC_FEATURE_SESSION_KEY);

		status = gensec_start_mech_by_oid(gensec_ctx, req->smb_conn->negotiate.oid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC %s server code: %s\n", 
				  gensec_get_name_by_oid(req->smb_conn->negotiate.oid), nt_errstr(status)));
			return status;
		}

		/* allocate a new session */
		smb_sess = smbsrv_session_new(req->smb_conn, gensec_ctx);
	}

	if (!smb_sess) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!smb_sess->gensec_ctx) {
		status = NT_STATUS_INTERNAL_ERROR;
		DEBUG(1, ("Internal ERROR: no gensec_ctx on session: %s\n", nt_errstr(status)));
		goto failed;
	}

	status = gensec_update(smb_sess->gensec_ctx, req, sess->spnego.in.secblob, &sess->spnego.out.secblob);
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		sess->spnego.out.vuid = smb_sess->vuid;
		return status;
	} else if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = gensec_session_info(smb_sess->gensec_ctx, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	skey_status = gensec_session_key(smb_sess->gensec_ctx, &session_key);
	if (NT_STATUS_IS_OK(skey_status) &&
	    session_info->server_info->authenticated &&
	    srv_setup_signing(req->smb_conn, &session_key, NULL)) {
		/* Force check of the request packet, now we know the session key */
		req_signing_check_incoming(req);

		srv_signing_restart(req->smb_conn, &session_key, NULL);
	}

	/* Ensure this is marked as a 'real' vuid, not one
	 * simply valid for the session setup leg */
	status = smbsrv_session_sesssetup_finished(smb_sess, session_info);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}
	req->session = smb_sess;

	sess->spnego.out.vuid = smb_sess->vuid;
	return NT_STATUS_OK;

failed:
	talloc_free(smb_sess);
	return auth_nt_status_squash(status);
}

/*
  backend for sessionsetup call - this takes all 3 variants of the call
*/
NTSTATUS smbsrv_sesssetup_backend(struct smbsrv_request *req,
				  union smb_sesssetup *sess)
{
	NTSTATUS status = NT_STATUS_INVALID_LEVEL;

	switch (sess->old.level) {
		case RAW_SESSSETUP_OLD:
			status = sesssetup_old(req, sess);
			break;
		case RAW_SESSSETUP_NT1:
			status = sesssetup_nt1(req, sess);
			break;
		case RAW_SESSSETUP_SPNEGO:
			status = sesssetup_spnego(req, sess);
			break;
	}

	if (NT_STATUS_IS_OK(status)) {
		req->smb_conn->negotiate.done_sesssetup = True;
	}

	return status;
}
