/* 
   Unix SMB/CIFS implementation.
   handle SMBsessionsetup
   Copyright (C) Andrew Tridgell 1998-2001
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jim McDonough        2002
   Copyright (C) Luke Howard          2003

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
  setup the OS, Lanman and domain portions of a session setup reply
*/
static void sesssetup_common_strings(struct smbsrv_request *req,
				     char **os, char **lanman, char **domain)
{
	(*os) = talloc_asprintf(req->mem_ctx, "Unix");
	(*lanman) = talloc_asprintf(req->mem_ctx, "Samba %s", SAMBA_VERSION_STRING);
	(*domain) = talloc_asprintf(req->mem_ctx, "%s", lp_workgroup());
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
	DATA_BLOB null_blob;

	if (!req->smb_conn->negotiate.done_sesssetup) {
		req->smb_conn->negotiate.max_send = sess->old.in.bufsize;
	}

	null_blob.length = 0;

	status = make_user_info_for_reply_enc(&user_info, 
					      sess->old.in.user, sess->old.in.domain,
					      sess->old.in.password,
					      null_blob);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = req->smb_conn->negotiate.auth_context->check_ntlm_password(req->smb_conn->negotiate.auth_context, 
								       user_info, 
								       &server_info);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	status = make_session_info(server_info, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	sess->old.out.action = 0;
	sess->old.out.vuid = smbsrv_register_session(req->smb_conn, session_info, NULL);
	if (sess->old.out.vuid == UID_FIELD_INVALID) {
		return NT_STATUS_ACCESS_DENIED;
	}
	sesssetup_common_strings(req, 
				 &sess->old.out.os,
				 &sess->old.out.lanman,
				 &sess->old.out.domain);

	req->session = smbsrv_session_find(req->smb_conn, sess->old.out.vuid);

	return NT_STATUS_OK;
}


/*
  handler for NT1 style session setup
*/
static NTSTATUS sesssetup_nt1(struct smbsrv_request *req, union smb_sesssetup *sess)
{
	NTSTATUS status;
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info;

	if (!req->smb_conn->negotiate.done_sesssetup) {
		req->smb_conn->negotiate.max_send = sess->nt1.in.bufsize;
		req->smb_conn->negotiate.client_caps = sess->nt1.in.capabilities;
	}

	status = make_user_info_for_reply_enc(&user_info, 
					      sess->nt1.in.user, sess->nt1.in.domain,
					      sess->nt1.in.password1,
					      sess->nt1.in.password2);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = req->smb_conn->negotiate
		.auth_context->check_ntlm_password(req->smb_conn->negotiate
						    .auth_context, 
						   user_info, 
						   &server_info);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	status = make_session_info(server_info, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return nt_status_squash(status);
	}

	sess->nt1.out.action = 0;
	sess->nt1.out.vuid = smbsrv_register_session(req->smb_conn, session_info, NULL);
	if (sess->nt1.out.vuid == UID_FIELD_INVALID) {
		return NT_STATUS_ACCESS_DENIED;
	}
	sesssetup_common_strings(req, 
				 &sess->nt1.out.os,
				 &sess->nt1.out.lanman,
				 &sess->nt1.out.domain);
	
	req->session = smbsrv_session_find(req->smb_conn, sess->nt1.out.vuid);
	if (!session_info->server_info->guest) {
		srv_setup_signing(req->smb_conn, &session_info->session_key, &sess->nt1.in.password2);
	}

	return NT_STATUS_OK;
}


/*
  handler for SPNEGO style session setup
*/
static NTSTATUS sesssetup_spnego(struct smbsrv_request *req, union smb_sesssetup *sess)
{
	/* defer this one for now */
	return NT_STATUS_INVALID_LEVEL;
}

/*
  backend for sessionsetup call - this takes all 3 variants of the call
*/
NTSTATUS sesssetup_backend(struct smbsrv_request *req, 
			   union smb_sesssetup *sess)
{
	NTSTATUS status = NT_STATUS_INVALID_LEVEL;

	switch (sess->generic.level) {
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


