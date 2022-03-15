/*
   Unix SMB/CIFS implementation.
   Pipe SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton  1997-1998.
   Copyright (C) Jeremy Allison 2005.

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
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "libcli/security/security.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "auth/auth_util.h"
#include "librpc/rpc/dcerpc_helper.h"

NTSTATUS open_np_file(struct smb_request *smb_req, const char *name,
		      struct files_struct **pfsp)
{
	struct smbXsrv_connection *xconn = smb_req->xconn;
	struct connection_struct *conn = smb_req->conn;
	struct files_struct *fsp;
	struct smb_filename *smb_fname = NULL;
	struct auth_session_info *session_info = conn->session_info;
	NTSTATUS status;

	status = file_new(smb_req, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("file_new failed: %s\n", nt_errstr(status)));
		return status;
	}

	fsp->conn = conn;
	fsp_set_fd(fsp, -1);
	fsp->vuid = smb_req->vuid;
	fsp->fsp_flags.can_lock = false;
	fsp->access_mask = FILE_READ_DATA | FILE_WRITE_DATA;

	smb_fname = synthetic_smb_fname(talloc_tos(),
					name,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		file_free(smb_req, fsp);
		return NT_STATUS_NO_MEMORY;
	}
	status = fsp_set_smb_fname(fsp, smb_fname);
	TALLOC_FREE(smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		file_free(smb_req, fsp);
		return status;
	}

	if (smb_req->smb2req != NULL && smb_req->smb2req->was_encrypted) {
		struct security_token *security_token = NULL;
		uint16_t dialect = xconn->smb2.server.dialect;
		uint16_t srv_smb_encrypt = DCERPC_SMB_ENCRYPTION_REQUIRED;
		uint16_t cipher = xconn->smb2.server.cipher;
		struct dom_sid smb3_sid = global_sid_Samba_SMB3;
		uint32_t i;
		bool ok;

		session_info = copy_session_info(fsp, conn->session_info);
		if (session_info == NULL) {
			DBG_ERR("Failed to copy session info\n");
			file_free(smb_req, fsp);
			return NT_STATUS_NO_MEMORY;
		}
		security_token = session_info->security_token;

		/*
		 * Security check:
		 *
		 * Make sure we don't have a SMB3 SID in the security token!
		 */
		for (i = 0; i < security_token->num_sids; i++) {
			int cmp;

			cmp = dom_sid_compare_domain(&security_token->sids[i],
						     &smb3_sid);
			if (cmp == 0) {
				DBG_ERR("ERROR: An SMB3 SID has already been "
					"detected in the security token!\n");
				file_free(smb_req, fsp);
				return NT_STATUS_ACCESS_DENIED;
			}
		}

		ok = sid_append_rid(&smb3_sid, dialect);
		ok &= sid_append_rid(&smb3_sid, srv_smb_encrypt);
		ok &= sid_append_rid(&smb3_sid, cipher);

		if (!ok) {
			DBG_ERR("sid too small\n");
			file_free(smb_req, fsp);
			return NT_STATUS_BUFFER_TOO_SMALL;
		}

		status = add_sid_to_array_unique(security_token,
						 &smb3_sid,
						 &security_token->sids,
						 &security_token->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to add SMB3 SID to security token\n");
			file_free(smb_req, fsp);
			return status;
		}

		fsp->fsp_flags.encryption_required = true;
	}

	status = np_open(fsp, name,
			 conn->sconn->remote_address,
			 conn->sconn->local_address,
			 session_info,
			 conn->sconn->ev_ctx,
			 conn->sconn->msg_ctx,
			 conn->sconn->dce_ctx,
			 &fsp->fake_file_handle);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("np_open(%s) returned %s\n", name,
			   nt_errstr(status)));
		file_free(smb_req, fsp);
		return status;
	}

	*pfsp = fsp;

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a write on a pipe.
****************************************************************************/

struct pipe_write_state {
	size_t numtowrite;
};

static void pipe_write_done(struct tevent_req *subreq);

void reply_pipe_write(struct smb_request *req)
{
	files_struct *fsp = file_fsp(req, SVAL(req->vwv+0, 0));
	const uint8_t *data;
	struct pipe_write_state *state;
	struct tevent_req *subreq;

	if (!fsp_is_np(fsp)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	if (fsp->vuid != req->vuid) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	state = talloc(req, struct pipe_write_state);
	if (state == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	req->async_priv = state;

	state->numtowrite = SVAL(req->vwv+1, 0);

	data = req->buf + 3;

	DEBUG(6, ("reply_pipe_write: %s, name: %s len: %d\n", fsp_fnum_dbg(fsp),
		  fsp_str_dbg(fsp), (int)state->numtowrite));

	subreq = np_write_send(state, req->sconn->ev_ctx,
			       fsp->fake_file_handle, data, state->numtowrite);
	if (subreq == NULL) {
		TALLOC_FREE(state);
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	tevent_req_set_callback(subreq, pipe_write_done,
				talloc_move(req->conn, &req));
}

static void pipe_write_done(struct tevent_req *subreq)
{
	struct smb_request *req = tevent_req_callback_data(
		subreq, struct smb_request);
	struct pipe_write_state *state = talloc_get_type_abort(
		req->async_priv, struct pipe_write_state);
	NTSTATUS status;
	ssize_t nwritten = -1;

	status = np_write_recv(subreq, &nwritten);
	TALLOC_FREE(subreq);
	if (nwritten < 0) {
		reply_nterror(req, status);
		goto send;
	}

	/* Looks bogus to me now. Needs to be removed ? JRA. */
	if ((nwritten == 0 && state->numtowrite != 0)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto send;
	}

	reply_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);

	DEBUG(3,("write-IPC nwritten=%d\n", (int)nwritten));

 send:
	if (!srv_send_smb(req->xconn, (char *)req->outbuf,
			  true, req->seqnum+1,
			  IS_CONN_ENCRYPTED(req->conn)||req->encrypted,
			  &req->pcd)) {
		exit_server_cleanly("construct_reply: srv_send_smb failed.");
	}
	TALLOC_FREE(req);
}
