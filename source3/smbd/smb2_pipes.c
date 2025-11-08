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

	smb_fname = cp_smb_basename(talloc_tos(), name);
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
		size_t num_smb3_sids;
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
		num_smb3_sids = security_token_count_flag_sids(security_token,
							       &smb3_sid,
							       3,
							       NULL);
		if (num_smb3_sids != 0) {
			DBG_ERR("ERROR: %zu SMB3 SIDs have already been "
				"detected in the security token!\n",
				num_smb3_sids);
			file_free(smb_req, fsp);
			return NT_STATUS_ACCESS_DENIED;
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
