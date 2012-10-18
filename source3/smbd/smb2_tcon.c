/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/security/security.h"
#include "auth.h"
#include "lib/param/loadparm.h"
#include "../lib/util/tevent_ntstatus.h"

static struct tevent_req *smbd_smb2_tree_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					const char *in_path);
static NTSTATUS smbd_smb2_tree_connect_recv(struct tevent_req *req,
					    uint8_t *out_share_type,
					    uint32_t *out_share_flags,
					    uint32_t *out_capabilities,
					    uint32_t *out_maximal_access,
					    uint32_t *out_tree_id);

static void smbd_smb2_request_tcon_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_tcon(struct smbd_smb2_request *req)
{
	const uint8_t *inbody;
	uint16_t in_path_offset;
	uint16_t in_path_length;
	DATA_BLOB in_path_buffer;
	char *in_path_string;
	size_t in_path_string_size;
	NTSTATUS status;
	bool ok;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x09);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_path_offset = SVAL(inbody, 0x04);
	in_path_length = SVAL(inbody, 0x06);

	if (in_path_offset != (SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(req))) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_path_length > SMBD_SMB2_IN_DYN_LEN(req)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_path_buffer.data = SMBD_SMB2_IN_DYN_PTR(req);
	in_path_buffer.length = in_path_length;

	ok = convert_string_talloc(req, CH_UTF16, CH_UNIX,
				   in_path_buffer.data,
				   in_path_buffer.length,
				   &in_path_string,
				   &in_path_string_size);
	if (!ok) {
		return smbd_smb2_request_error(req, NT_STATUS_ILLEGAL_CHARACTER);
	}

	if (in_path_buffer.length == 0) {
		in_path_string_size = 0;
	}

	if (strlen(in_path_string) != in_path_string_size) {
		return smbd_smb2_request_error(req, NT_STATUS_BAD_NETWORK_NAME);
	}

	subreq = smbd_smb2_tree_connect_send(req,
					     req->sconn->ev_ctx,
					     req,
					     in_path_string);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_tcon_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_tcon_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req =
		tevent_req_callback_data(subreq,
		struct smbd_smb2_request);
	uint8_t *outhdr;
	DATA_BLOB outbody;
	uint8_t out_share_type = 0;
	uint32_t out_share_flags = 0;
	uint32_t out_capabilities = 0;
	uint32_t out_maximal_access = 0;
	uint32_t out_tree_id = 0;
	NTSTATUS status;
	NTSTATUS error;

	status = smbd_smb2_tree_connect_recv(subreq,
					     &out_share_type,
					     &out_share_flags,
					     &out_capabilities,
					     &out_maximal_access,
					     &out_tree_id);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->sconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	outhdr = SMBD_SMB2_OUT_HDR_PTR(req);

	outbody = data_blob_talloc(req->out.vector, NULL, 0x10);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->sconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SIVAL(outhdr, SMB2_HDR_TID, out_tree_id);

	SSVAL(outbody.data, 0x00, 0x10);	/* struct size */
	SCVAL(outbody.data, 0x02,
	      out_share_type);			/* share type */
	SCVAL(outbody.data, 0x03, 0);		/* reserved */
	SIVAL(outbody.data, 0x04,
	      out_share_flags);			/* share flags */
	SIVAL(outbody.data, 0x08,
	      out_capabilities);		/* capabilities */
	SIVAL(outbody.data, 0x0C,
	      out_maximal_access);		/* maximal access */

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->sconn,
						 nt_errstr(error));
		return;
	}
}

static NTSTATUS smbd_smb2_tree_connect(struct smbd_smb2_request *req,
				       const char *in_path,
				       uint8_t *out_share_type,
				       uint32_t *out_share_flags,
				       uint32_t *out_capabilities,
				       uint32_t *out_maximal_access,
				       uint32_t *out_tree_id)
{
	struct smbXsrv_connection *conn = req->sconn->conn;
	const char *share = in_path;
	char *service = NULL;
	int snum = -1;
	struct smbXsrv_tcon *tcon;
	NTTIME now = timeval_to_nttime(&req->request_time);
	connection_struct *compat_conn = NULL;
	struct user_struct *compat_vuser = req->session->compat;
	NTSTATUS status;
	bool encryption_required = req->session->global->encryption_required;
	bool guest_session = false;

	if (strncmp(share, "\\\\", 2) == 0) {
		const char *p = strchr(share+2, '\\');
		if (p) {
			share = p + 1;
		}
	}

	DEBUG(10,("smbd_smb2_tree_connect: path[%s] share[%s]\n",
		  in_path, share));

	service = talloc_strdup(talloc_tos(), share);
	if(!service) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!strlower_m(service)) {
		DEBUG(2, ("strlower_m %s failed\n", service));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* TODO: do more things... */
	if (strequal(service,HOMES_NAME)) {
		if (compat_vuser->homes_snum == -1) {
			DEBUG(2, ("[homes] share not available for "
				"user %s because it was not found "
				"or created at session setup "
				"time\n",
				compat_vuser->session_info->unix_info->unix_name));
			return NT_STATUS_BAD_NETWORK_NAME;
		}
		snum = compat_vuser->homes_snum;
	} else if ((compat_vuser->homes_snum != -1)
                   && strequal(service,
			lp_servicename(talloc_tos(), compat_vuser->homes_snum))) {
		snum = compat_vuser->homes_snum;
	} else {
		snum = find_service(talloc_tos(), service, &service);
		if (!service) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (snum < 0) {
		DEBUG(3,("smbd_smb2_tree_connect: couldn't find service %s\n",
			 service));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	if (lp_smb_encrypt(snum) == SMB_SIGNING_REQUIRED) {
		encryption_required = true;
	}

	if (security_session_user_level(compat_vuser->session_info, NULL) < SECURITY_USER) {
		guest_session = true;
	}

	if (guest_session && encryption_required) {
		DEBUG(1,("reject guest as encryption is required for service %s\n",
			 service));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!(conn->smb2.server.capabilities & SMB2_CAP_ENCRYPTION)) {
		if (encryption_required) {
			DEBUG(1,("reject tcon with dialect[0x%04X] "
				 "as encryption is required for service %s\n",
				 conn->smb2.server.dialect, service));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	/* create a new tcon as child of the session */
	status = smb2srv_tcon_create(req->session, now, &tcon);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	tcon->global->encryption_required = encryption_required;

	compat_conn = make_connection_smb2(req->sconn,
					tcon, snum,
					req->session->compat,
					"???",
					&status);
	if (compat_conn == NULL) {
		TALLOC_FREE(tcon);
		return status;
	}

	tcon->global->share_name = lp_servicename(tcon->global,
						  SNUM(compat_conn));
	if (tcon->global->share_name == NULL) {
		conn_free(compat_conn);
		TALLOC_FREE(tcon);
		return NT_STATUS_NO_MEMORY;
	}
	tcon->global->session_global_id =
		req->session->global->session_global_id;

	tcon->compat = talloc_move(tcon, &compat_conn);

	tcon->status = NT_STATUS_OK;

	status = smbXsrv_tcon_update(tcon);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tcon);
		return status;
	}

	if (IS_PRINT(tcon->compat)) {
		*out_share_type = SMB2_SHARE_TYPE_PRINT;
	} else if (IS_IPC(tcon->compat)) {
		*out_share_type = SMB2_SHARE_TYPE_PIPE;
	} else {
		*out_share_type = SMB2_SHARE_TYPE_DISK;
	}

	*out_share_flags = 0;

	if (lp_msdfs_root(SNUM(tcon->compat)) && lp_host_msdfs()) {
		*out_share_flags |= (SMB2_SHAREFLAG_DFS|SMB2_SHAREFLAG_DFS_ROOT);
		*out_capabilities = SMB2_SHARE_CAP_DFS;
	} else {
		*out_capabilities = 0;
	}

	switch(lp_csc_policy(SNUM(tcon->compat))) {
	case CSC_POLICY_MANUAL:
		break;
	case CSC_POLICY_DOCUMENTS:
		*out_share_flags |= SMB2_SHAREFLAG_AUTO_CACHING;
		break;
	case CSC_POLICY_PROGRAMS:
		*out_share_flags |= SMB2_SHAREFLAG_VDO_CACHING;
		break;
	case CSC_POLICY_DISABLE:
		*out_share_flags |= SMB2_SHAREFLAG_NO_CACHING;
		break;
	default:
		break;
	}

	if (lp_hideunreadable(SNUM(tcon->compat)) ||
	    lp_hideunwriteable_files(SNUM(tcon->compat))) {
		*out_share_flags |= SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM;
	}

	if (encryption_required) {
		*out_share_flags |= SMB2_SHAREFLAG_ENCRYPT_DATA;
	}

	*out_maximal_access = tcon->compat->share_access;

	*out_tree_id = tcon->global->tcon_wire_id;
	return NT_STATUS_OK;
}

struct smbd_smb2_tree_connect_state {
	const char *in_path;
	uint8_t out_share_type;
	uint32_t out_share_flags;
	uint32_t out_capabilities;
	uint32_t out_maximal_access;
	uint32_t out_tree_id;
};

static struct tevent_req *smbd_smb2_tree_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					const char *in_path)
{
	struct tevent_req *req;
	struct smbd_smb2_tree_connect_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_tree_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->in_path = in_path;

	status = smbd_smb2_tree_connect(smb2req,
					state->in_path,
					&state->out_share_type,
					&state->out_share_flags,
					&state->out_capabilities,
					&state->out_maximal_access,
					&state->out_tree_id);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS smbd_smb2_tree_connect_recv(struct tevent_req *req,
					    uint8_t *out_share_type,
					    uint32_t *out_share_flags,
					    uint32_t *out_capabilities,
					    uint32_t *out_maximal_access,
					    uint32_t *out_tree_id)
{
	struct smbd_smb2_tree_connect_state *state =
		tevent_req_data(req,
		struct smbd_smb2_tree_connect_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_share_type = state->out_share_type;
	*out_share_flags = state->out_share_flags;
	*out_capabilities = state->out_capabilities;
	*out_maximal_access = state->out_maximal_access;
	*out_tree_id = state->out_tree_id;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS smbd_smb2_request_process_tdis(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	DATA_BLOB outbody;

	status = smbd_smb2_request_verify_sizes(req, 0x04);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	/*
	 * TODO: cancel all outstanding requests on the tcon
	 */
	status = smbXsrv_tcon_disconnect(req->tcon, req->tcon->compat->vuid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smbd_smb2_request_process_tdis: "
			  "smbXsrv_tcon_disconnect() failed: %s\n",
			  nt_errstr(status)));
		/*
		 * If we hit this case, there is something completely
		 * wrong, so we better disconnect the transport connection.
		 */
		return status;
	}

	TALLOC_FREE(req->tcon);

	outbody = data_blob_talloc(req->out.vector, NULL, 0x04);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	return smbd_smb2_request_done(req, outbody, NULL);
}
