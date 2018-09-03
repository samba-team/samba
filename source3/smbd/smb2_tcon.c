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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

static struct tevent_req *smbd_smb2_tree_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					uint16_t in_flags,
					const char *in_path);
static NTSTATUS smbd_smb2_tree_connect_recv(struct tevent_req *req,
					    uint8_t *out_share_type,
					    uint32_t *out_share_flags,
					    uint32_t *out_capabilities,
					    uint32_t *out_maximal_access,
					    uint32_t *out_tree_id,
					    bool *disconnect);

static void smbd_smb2_request_tcon_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_tcon(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	const uint8_t *inbody;
	uint16_t in_flags;
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

	if (xconn->protocol >= PROTOCOL_SMB3_11) {
		in_flags = SVAL(inbody, 0x02);
	} else {
		in_flags = 0;
	}
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
					     in_flags,
					     in_path_string);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_tcon_done, req);

	/*
	 * Avoid sending a STATUS_PENDING message, it's very likely
	 * the client won't expect that.
	 */
	return smbd_smb2_request_pending_queue(req, subreq, 0);
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
	bool disconnect = false;
	NTSTATUS status;
	NTSTATUS error;

	status = smbd_smb2_tree_connect_recv(subreq,
					     &out_share_type,
					     &out_share_flags,
					     &out_capabilities,
					     &out_maximal_access,
					     &out_tree_id,
					     &disconnect);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		if (disconnect) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(status));
			return;
		}
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	outhdr = SMBD_SMB2_OUT_HDR_PTR(req);

	outbody = smbd_smb2_generate_outbody(req, 0x10);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
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
		smbd_server_connection_terminate(req->xconn,
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
				       uint32_t *out_tree_id,
				       bool *disconnect)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smbXsrv_connection *conn = req->xconn;
	struct smbXsrv_session *session = req->session;
	struct auth_session_info *session_info =
		session->global->auth_session_info;
	const char *share = in_path;
	char *service = NULL;
	int snum = -1;
	struct smbXsrv_tcon *tcon;
	NTTIME now = timeval_to_nttime(&req->request_time);
	connection_struct *compat_conn = NULL;
	NTSTATUS status;
	bool encryption_desired = req->session->global->encryption_flags & SMBXSRV_ENCRYPTION_DESIRED;
	bool encryption_required = req->session->global->encryption_flags & SMBXSRV_ENCRYPTION_REQUIRED;
	bool guest_session = false;
	bool require_signed_tcon = false;

	*disconnect = false;

	if (strncmp(share, "\\\\", 2) == 0) {
		const char *p = strchr(share+2, '\\');
		if (p) {
			share = p + 1;
		}
	}

	DEBUG(10,("smbd_smb2_tree_connect: path[%s] share[%s]\n",
		  in_path, share));

	if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
		guest_session = true;
	}

	if (conn->protocol >= PROTOCOL_SMB3_11 && !guest_session) {
		require_signed_tcon = true;
	}

	if (require_signed_tcon && !req->do_encryption && !req->do_signing) {
		DEBUG(1, ("smbd_smb2_tree_connect: reject request to share "
			  "[%s] as '%s\\%s' without encryption or signing. "
			  "Disconnecting.\n",
			  share,
			  req->session->global->auth_session_info->info->domain_name,
			  req->session->global->auth_session_info->info->account_name));
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

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
		if (session->homes_snum == -1) {
			DEBUG(2, ("[homes] share not available for "
				"user %s because it was not found "
				"or created at session setup "
				"time\n",
				session_info->unix_info->unix_name));
			return NT_STATUS_BAD_NETWORK_NAME;
		}
		snum = session->homes_snum;
	} else if ((session->homes_snum != -1)
                   && strequal(service,
			lp_servicename(talloc_tos(), lp_sub, session->homes_snum))) {
		snum = session->homes_snum;
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

	/* Handle non-DFS clients attempting connections to msdfs proxy */
	if (lp_host_msdfs()) {
		char *proxy = lp_msdfs_proxy(talloc_tos(), lp_sub, snum);

		if ((proxy != NULL) && (*proxy != '\0')) {
			DBG_NOTICE("refusing connection to dfs proxy share "
				   "'%s' (pointing to %s)\n",
				   service,
				   proxy);
			TALLOC_FREE(proxy);
			return NT_STATUS_BAD_NETWORK_NAME;
		}
		TALLOC_FREE(proxy);
	}

	if ((lp_smb_encrypt(snum) >= SMB_SIGNING_DESIRED) &&
	    (conn->smb2.server.cipher != 0))
	{
		encryption_desired = true;
	}

	if (lp_smb_encrypt(snum) == SMB_SIGNING_REQUIRED) {
		encryption_desired = true;
		encryption_required = true;
	}

	if (guest_session && encryption_required) {
		DEBUG(1,("reject guest as encryption is required for service %s\n",
			 service));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (conn->smb2.server.cipher == 0) {
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

	if (encryption_desired) {
		tcon->global->encryption_flags |= SMBXSRV_ENCRYPTION_DESIRED;
	}
	if (encryption_required) {
		tcon->global->encryption_flags |= SMBXSRV_ENCRYPTION_REQUIRED;
	}

	compat_conn = make_connection_smb2(req,
					tcon, snum,
					"???",
					&status);
	if (compat_conn == NULL) {
		TALLOC_FREE(tcon);
		return status;
	}

	tcon->global->share_name = lp_servicename(tcon->global,
						  lp_sub,
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

	if (lp_hide_unreadable(SNUM(tcon->compat)) ||
	    lp_hide_unwriteable_files(SNUM(tcon->compat))) {
		*out_share_flags |= SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM;
	}

	if (encryption_desired) {
		*out_share_flags |= SMB2_SHAREFLAG_ENCRYPT_DATA;
	}

	*out_maximal_access = tcon->compat->share_access;

	*out_tree_id = tcon->global->tcon_wire_id;
	req->last_tid = tcon->global->tcon_wire_id;

	return NT_STATUS_OK;
}

struct smbd_smb2_tree_connect_state {
	const char *in_path;
	uint8_t out_share_type;
	uint32_t out_share_flags;
	uint32_t out_capabilities;
	uint32_t out_maximal_access;
	uint32_t out_tree_id;
	bool disconnect;
};

static struct tevent_req *smbd_smb2_tree_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					uint16_t in_flags,
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
					&state->out_tree_id,
					&state->disconnect);
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
					    uint32_t *out_tree_id,
					    bool *disconnect)
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
	*disconnect = state->disconnect;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static struct tevent_req *smbd_smb2_tdis_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req);
static NTSTATUS smbd_smb2_tdis_recv(struct tevent_req *req);
static void smbd_smb2_request_tdis_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_tdis(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	struct tevent_req *subreq = NULL;

	status = smbd_smb2_request_verify_sizes(req, 0x04);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	subreq = smbd_smb2_tdis_send(req, req->sconn->ev_ctx, req);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_tdis_done, req);

	/*
	 * Avoid sending a STATUS_PENDING message, it's very likely
	 * the client won't expect that.
	 */
	return smbd_smb2_request_pending_queue(req, subreq, 0);
}

static void smbd_smb2_request_tdis_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *smb2req =
		tevent_req_callback_data(subreq,
		struct smbd_smb2_request);
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error;

	status = smbd_smb2_tdis_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(smb2req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							nt_errstr(error));
			return;
		}
		return;
	}

	outbody = smbd_smb2_generate_outbody(smb2req, 0x04);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	error = smbd_smb2_request_done(smb2req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(smb2req->xconn,
						nt_errstr(error));
		return;
	}
}

struct smbd_smb2_tdis_state {
	struct smbd_smb2_request *smb2req;
	struct tevent_queue *wait_queue;
};

static void smbd_smb2_tdis_wait_done(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_tdis_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req)
{
	struct tevent_req *req;
	struct smbd_smb2_tdis_state *state;
	struct tevent_req *subreq;
	struct smbXsrv_connection *xconn = NULL;

	req = tevent_req_create(mem_ctx, &state,
			struct smbd_smb2_tdis_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;

	state->wait_queue = tevent_queue_create(state, "tdis_wait_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * Make sure that no new request will be able to use this tcon.
	 */
	smb2req->tcon->status = NT_STATUS_NETWORK_NAME_DELETED;

	xconn = smb2req->xconn->client->connections;
	for (; xconn != NULL; xconn = xconn->next) {
		struct smbd_smb2_request *preq;

		for (preq = xconn->smb2.requests; preq != NULL; preq = preq->next) {
			if (preq == smb2req) {
				/* Can't cancel current request. */
				continue;
			}
			if (preq->tcon != smb2req->tcon) {
				/* Request on different tcon. */
				continue;
			}

			/*
			 * Never cancel anything in a compound
			 * request. Way too hard to deal with
			 * the result.
			 */
			if (!preq->compound_related && preq->subreq != NULL) {
				tevent_req_cancel(preq->subreq);
			}

			/*
			 * Now wait until the request is finished.
			 *
			 * We don't set a callback, as we just want to block the
			 * wait queue and the talloc_free() of the request will
			 * remove the item from the wait queue.
			 */
			subreq = tevent_queue_wait_send(preq, ev, state->wait_queue);
			if (tevent_req_nomem(subreq, req)) {
				return tevent_req_post(req, ev);
			}
		}
	}

	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and send to the socket.
	 */
	subreq = tevent_queue_wait_send(state, ev, state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbd_smb2_tdis_wait_done, req);

	return req;
}

static void smbd_smb2_tdis_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_tdis_state *state = tevent_req_data(
		req, struct smbd_smb2_tdis_state);
	NTSTATUS status;

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);

	/*
	 * As we've been awoken, we may have changed
	 * uid in the meantime. Ensure we're still
	 * root (SMB2_OP_TDIS has .as_root = true).
	 */
	change_to_root_user();

	status = smbXsrv_tcon_disconnect(state->smb2req->tcon,
					 state->smb2req->tcon->compat->vuid);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* We did tear down the tcon. */
	TALLOC_FREE(state->smb2req->tcon);
	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_tdis_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
