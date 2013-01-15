/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) David Disseldorp 2012

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
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/ccan/build_assert/build_assert.h"
#include "include/ntioctl.h"
#include "../librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "smb2_ioctl_private.h"

#define COPYCHUNK_MAX_CHUNKS	256		/* 2k8r2 & win8 = 256 */
#define COPYCHUNK_MAX_CHUNK_LEN	1048576		/* 2k8r2 & win8 = 1048576 */
#define COPYCHUNK_MAX_TOTAL_LEN	16777216	/* 2k8r2 & win8 = 16777216 */
static void copychunk_pack_limits(struct srv_copychunk_rsp *cc_rsp)
{
	cc_rsp->chunks_written = COPYCHUNK_MAX_CHUNKS;
	cc_rsp->chunk_bytes_written = COPYCHUNK_MAX_CHUNK_LEN;
	cc_rsp->total_bytes_written = COPYCHUNK_MAX_TOTAL_LEN;
}

static NTSTATUS copychunk_check_limits(struct srv_copychunk_copy *cc_copy)
{
	uint32_t i;
	uint32_t total_len = 0;

	if (cc_copy->chunk_count > COPYCHUNK_MAX_CHUNKS) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i = 0; i < cc_copy->chunk_count; i++) {
		if (cc_copy->chunks[i].length > COPYCHUNK_MAX_CHUNK_LEN) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		total_len += cc_copy->chunks[i].length;
	}
	if (total_len > COPYCHUNK_MAX_TOTAL_LEN) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

static void copychunk_unlock_all(struct files_struct *src_fsp,
				 struct files_struct *dst_fsp,
				 struct lock_struct *rd_locks,
				 struct lock_struct *wr_locks,
				 uint32_t num_locks)
{

	uint32_t i;

	for (i = 0; i < num_locks; i++) {
		SMB_VFS_STRICT_UNLOCK(src_fsp->conn, src_fsp, &rd_locks[i]);
		SMB_VFS_STRICT_UNLOCK(dst_fsp->conn, dst_fsp, &wr_locks[i]);
	}
}

/* request read and write locks for each chunk */
static NTSTATUS copychunk_lock_all(TALLOC_CTX *mem_ctx,
				   struct srv_copychunk_copy *cc_copy,
				   struct files_struct *src_fsp,
				   struct files_struct *dst_fsp,
				   struct lock_struct **rd_locks,
				   struct lock_struct **wr_locks,
				   uint32_t *num_locks)
{
	NTSTATUS status;
	uint32_t i;
	struct lock_struct *rlocks;
	struct lock_struct *wlocks;

	rlocks = talloc_array(mem_ctx, struct lock_struct,
			      cc_copy->chunk_count);
	if (rlocks == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	wlocks = talloc_array(mem_ctx, struct lock_struct,
			      cc_copy->chunk_count);
	if (wlocks == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_rlocks_free;
	}

	for (i = 0; i < cc_copy->chunk_count; i++) {
		init_strict_lock_struct(src_fsp,
					src_fsp->op->global->open_persistent_id,
					cc_copy->chunks[i].source_off,
					cc_copy->chunks[i].length,
					READ_LOCK,
					&rlocks[i]);
		init_strict_lock_struct(dst_fsp,
					dst_fsp->op->global->open_persistent_id,
					cc_copy->chunks[i].target_off,
					cc_copy->chunks[i].length,
					WRITE_LOCK,
					&wlocks[i]);

		if (!SMB_VFS_STRICT_LOCK(src_fsp->conn, src_fsp, &rlocks[i])) {
			status = NT_STATUS_FILE_LOCK_CONFLICT;
			goto err_unlock;
		}
		if (!SMB_VFS_STRICT_LOCK(dst_fsp->conn, dst_fsp, &wlocks[i])) {
			/* unlock last rlock, otherwise missed by cleanup */
			SMB_VFS_STRICT_UNLOCK(src_fsp->conn, src_fsp,
					      &rlocks[i]);
			status = NT_STATUS_FILE_LOCK_CONFLICT;
			goto err_unlock;
		}
	}

	*rd_locks = rlocks;
	*wr_locks = wlocks;
	*num_locks = i;

	return NT_STATUS_OK;

err_unlock:
	if (i > 0) {
		/* cleanup all locks successfully issued so far */
		copychunk_unlock_all(src_fsp, dst_fsp, rlocks, wlocks, i);
	}
	talloc_free(wlocks);
err_rlocks_free:
	talloc_free(rlocks);
err_out:
	return status;
}

struct fsctl_srv_copychunk_state {
	struct connection_struct *conn;
	uint32_t dispatch_count;
	uint32_t recv_count;
	uint32_t bad_recv_count;
	NTSTATUS status;
	off_t total_written;
	struct files_struct *src_fsp;
	struct files_struct *dst_fsp;
	struct lock_struct *wlocks;
	struct lock_struct *rlocks;
	uint32_t num_locks;
};
static void fsctl_srv_copychunk_vfs_done(struct tevent_req *subreq);

static struct tevent_req *fsctl_srv_copychunk_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct files_struct *dst_fsp,
						   DATA_BLOB *in_input,
						   struct smbd_smb2_request *smb2req)
{
	struct tevent_req *req;
	struct srv_copychunk_copy cc_copy;
	enum ndr_err_code ndr_ret;
	uint64_t src_persistent_h;
	uint64_t src_volatile_h;
	int i;
	struct srv_copychunk *chunk;
	struct fsctl_srv_copychunk_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct fsctl_srv_copychunk_state);
	if (req == NULL) {
		return NULL;
	}
	state->conn = dst_fsp->conn;
	ndr_ret = ndr_pull_struct_blob(in_input, mem_ctx, &cc_copy,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_copy);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		DEBUG(0, ("failed to unmarshall copy chunk req\n"));
		state->status = NT_STATUS_INVALID_PARAMETER;
		tevent_req_nterror(req, state->status);
		return tevent_req_post(req, ev);
	}

	/* persistent/volatile keys sent as the resume key */
	src_persistent_h = BVAL(cc_copy.source_key, 0);
	src_volatile_h = BVAL(cc_copy.source_key, 8);
	state->src_fsp = file_fsp_get(smb2req, src_persistent_h, src_volatile_h);
	if (state->src_fsp == NULL) {
		DEBUG(3, ("invalid resume key in copy chunk req\n"));
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		tevent_req_nterror(req, state->status);
		return tevent_req_post(req, ev);
	}

	state->dst_fsp = dst_fsp;

	state->status = copychunk_check_limits(&cc_copy);
	if (tevent_req_nterror(req, state->status)) {
		DEBUG(3, ("copy chunk req exceeds limits\n"));
		return tevent_req_post(req, ev);
	}

	state->status = copychunk_lock_all(state,
					   &cc_copy,
					   state->src_fsp,
					   state->dst_fsp,
					   &state->rlocks,
					   &state->wlocks,
					   &state->num_locks);
	if (tevent_req_nterror(req, state->status)) {
		return tevent_req_post(req, ev);
	}

	for (i = 0; i < cc_copy.chunk_count; i++) {
		struct tevent_req *vfs_subreq;
		chunk = &cc_copy.chunks[i];
		vfs_subreq = SMB_VFS_COPY_CHUNK_SEND(dst_fsp->conn,
						     state, ev,
						     state->src_fsp,
						     chunk->source_off,
						     state->dst_fsp,
						     chunk->target_off,
						     chunk->length);
		if (vfs_subreq == NULL) {
			DEBUG(0, ("VFS copy chunk send failed\n"));
			state->status = NT_STATUS_NO_MEMORY;
			if (state->dispatch_count == 0) {
				/* nothing dispatched, return immediately */
				copychunk_unlock_all(state->src_fsp,
						     state->dst_fsp,
						     state->rlocks,
						     state->wlocks,
						     state->num_locks);
				tevent_req_nterror(req, state->status);
				return tevent_req_post(req, ev);
			} else {
				/*
				 * wait for dispatched to complete before
				 * returning error, locks held.
				 */
				break;
			}
		}
		tevent_req_set_callback(vfs_subreq,
					fsctl_srv_copychunk_vfs_done, req);
		state->dispatch_count++;
	}

	/* hold locks until all dispatched requests are completed */
	return req;
}

static void fsctl_srv_copychunk_vfs_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fsctl_srv_copychunk_state *state = tevent_req_data(req,
					struct fsctl_srv_copychunk_state);
	off_t chunk_nwritten;
	NTSTATUS status;

	state->recv_count++;
	status = SMB_VFS_COPY_CHUNK_RECV(state->conn, subreq,
					 &chunk_nwritten);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("good copy chunk recv %d of %d\n",
			   state->recv_count,
			   state->dispatch_count));
		state->total_written += chunk_nwritten;
	} else {
		DEBUG(0, ("bad status in copy chunk recv %d of %d: %s\n",
			  state->recv_count,
			  state->dispatch_count,
			  nt_errstr(status)));
		state->bad_recv_count++;
		/* may overwrite previous failed status */
		state->status = status;
	}

	if (state->recv_count != state->dispatch_count) {
		/*
		 * Wait for all VFS copy_chunk requests to complete, even
		 * if an error is received for a specific chunk.
		 */
		return;
	}

	/* all VFS copy_chunk requests done */
	copychunk_unlock_all(state->src_fsp,
			     state->dst_fsp,
			     state->rlocks,
			     state->wlocks,
			     state->num_locks);

	if (!tevent_req_nterror(req, state->status)) {
		tevent_req_done(req);
	}
}

static NTSTATUS fsctl_srv_copychunk_recv(struct tevent_req *req,
					 struct srv_copychunk_rsp *cc_rsp)
{
	struct fsctl_srv_copychunk_state *state = tevent_req_data(req,
					struct fsctl_srv_copychunk_state);
	NTSTATUS status;

	if (NT_STATUS_EQUAL(state->status, NT_STATUS_INVALID_PARAMETER)) {
		/* 2.2.32.1 - send back our maximum transfer size limits */
		copychunk_pack_limits(cc_rsp);
		tevent_req_received(req);
		return NT_STATUS_INVALID_PARAMETER;
	}

	cc_rsp->chunks_written = state->recv_count - state->bad_recv_count;
	cc_rsp->chunk_bytes_written = 0;
	cc_rsp->total_bytes_written = state->total_written;
	status = state->status;
	tevent_req_received(req);

	return status;
}

static NTSTATUS fsctl_validate_neg_info(TALLOC_CTX *mem_ctx,
				        struct tevent_context *ev,
				        struct smbXsrv_connection *conn,
				        DATA_BLOB *in_input,
				        uint32_t in_max_output,
				        DATA_BLOB *out_output,
					bool *disconnect)
{
	uint32_t in_capabilities;
	DATA_BLOB in_guid_blob;
	struct GUID in_guid;
	uint16_t in_security_mode;
	uint16_t in_num_dialects;
	uint16_t i;
	DATA_BLOB out_guid_blob;
	NTSTATUS status;

	if (in_input->length < 0x18) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_capabilities = IVAL(in_input->data, 0x00);
	in_guid_blob = data_blob_const(in_input->data + 0x04, 16);
	in_security_mode = SVAL(in_input->data, 0x14);
	in_num_dialects = SVAL(in_input->data, 0x16);

	if (in_input->length < (0x18 + in_num_dialects*2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_max_output < 0x18) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	status = GUID_from_ndr_blob(&in_guid_blob, &in_guid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (in_num_dialects != conn->smb2.client.num_dialects) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	for (i=0; i < in_num_dialects; i++) {
		uint16_t v = SVAL(in_input->data, 0x18 + i*2);

		if (conn->smb2.client.dialects[i] != v) {
			*disconnect = true;
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (GUID_compare(&in_guid, &conn->smb2.client.guid) != 0) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	if (in_security_mode != conn->smb2.client.security_mode) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	if (in_capabilities != conn->smb2.client.capabilities) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	status = GUID_to_ndr_blob(&conn->smb2.server.guid, mem_ctx,
				  &out_guid_blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*out_output = data_blob_talloc(mem_ctx, NULL, 0x18);
	if (out_output->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	SIVAL(out_output->data, 0x00, conn->smb2.server.capabilities);
	memcpy(out_output->data+0x04, out_guid_blob.data, 16);
	SIVAL(out_output->data, 0x14, conn->smb2.server.security_mode);
	SIVAL(out_output->data, 0x16, conn->smb2.server.dialect);

	return NT_STATUS_OK;
}

static NTSTATUS fsctl_srv_req_resume_key(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct files_struct *fsp,
					 uint32_t in_max_output,
					 DATA_BLOB *out_output)
{
	struct req_resume_key_rsp rkey_rsp;
	enum ndr_err_code ndr_ret;
	DATA_BLOB output;

	if (fsp == NULL) {
		return NT_STATUS_FILE_CLOSED;
	}

	ZERO_STRUCT(rkey_rsp);
	/* combine persistent and volatile handles for the resume key */
	SBVAL(rkey_rsp.resume_key, 0, fsp->op->global->open_persistent_id);
	SBVAL(rkey_rsp.resume_key, 8, fsp->op->global->open_volatile_id);

	ndr_ret = ndr_push_struct_blob(&output, mem_ctx, &rkey_rsp,
			(ndr_push_flags_fn_t)ndr_push_req_resume_key_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (in_max_output < output.length) {
		DEBUG(1, ("max output %u too small for resume key rsp %ld\n",
			  in_max_output, (long int)output.length));
		return NT_STATUS_INVALID_PARAMETER;
	}
	*out_output = output;

	return NT_STATUS_OK;
}

static void smb2_ioctl_network_fs_copychunk_done(struct tevent_req *subreq);

struct tevent_req *smb2_ioctl_network_fs(uint32_t ctl_code,
					 struct tevent_context *ev,
					 struct tevent_req *req,
					 struct smbd_smb2_ioctl_state *state)
{
	struct tevent_req *subreq;
	NTSTATUS status;

	switch (ctl_code) {
	case FSCTL_SRV_COPYCHUNK:
		subreq = fsctl_srv_copychunk_send(state, ev, state->fsp,
						  &state->in_input,
						  state->smb2req);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smb2_ioctl_network_fs_copychunk_done,
					req);
		return req;
		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
		status = fsctl_validate_neg_info(state, ev,
						 state->smbreq->sconn->conn,
						 &state->in_input,
						 state->in_max_output,
						 &state->out_output,
						 &state->disconnect);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
	case FSCTL_SRV_REQUEST_RESUME_KEY:
		status = fsctl_srv_req_resume_key(state, ev, state->fsp,
						  state->in_max_output,
						  &state->out_output);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
	default: {
		uint8_t *out_data = NULL;
		uint32_t out_data_len = 0;

		status = SMB_VFS_FSCTL(state->fsp,
				       state,
				       ctl_code,
				       state->smbreq->flags2,
				       state->in_input.data,
				       state->in_input.length,
				       &out_data,
				       state->in_max_output,
				       &out_data_len);
		state->out_output = data_blob_const(out_data, out_data_len);
		if (NT_STATUS_IS_OK(status)) {
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			if (IS_IPC(state->smbreq->conn)) {
				status = NT_STATUS_FS_DRIVER_REQUIRED;
			} else {
				status = NT_STATUS_INVALID_DEVICE_REQUEST;
			}
		}

		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
		break;
	}
	}

	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
	return tevent_req_post(req, ev);
}

static void smb2_ioctl_network_fs_copychunk_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct smbd_smb2_ioctl_state *ioctl_state = tevent_req_data(req,
						struct smbd_smb2_ioctl_state);
	struct srv_copychunk_rsp cc_rsp;
	NTSTATUS status;
	enum ndr_err_code ndr_ret;

	ZERO_STRUCT(cc_rsp);
	status = fsctl_srv_copychunk_recv(subreq, &cc_rsp);
	TALLOC_FREE(subreq);
	ndr_ret = ndr_push_struct_blob(&ioctl_state->out_output,
				       ioctl_state,
				       &cc_rsp,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		status = NT_STATUS_INTERNAL_ERROR;
	}

	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
}
