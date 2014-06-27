/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Volker Lendecke 2011

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
#include "system/network.h"
#include "lib/util/tevent_ntstatus.h"
#include "smb_common.h"
#include "smbXcli_base.h"
#include "smb2_create_blob.h"

struct smb2cli_create_state {
	uint8_t fixed[56];

	uint64_t fid_persistent;
	uint64_t fid_volatile;
	struct smb_create_returns cr;
	struct smb2_create_blobs blobs;
	struct tevent_req *subreq;
};

static void smb2cli_create_done(struct tevent_req *subreq);
static bool smb2cli_create_cancel(struct tevent_req *req);

struct tevent_req *smb2cli_create_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smbXcli_conn *conn,
	uint32_t timeout_msec,
	struct smbXcli_session *session,
	struct smbXcli_tcon *tcon,
	const char *filename,
	uint8_t  oplock_level,		/* SMB2_OPLOCK_LEVEL_* */
	uint32_t impersonation_level,	/* SMB2_IMPERSONATION_* */
	uint32_t desired_access,
	uint32_t file_attributes,
	uint32_t share_access,
	uint32_t create_disposition,
	uint32_t create_options,
	struct smb2_create_blobs *blobs)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_create_state *state;
	uint8_t *fixed;
	uint8_t *name_utf16;
	size_t name_utf16_len;
	DATA_BLOB blob;
	NTSTATUS status;
	size_t blobs_offset;
	uint8_t *dyn;
	size_t dyn_len;
	size_t max_dyn_len;
	uint32_t additional_flags = 0;
	uint32_t clear_flags = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_create_state);
	if (req == NULL) {
		return NULL;
	}

	if (!convert_string_talloc(state, CH_UNIX, CH_UTF16,
				   filename, strlen(filename),
				   &name_utf16, &name_utf16_len)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	if (strlen(filename) == 0) {
		TALLOC_FREE(name_utf16);
		name_utf16_len = 0;
	}

	fixed = state->fixed;

	SSVAL(fixed, 0, 57);
	SCVAL(fixed, 3, oplock_level);
	SIVAL(fixed, 4, impersonation_level);
	SIVAL(fixed, 24, desired_access);
	SIVAL(fixed, 28, file_attributes);
	SIVAL(fixed, 32, share_access);
	SIVAL(fixed, 36, create_disposition);
	SIVAL(fixed, 40, create_options);

	SSVAL(fixed, 44, SMB2_HDR_BODY + 56);
	SSVAL(fixed, 46, name_utf16_len);

	blob = data_blob_null;

	if (blobs != NULL) {
		status = smb2_create_blob_push(state, &blob, *blobs);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	blobs_offset = name_utf16_len;
	blobs_offset = ((blobs_offset + 3) & ~3);

	if (blob.length > 0) {
		SIVAL(fixed, 48, blobs_offset + SMB2_HDR_BODY + 56);
		SIVAL(fixed, 52, blob.length);
	}

	dyn_len = MAX(1, blobs_offset + blob.length);
	dyn = talloc_zero_array(state, uint8_t, dyn_len);
	if (tevent_req_nomem(dyn, req)) {
		return tevent_req_post(req, ev);
	}

	if (name_utf16) {
		memcpy(dyn, name_utf16, name_utf16_len);
		TALLOC_FREE(name_utf16);
	}

	if (blob.data != NULL) {
		memcpy(dyn + blobs_offset,
		       blob.data, blob.length);
		data_blob_free(&blob);
	}

	if (smbXcli_conn_dfs_supported(conn) &&
	    smbXcli_tcon_is_dfs_share(tcon))
	{
		additional_flags |= SMB2_HDR_FLAG_DFS;
	}

	/*
	 * We use max_dyn_len = 0
	 * as we don't explicitly ask for any output length.
	 *
	 * But it's still possible for the server to return
	 * large create blobs.
	 */
	max_dyn_len = 0;

	subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_CREATE,
				  additional_flags, clear_flags,
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len,
				  max_dyn_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_create_done, req);

	state->subreq = subreq;
	tevent_req_set_cancel_fn(req, smb2cli_create_cancel);

	return req;
}

static bool smb2cli_create_cancel(struct tevent_req *req)
{
	struct smb2cli_create_state *state = tevent_req_data(req,
		struct smb2cli_create_state);
	return tevent_req_cancel(state->subreq);
}

static void smb2cli_create_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_create_state *state =
		tevent_req_data(req,
		struct smb2cli_create_state);
	NTSTATUS status;
	struct iovec *iov;
	uint8_t *body;
	uint32_t offset, length;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x59
	}
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	body = (uint8_t *)iov[1].iov_base;

	state->cr.oplock_level  = CVAL(body, 2);
	state->cr.create_action = IVAL(body, 4);
	state->cr.creation_time = BVAL(body, 8);
	state->cr.last_access_time = BVAL(body, 16);
	state->cr.last_write_time = BVAL(body, 24);
	state->cr.change_time   = BVAL(body, 32);
	state->cr.allocation_size = BVAL(body, 40);
	state->cr.end_of_file   = BVAL(body, 48);
	state->cr.file_attributes = IVAL(body, 56);
	state->fid_persistent	= BVAL(body, 64);
	state->fid_volatile	= BVAL(body, 72);

	offset = IVAL(body, 80);
	length = IVAL(body, 84);

	if ((offset != 0) && (length != 0)) {
		if ((offset != SMB2_HDR_BODY + 88) ||
		    (length > iov[2].iov_len)) {
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}
		status = smb2_create_blob_parse(
			state, data_blob_const(iov[2].iov_base, length),
			&state->blobs);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}
	tevent_req_done(req);
}

NTSTATUS smb2cli_create_recv(struct tevent_req *req,
			     uint64_t *fid_persistent,
			     uint64_t *fid_volatile,
			     struct smb_create_returns *cr,
			     TALLOC_CTX *mem_ctx,
			     struct smb2_create_blobs *blobs)
{
	struct smb2cli_create_state *state =
		tevent_req_data(req,
		struct smb2cli_create_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*fid_persistent = state->fid_persistent;
	*fid_volatile = state->fid_volatile;
	if (cr) {
		*cr = state->cr;
	}
	if (blobs) {
		blobs->num_blobs = state->blobs.num_blobs;
		blobs->blobs = talloc_move(mem_ctx, &state->blobs.blobs);
	}
	return NT_STATUS_OK;
}

NTSTATUS smb2cli_create(struct smbXcli_conn *conn,
			uint32_t timeout_msec,
			struct smbXcli_session *session,
			struct smbXcli_tcon *tcon,
			const char *filename,
			uint8_t  oplock_level,	     /* SMB2_OPLOCK_LEVEL_* */
			uint32_t impersonation_level, /* SMB2_IMPERSONATION_* */
			uint32_t desired_access,
			uint32_t file_attributes,
			uint32_t share_access,
			uint32_t create_disposition,
			uint32_t create_options,
			struct smb2_create_blobs *blobs,
			uint64_t *fid_persistent,
			uint64_t *fid_volatile,
			struct smb_create_returns *cr,
			TALLOC_CTX *mem_ctx,
			struct smb2_create_blobs *ret_blobs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_create_send(frame, ev, conn, timeout_msec,
				  session, tcon,
				  filename, oplock_level,
				  impersonation_level, desired_access,
				  file_attributes, share_access,
				  create_disposition, create_options,
				  blobs);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_create_recv(req, fid_persistent, fid_volatile, cr,
				     mem_ctx, ret_blobs);
 fail:
	TALLOC_FREE(frame);
	return status;
}
