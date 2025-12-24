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
#include "reparse.h"

struct smb2cli_create_state {
	enum protocol_types protocol; /* for symlink error response parser */
	uint8_t *name_utf16;
	size_t name_utf16_len;
	uint8_t fixed[56];

	uint64_t fid_persistent;
	uint64_t fid_volatile;
	struct smb_create_returns cr;
	struct smb2_create_blobs blobs;
	struct symlink_reparse_struct *symlink;
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
	DATA_BLOB blob = {};
	NTSTATUS status;
	size_t blobs_offset;
	uint8_t *dyn;
	size_t dyn_len;
	size_t max_dyn_len;
	uint32_t additional_flags = 0;
	uint32_t clear_flags = 0;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_create_state);
	if (req == NULL) {
		return NULL;
	}
	state->protocol = smbXcli_conn_protocol(conn);

	ok = convert_string_talloc(
		state,
		CH_UNIX,
		CH_UTF16,
		filename,
		strlen(filename),
		&state->name_utf16,
		&state->name_utf16_len);
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	if (strlen(filename) == 0) {
		TALLOC_FREE(state->name_utf16);
		state->name_utf16_len = 0;
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
	SSVAL(fixed, 46, state->name_utf16_len);

	if (blobs != NULL) {
		status = smb2_create_blob_push(state, &blob, *blobs);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	blobs_offset = state->name_utf16_len;
	blobs_offset = ((blobs_offset + 3) & ~3);

	if (blob.length > 0) {
		blobs_offset = ((blobs_offset + 7) & ~7);
		SIVAL(fixed, 48, blobs_offset + SMB2_HDR_BODY + 56);
		SIVAL(fixed, 52, blob.length);
	}

	dyn_len = MAX(1, blobs_offset + blob.length);
	dyn = talloc_zero_array(state, uint8_t, dyn_len);
	if (tevent_req_nomem(dyn, req)) {
		return tevent_req_post(req, ev);
	}

	if (state->name_utf16 != NULL) {
		memcpy(dyn, state->name_utf16, state->name_utf16_len);
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

/*
 * [MS-SMB2] 2.2.2.2.1 Symbolic Link Error Response
 */

static NTSTATUS smb2cli_parse_symlink_error_response(
	TALLOC_CTX *mem_ctx,
	const uint8_t *buf,
	size_t buflen,
	struct symlink_reparse_struct **psymlink)
{
	struct symlink_reparse_struct *symlink = NULL;
	struct reparse_data_buffer reparse_buf = {
		.tag = 0,
	};
	uint32_t symlink_length, error_tag;
	NTSTATUS status;

	if (buflen < 8) {
		DBG_DEBUG("buffer too short: %zu bytes\n", buflen);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	symlink_length = IVAL(buf, 0);
	if (symlink_length != (buflen-4)) {
		DBG_DEBUG("symlink_length=%"PRIu32", (buflen-4)=%zu\n",
			  symlink_length, buflen-4);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	error_tag = IVAL(buf, 4);
	if (error_tag != SYMLINK_ERROR_TAG) {
		DBG_DEBUG("error_tag=%"PRIu32", expected 0x%x\n",
			  error_tag,
			  SYMLINK_ERROR_TAG);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	symlink = talloc(mem_ctx, struct symlink_reparse_struct);
	if (symlink == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = reparse_data_buffer_parse(symlink,
					   &reparse_buf,
					   buf + 8,
					   buflen - 8);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("reparse_data_buffer_parse() failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(symlink);
		return status;
	}

	if (reparse_buf.tag != IO_REPARSE_TAG_SYMLINK) {
		DBG_DEBUG("Got tag 0x%" PRIx32 ", "
			  "expected IO_REPARSE_TAG_SYMLINK\n",
			  reparse_buf.tag);
		TALLOC_FREE(symlink);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	*symlink = reparse_buf.parsed.lnk;
	*psymlink = symlink;
	return NT_STATUS_OK;
}

/*
 * [MS-SMB2] 2.2.2 ErrorData
 *
 * This is in theory a broad API, but as right now we only have a
 * single [MS-SMB2] 2.2.2.2.1 symlink error response we can return
 * just this.
 */
static NTSTATUS smb2cli_create_error_data_parse(
	enum protocol_types protocol,
	uint8_t error_context_count,
	uint32_t byte_count,
	const uint8_t *buf,
	size_t buflen,
	TALLOC_CTX *mem_ctx,
	struct symlink_reparse_struct **_symlink)
{
	struct symlink_reparse_struct *symlink = NULL;
	uint32_t error_data_length, error_id;
	NTSTATUS status;

	if (protocol != PROTOCOL_SMB3_11) {
		if (error_context_count != 0) {
			DBG_DEBUG("Got error_context_count=%"PRIu8"\n",
				  error_context_count);
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		status = smb2cli_parse_symlink_error_response(
			mem_ctx, buf, buflen, &symlink);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		*_symlink = symlink;
		return NT_STATUS_OK;
	}

	/*
	 * The STOPPED_ON_SYMLINK that I've seen coming from W2k16 has
	 * just a single array element in the [MS-SMB2] 2.2.2
	 * ErrorData array. We'll need to adapt this if there actually
	 * comes an array of multiple ErrorData elements.
	 */

	if (error_context_count != 1) {
		DBG_DEBUG("Got error_context_count=%"PRIu8"\n",
			  error_context_count);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (byte_count != buflen) {
		DBG_DEBUG("bytecount=%"PRIu32", "
			  "buflen=%zu\n",
			  byte_count,
			  buflen);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (buflen < 8) {
		DBG_DEBUG("buflen=%zu\n", buflen);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	error_data_length = IVAL(buf, 0);
	if (error_data_length != (buflen - 8)) {
		DBG_DEBUG("error_data_length=%"PRIu32", expected %zu\n",
			  error_data_length,
			  buflen - 8);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	error_id = IVAL(buf, 4);
	if (error_id != 0) {
		DBG_DEBUG("error_id=%"PRIu32", expected 0\n", error_id);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	status = smb2cli_parse_symlink_error_response(
		mem_ctx, buf + 8, buflen - 8, &symlink);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("smb2cli_parse_symlink_error_response failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	*_symlink = symlink;
	return NT_STATUS_OK;
}

static NTSTATUS smb2cli_create_unparsed_unix_len(
	size_t unparsed_utf16_len,
	uint8_t *name_utf16,
	size_t name_utf16_len,
	size_t *_unparsed_unix_len)
{
	uint8_t *unparsed_utf16 = NULL;
	uint8_t *unparsed_unix = NULL;
	size_t unparsed_unix_len = 0;
	bool ok;

	if (unparsed_utf16_len > name_utf16_len) {
		DBG_DEBUG("unparsed_utf16_len=%zu, name_utf16_len=%zu\n",
			  unparsed_utf16_len,
			  name_utf16_len);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (unparsed_utf16_len == 0) {
		*_unparsed_unix_len = 0;
		return NT_STATUS_OK;
	}

	unparsed_utf16 = name_utf16 + name_utf16_len - unparsed_utf16_len;

	ok = convert_string_talloc(
		talloc_tos(),
		CH_UTF16,
		CH_UNIX,
		unparsed_utf16,
		unparsed_utf16_len,
		&unparsed_unix,
		&unparsed_unix_len);
	if (!ok) {
		NTSTATUS status = map_nt_error_from_unix_common(errno);
		DBG_DEBUG("convert_string_talloc failed: %s\n",
			  strerror(errno));
		return status;
	}
	*_unparsed_unix_len = unparsed_unix_len;
	return NT_STATUS_OK;
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
	},
	{
		.status = NT_STATUS_STOPPED_ON_SYMLINK,
		.body_size = 0x9,
	}
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
		uint16_t error_context_count = CVAL(iov[1].iov_base, 2);
		uint32_t byte_count = IVAL(iov[1].iov_base, 4);
		size_t unparsed_unix_len = 0;

		NTSTATUS symlink_status;

		symlink_status = smb2cli_create_error_data_parse(
			state->protocol,
			error_context_count,
			byte_count,
			iov[2].iov_base,
			iov[2].iov_len,
			state,
			&state->symlink);
		if (tevent_req_nterror(req, symlink_status)) {
			return;
		}

		/*
		 * Our callers want to know the unparsed length in
		 * unix encoding.
		 */
		symlink_status = smb2cli_create_unparsed_unix_len(
			state->symlink->unparsed_path_length,
			state->name_utf16,
			state->name_utf16_len,
			&unparsed_unix_len);
		if (tevent_req_nterror(req, symlink_status)) {
			return;
		}
		state->symlink->unparsed_path_length = unparsed_unix_len;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	body = (uint8_t *)iov[1].iov_base;

	state->cr.oplock_level  = CVAL(body, 2);
	state->cr.flags         = CVAL(body, 3);
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
			     struct smb2_create_blobs *blobs,
			     struct symlink_reparse_struct **psymlink)
{
	struct smb2cli_create_state *state =
		tevent_req_data(req,
		struct smb2cli_create_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK) &&
		    (psymlink != NULL)) {
			*psymlink = talloc_move(mem_ctx, &state->symlink);
		}
		tevent_req_received(req);
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
	tevent_req_received(req);
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
			struct smb2_create_blobs *ret_blobs,
			struct symlink_reparse_struct **psymlink)
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
	status = smb2cli_create_recv(
		req,
		fid_persistent,
		fid_volatile,
		cr,
		mem_ctx,
		ret_blobs,
		psymlink);
 fail:
	TALLOC_FREE(frame);
	return status;
}
