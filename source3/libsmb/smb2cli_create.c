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
#include "client.h"
#include "async_smb.h"
#include "smb2cli_base.h"
#include "smb2cli.h"
#include "libsmb/proto.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/smb/smb2_create_blob.h"

struct smb2cli_create_state {
	uint8_t fixed[56];

	uint8_t oplock_level;
	uint32_t create_action;
	struct timespec creation_time;
	struct timespec last_access_time;
	struct timespec last_write_time;
	struct timespec change_time;
	uint64_t allocation_size;
	uint64_t end_of_file;
	uint32_t file_attributes;
	uint64_t fid_persistent;
	uint64_t fid_volatile;
	struct smb2_create_blobs blobs;
};

static void smb2cli_create_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_create_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
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

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_create_state);
	if (req == NULL) {
		return NULL;
	}

	if (!convert_string_talloc(state, CH_UNIX, CH_UTF16,
				   filename, strlen(filename)+1,
				   &name_utf16, &name_utf16_len)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
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
		status = smb2_create_blob_push(talloc_tos(), &blob, *blobs);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	blobs_offset = name_utf16_len;
	blobs_offset = ((blobs_offset + 3) & ~3);

	SIVAL(fixed, 48, blobs_offset + SMB2_HDR_BODY + 56);
	SIVAL(fixed, 52, blob.length);

	dyn_len = blobs_offset + blob.length;
	dyn = talloc_zero_array(state, uint8_t, dyn_len);
	if (tevent_req_nomem(dyn, req)) {
		return tevent_req_post(req, ev);
	}

	memcpy(dyn, name_utf16, name_utf16_len);
	TALLOC_FREE(name_utf16);

	if (blob.data != NULL) {
		memcpy(dyn + blobs_offset - (SMB2_HDR_BODY + 56),
		       blob.data, blob.length);
		data_blob_free(&blob);
	}

	subreq = smb2cli_req_send(state, ev, cli, SMB2_OP_CREATE, 0,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_create_done, req);
	return req;
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

	status = smb2cli_req_recv(subreq, talloc_tos(), &iov, 89);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	body = (uint8_t *)iov[1].iov_base;

	state->oplock_level	= CVAL(body, 2);
	state->create_action	= IVAL(body, 4);
	state->creation_time	= interpret_long_date((char *)body + 8);
	state->last_access_time	= interpret_long_date((char *)body + 16);
	state->last_write_time	= interpret_long_date((char *)body + 24);
	state->change_time	= interpret_long_date((char *)body + 32);
	state->allocation_size	= BVAL(body, 40);
	state->end_of_file	= BVAL(body, 48);
	state->file_attributes	= IVAL(body, 56);
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
			     uint64_t *fid_volatile)
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
	return NT_STATUS_OK;
}

NTSTATUS smb2cli_create(struct cli_state *cli,
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
			uint64_t *fid_volatile)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = event_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_create_send(frame, ev, cli, filename, oplock_level,
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
	status = smb2cli_create_recv(req, fid_persistent, fid_volatile);
 fail:
	TALLOC_FREE(frame);
	return status;
}
