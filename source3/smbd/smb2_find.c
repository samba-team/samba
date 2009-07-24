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
#include "smbd/globals.h"
#include "../source4/libcli/smb2/smb2_constants.h"

static struct tevent_req *smbd_smb2_find_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      uint8_t in_file_info_class,
					      uint8_t in_flags,
					      uint32_t in_file_index,
					      uint64_t in_file_id_volatile,
					      uint32_t in_output_buffer_length,
					      const char *in_file_name);
static NTSTATUS smbd_smb2_find_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_output_buffer);

static void smbd_smb2_request_find_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_find(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	int i = req->current_idx;
	size_t expected_body_size = 0x21;
	size_t body_size;
	uint8_t in_file_info_class;
	uint8_t in_flags;
	uint32_t in_file_index;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint16_t in_file_name_offset;
	uint16_t in_file_name_length;
	DATA_BLOB in_file_name_buffer;
	char *in_file_name_string;
	size_t in_file_name_string_size;
	uint32_t in_output_buffer_length;
	struct tevent_req *subreq;
	bool ok;

	inhdr = (const uint8_t *)req->in.vector[i+0].iov_base;
	if (req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_file_info_class		= CVAL(inbody, 0x02);
	in_flags			= CVAL(inbody, 0x03);
	in_file_index			= IVAL(inbody, 0x04);
	in_file_id_persistent		= BVAL(inbody, 0x08);
	in_file_id_volatile		= BVAL(inbody, 0x10);
	in_file_name_offset		= SVAL(inbody, 0x18);
	in_file_name_length		= SVAL(inbody, 0x1A);
	in_output_buffer_length		= IVAL(inbody, 0x1C);

	if (in_file_name_offset == 0 && in_file_name_length == 0) {
		/* This is ok */
	} else if (in_file_name_offset !=
		   (SMB2_HDR_BODY + (body_size & 0xFFFFFFFE))) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_file_name_length > req->in.vector[i+2].iov_len) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_file_name_buffer.data = (uint8_t *)req->in.vector[i+2].iov_base;
	in_file_name_buffer.length = in_file_name_length;

	ok = convert_string_talloc(req, CH_UTF16, CH_UNIX,
				   in_file_name_buffer.data,
				   in_file_name_buffer.length,
				   &in_file_name_string,
				   &in_file_name_string_size, false);
	if (!ok) {
		return smbd_smb2_request_error(req, NT_STATUS_ILLEGAL_CHARACTER);
	}

	if (req->compat_chain_fsp) {
		/* skip check */
	} else if (in_file_id_persistent != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_find_send(req,
				     req->conn->smb2.event_ctx,
				     req,
				     in_file_info_class,
				     in_flags,
				     in_file_index,
				     in_file_id_volatile,
				     in_output_buffer_length,
				     in_file_name_string);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_find_done, req);

	if (tevent_req_is_in_progress(subreq)) {
		return smbd_smb2_request_pending_queue(req);
	}

	return NT_STATUS_OK;
}

static void smbd_smb2_request_find_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	int i = req->current_idx;
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint16_t out_output_buffer_offset;
	DATA_BLOB out_output_buffer = data_blob_null;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_find_recv(subreq,
				     req,
				     &out_output_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->conn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	out_output_buffer_offset = SMB2_HDR_BODY + 0x08;

	outhdr = (uint8_t *)req->out.vector[i].iov_base;

	outbody = data_blob_talloc(req->out.vector, NULL, 0x08);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->conn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x08 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02,
	      out_output_buffer_offset);	/* output buffer offset */
	SIVAL(outbody.data, 0x04,
	      out_output_buffer.length);	/* output buffer length */

	outdyn = out_output_buffer;

	error = smbd_smb2_request_done(req, outbody, &outdyn);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->conn,
						 nt_errstr(error));
		return;
	}
}

struct smbd_smb2_find_state {
	struct smbd_smb2_request *smb2req;
	DATA_BLOB out_output_buffer;
};

static struct tevent_req *smbd_smb2_find_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      uint8_t in_file_info_class,
					      uint8_t in_flags,
					      uint32_t in_file_index,
					      uint64_t in_file_id_volatile,
					      uint32_t in_output_buffer_length,
					      const char *in_file_name)
{
	struct tevent_req *req;
	struct smbd_smb2_find_state *state;
	struct smb_request *smbreq;
	connection_struct *conn = smb2req->tcon->compat_conn;
	files_struct *fsp;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_find_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;
	state->out_output_buffer = data_blob_null;

	DEBUG(10,("smbd_smb2_find_send: file_id[0x%016llX]\n",
		  (unsigned long long)in_file_id_volatile));

	smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}

	fsp = file_fsp(smbreq, (uint16_t)in_file_id_volatile);
	if (fsp == NULL) {
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return tevent_req_post(req, ev);
	}
	if (conn != fsp->conn) {
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return tevent_req_post(req, ev);
	}
	if (smb2req->session->vuid != fsp->vuid) {
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return tevent_req_post(req, ev);
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS smbd_smb2_find_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_output_buffer)
{
	NTSTATUS status;
	struct smbd_smb2_find_state *state = tevent_req_data(req,
					     struct smbd_smb2_find_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_output_buffer = state->out_output_buffer;
	talloc_steal(mem_ctx, out_output_buffer->data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}
