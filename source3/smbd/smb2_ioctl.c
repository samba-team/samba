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
#include "../lib/util/tevent_ntstatus.h"
#include "include/ntioctl.h"
#include "smb2_ioctl_private.h"
#include "librpc/gen_ndr/ioctl.h"

static struct tevent_req *smbd_smb2_ioctl_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbd_smb2_request *smb2req,
					       struct files_struct *in_fsp,
					       uint32_t in_ctl_code,
					       DATA_BLOB in_input,
					       uint32_t in_max_output,
					       uint32_t in_flags);
static NTSTATUS smbd_smb2_ioctl_recv(struct tevent_req *req,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *out_output,
				     bool *disconnect);

static void smbd_smb2_request_ioctl_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_ioctl(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	const uint8_t *inbody;
	uint32_t min_buffer_offset;
	uint32_t max_buffer_offset;
	uint32_t min_output_offset;
	uint32_t allowed_length_in;
	uint32_t allowed_length_out;
	uint32_t in_ctl_code;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp = NULL;
	uint32_t in_input_offset;
	uint32_t in_input_length;
	DATA_BLOB in_input_buffer = data_blob_null;
	uint32_t in_max_input_length;
	uint32_t in_output_offset;
	uint32_t in_output_length;
	DATA_BLOB in_output_buffer = data_blob_null;
	uint32_t in_max_output_length;
	uint32_t in_flags;
	uint32_t data_length_in;
	uint32_t data_length_out;
	uint32_t data_length_tmp;
	uint32_t data_length_max;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x39);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_ctl_code		= IVAL(inbody, 0x04);
	in_file_id_persistent	= BVAL(inbody, 0x08);
	in_file_id_volatile	= BVAL(inbody, 0x10);
	in_input_offset		= IVAL(inbody, 0x18);
	in_input_length		= IVAL(inbody, 0x1C);
	in_max_input_length	= IVAL(inbody, 0x20);
	in_output_offset	= IVAL(inbody, 0x24);
	in_output_length	= IVAL(inbody, 0x28);
	in_max_output_length	= IVAL(inbody, 0x2C);
	in_flags		= IVAL(inbody, 0x30);

	min_buffer_offset = SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(req);
	max_buffer_offset = min_buffer_offset + SMBD_SMB2_IN_DYN_LEN(req);
	min_output_offset = min_buffer_offset;

	/*
	 * InputOffset (4 bytes): The offset, in bytes, from the beginning of
	 * the SMB2 header to the input data buffer. If no input data is
	 * required for the FSCTL/IOCTL command being issued, the client SHOULD
	 * set this value to 0.<49>
	 * <49> If no input data is required for the FSCTL/IOCTL command being
	 * issued, Windows-based clients set this field to any value.
	 */
	allowed_length_in = 0;
	if ((in_input_offset > 0) && (in_input_length > 0)) {
		uint32_t tmp_ofs;

		if (in_input_offset < min_buffer_offset) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}
		if (in_input_offset > max_buffer_offset) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}
		allowed_length_in = max_buffer_offset - in_input_offset;

		tmp_ofs = in_input_offset - min_buffer_offset;
		in_input_buffer.data = SMBD_SMB2_IN_DYN_PTR(req);
		in_input_buffer.data += tmp_ofs;
		in_input_buffer.length = in_input_length;
		min_output_offset += tmp_ofs;
		min_output_offset += in_input_length;
	}

	if (in_input_length > allowed_length_in) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	allowed_length_out = 0;
	if (in_output_offset > 0) {
		if (in_output_offset < min_buffer_offset) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}
		if (in_output_offset > max_buffer_offset) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}
		allowed_length_out = max_buffer_offset - in_output_offset;
	}

	if (in_output_length > allowed_length_out) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_output_length > 0) {
		uint32_t tmp_ofs;

		if (in_output_offset < min_output_offset) {
			return smbd_smb2_request_error(req,
					NT_STATUS_INVALID_PARAMETER);
		}

		tmp_ofs = in_output_offset - min_buffer_offset;
		in_output_buffer.data = SMBD_SMB2_IN_DYN_PTR(req);
		in_output_buffer.data += tmp_ofs;
		in_output_buffer.length = in_output_length;
	}

	/*
	 * verify the credits and avoid overflows
	 * in_input_buffer.length and in_output_buffer.length
	 * are already verified.
	 */
	data_length_in = in_input_buffer.length + in_output_buffer.length;

	data_length_out = in_max_input_length;
	data_length_tmp = UINT32_MAX - data_length_out;
	if (data_length_tmp < in_max_output_length) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}
	data_length_out += in_max_output_length;

	data_length_max = MAX(data_length_in, data_length_out);

	status = smbd_smb2_request_verify_creditcharge(req, data_length_max);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	/*
	 * If the Flags field of the request is not SMB2_0_IOCTL_IS_FSCTL the
	 * server MUST fail the request with STATUS_NOT_SUPPORTED.
	 */
	if (in_flags != SMB2_IOCTL_FLAG_IS_FSCTL) {
		return smbd_smb2_request_error(req, NT_STATUS_NOT_SUPPORTED);
	}

	switch (in_ctl_code) {
	case FSCTL_DFS_GET_REFERRALS:
	case FSCTL_DFS_GET_REFERRALS_EX:
	case FSCTL_PIPE_WAIT:
	case FSCTL_VALIDATE_NEGOTIATE_INFO_224:
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
		/*
		 * Some SMB2 specific CtlCodes like FSCTL_DFS_GET_REFERRALS or
		 * FSCTL_PIPE_WAIT does not take a file handle.
		 *
		 * If FileId in the SMB2 Header of the request is not
		 * 0xFFFFFFFFFFFFFFFF, then the server MUST fail the request
		 * with STATUS_INVALID_PARAMETER.
		 */
		if (in_file_id_persistent != UINT64_MAX ||
		    in_file_id_volatile != UINT64_MAX) {
			return smbd_smb2_request_error(req,
				NT_STATUS_INVALID_PARAMETER);
		}
		break;
	default:
		in_fsp = file_fsp_smb2(req, in_file_id_persistent,
				       in_file_id_volatile);
		if (in_fsp == NULL) {
			return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
		}
		break;
	}

	subreq = smbd_smb2_ioctl_send(req, req->sconn->ev_ctx,
				      req, in_fsp,
				      in_ctl_code,
				      in_input_buffer,
				      in_max_output_length,
				      in_flags);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_ioctl_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 1000);
}

/*
 * 3.3.4.4 Sending an Error Response
 * An error code other than one of the following indicates a failure:
 */
static bool smbd_smb2_ioctl_is_failure(uint32_t ctl_code, NTSTATUS status,
				       size_t data_size)
{
	if (NT_STATUS_IS_OK(status)) {
		return false;
	}

	/*
	 * STATUS_BUFFER_OVERFLOW in a FSCTL_PIPE_TRANSCEIVE, FSCTL_PIPE_PEEK or
	 * FSCTL_DFS_GET_REFERRALS Response specified in section 2.2.32.<153>
	 */
	if (NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)
	 && ((ctl_code == FSCTL_PIPE_TRANSCEIVE)
	  || (ctl_code == FSCTL_PIPE_PEEK)
	  || (ctl_code == FSCTL_DFS_GET_REFERRALS))) {
		return false;
	}

	/*
	 * Any status other than STATUS_SUCCESS in a FSCTL_SRV_COPYCHUNK or
	 * FSCTL_SRV_COPYCHUNK_WRITE Response, when returning an
	 * SRV_COPYCHUNK_RESPONSE as described in section 2.2.32.1.
	 */
	if (((ctl_code == FSCTL_SRV_COPYCHUNK)
				|| (ctl_code == FSCTL_SRV_COPYCHUNK_WRITE))
	 && (data_size == sizeof(struct srv_copychunk_rsp))) {
		return false;
	}

	return true;
}

static void smbd_smb2_request_ioctl_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	const uint8_t *inbody;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint32_t in_ctl_code;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t out_input_offset;
	uint32_t out_output_offset;
	DATA_BLOB out_output_buffer = data_blob_null;
	NTSTATUS status;
	NTSTATUS error; /* transport error */
	bool disconnect = false;

	status = smbd_smb2_ioctl_recv(subreq, req,
				      &out_output_buffer,
				      &disconnect);

	DEBUG(10,("smbd_smb2_request_ioctl_done: smbd_smb2_ioctl_recv returned "
		"%u status %s\n",
		(unsigned int)out_output_buffer.length,
		nt_errstr(status) ));

	TALLOC_FREE(subreq);
	if (disconnect) {
		error = status;
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}

	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_ctl_code		= IVAL(inbody, 0x04);
	in_file_id_persistent	= BVAL(inbody, 0x08);
	in_file_id_volatile	= BVAL(inbody, 0x10);

	if (smbd_smb2_ioctl_is_failure(in_ctl_code, status,
				       out_output_buffer.length)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	out_input_offset = SMB2_HDR_BODY + 0x30;
	out_output_offset = SMB2_HDR_BODY + 0x30;

	outbody = smbd_smb2_generate_outbody(req, 0x30);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x30 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */
	SIVAL(outbody.data, 0x04,
	      in_ctl_code);			/* ctl code */
	SBVAL(outbody.data, 0x08,
	      in_file_id_persistent);		/* file id (persistent) */
	SBVAL(outbody.data, 0x10,
	      in_file_id_volatile);		/* file id (volatile) */
	SIVAL(outbody.data, 0x18,
	      out_input_offset);		/* input offset */
	SIVAL(outbody.data, 0x1C, 0);		/* input count */
	SIVAL(outbody.data, 0x20,
	      out_output_offset);		/* output offset */
	SIVAL(outbody.data, 0x24,
	      out_output_buffer.length);	/* output count */
	SIVAL(outbody.data, 0x28, 0);		/* flags */
	SIVAL(outbody.data, 0x2C, 0);		/* reserved */

	/*
	 * Note: Windows Vista and 2008 send back also the
	 *       input from the request. But it was fixed in
	 *       Windows 7.
	 */
	outdyn = out_output_buffer;

	error = smbd_smb2_request_done_ex(req, status, outbody, &outdyn,
					  __location__);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

static struct tevent_req *smbd_smb2_ioctl_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbd_smb2_request *smb2req,
					       struct files_struct *fsp,
					       uint32_t in_ctl_code,
					       DATA_BLOB in_input,
					       uint32_t in_max_output,
					       uint32_t in_flags)
{
	struct tevent_req *req;
	struct smbd_smb2_ioctl_state *state;
	struct smb_request *smbreq;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_ioctl_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;
	state->smbreq = NULL;
	state->fsp = fsp;
	state->in_input = in_input;
	state->in_max_output = in_max_output;
	state->out_output = data_blob_null;

	DEBUG(10, ("smbd_smb2_ioctl: ctl_code[0x%08x] %s, %s\n",
		   (unsigned)in_ctl_code,
		   fsp ? fsp_str_dbg(fsp) : "<no handle>",
		   fsp_fnum_dbg(fsp)));

	smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}
	state->smbreq = smbreq;

	switch (in_ctl_code & IOCTL_DEV_TYPE_MASK) {
	case FSCTL_DFS:
		return smb2_ioctl_dfs(in_ctl_code, ev, req, state);
		break;
	case FSCTL_FILESYSTEM:
		return smb2_ioctl_filesys(in_ctl_code, ev, req, state);
		break;
	case FSCTL_NAMED_PIPE:
		return smb2_ioctl_named_pipe(in_ctl_code, ev, req, state);
		break;
	case FSCTL_NETWORK_FILESYSTEM:
		return smb2_ioctl_network_fs(in_ctl_code, ev, req, state);
		break;
	default:
		if (IS_IPC(smbreq->conn)) {
			tevent_req_nterror(req, NT_STATUS_FS_DRIVER_REQUIRED);
		} else {
			tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		}

		return tevent_req_post(req, ev);
		break;
	}

	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
	return tevent_req_post(req, ev);
}

static NTSTATUS smbd_smb2_ioctl_recv(struct tevent_req *req,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *out_output,
				     bool *disconnect)
{
	NTSTATUS status = NT_STATUS_OK;
	struct smbd_smb2_ioctl_state *state = tevent_req_data(req,
					      struct smbd_smb2_ioctl_state);
	enum tevent_req_state req_state;
	uint64_t err;

	*disconnect = state->disconnect;

	if ((tevent_req_is_error(req, &req_state, &err) == false)
	 || (req_state == TEVENT_REQ_USER_ERROR)) {
		/*
		 * Return output buffer to caller if the ioctl was successfully
		 * processed, even if a user error occurred. Some ioctls return
		 * data on failure.
		 */
		*out_output = state->out_output;
		talloc_steal(mem_ctx, out_output->data);
	}

	tevent_req_is_nterror(req, &status);
	tevent_req_received(req);
	return status;
}
