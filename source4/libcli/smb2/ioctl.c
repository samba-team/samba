/* 
   Unix SMB/CIFS implementation.

   SMB2 client ioctl call

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "librpc/gen_ndr/ioctl.h"

/*
  send a ioctl request
*/
struct smb2_request *smb2_ioctl_send(struct smb2_tree *tree, struct smb2_ioctl *io)
{
	NTSTATUS status;
	struct smb2_request *req;
	uint64_t max_payload_in;
	uint64_t max_payload_out;
	size_t max_payload;

	req = smb2_request_init_tree(tree, SMB2_OP_IOCTL, 0x38, true,
				     io->in.in.length+io->in.out.length);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x02, 0); /* pad */
	SIVAL(req->out.body, 0x04, io->in.function);
	smb2_push_handle(req->out.body+0x08, &io->in.file.handle);

	status = smb2_push_o32s32_blob(&req->out, 0x18, io->in.out);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	SIVAL(req->out.body, 0x20, io->in.max_input_response);

	status = smb2_push_o32s32_blob(&req->out, 0x24, io->in.in);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	SIVAL(req->out.body, 0x2C, io->in.max_output_response);
	SBVAL(req->out.body, 0x30, io->in.flags);

	max_payload_in = io->in.out.length + io->in.in.length;
	max_payload_in = MIN(max_payload_in, UINT32_MAX);
	max_payload_out = io->in.max_input_response + io->in.max_output_response;
	max_payload_out = MIN(max_payload_out, UINT32_MAX);

	max_payload = MAX(max_payload_in, max_payload_out);
	req->credit_charge = (MAX(max_payload, 1) - 1)/ 65536 + 1;

	smb2_transport_send(req);

	return req;
}

/*
 * 3.3.4.4 Sending an Error Response
 */
static bool smb2_ioctl_is_failure(uint32_t ctl_code, NTSTATUS status,
				  size_t data_size)
{
	if (NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)
	 && ((ctl_code == FSCTL_PIPE_TRANSCEIVE)
	  || (ctl_code == FSCTL_PIPE_PEEK)
	  || (ctl_code == FSCTL_DFS_GET_REFERRALS))) {
		return false;
	}

	if (((ctl_code == FSCTL_SRV_COPYCHUNK)
				|| (ctl_code == FSCTL_SRV_COPYCHUNK_WRITE))
	 && (data_size == sizeof(struct srv_copychunk_rsp))) {
		/*
		 * copychunk responses may come with copychunk data or error
		 * response data, independent of status.
		 */
		return false;
	}

	return true;
}

/*
  recv a ioctl reply
*/
NTSTATUS smb2_ioctl_recv(struct smb2_request *req,
			 TALLOC_CTX *mem_ctx, struct smb2_ioctl *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) ||
	    smb2_ioctl_is_failure(io->in.function, req->status,
				  req->in.bufinfo.data_size)) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x30, true);

	io->out.reserved   = SVAL(req->in.body, 0x02);
	io->out.function   = IVAL(req->in.body, 0x04);
	smb2_pull_handle(req->in.body+0x08, &io->out.file.handle);

	status = smb2_pull_o32s32_blob(&req->in, mem_ctx, req->in.body+0x18, &io->out.in);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}

	status = smb2_pull_o32s32_blob(&req->in, mem_ctx, req->in.body+0x20, &io->out.out);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}

	io->out.flags     = IVAL(req->in.body, 0x28);
	io->out.reserved2 = IVAL(req->in.body, 0x2C);

	return smb2_request_destroy(req);
}

/*
  sync ioctl request
*/
NTSTATUS smb2_ioctl(struct smb2_tree *tree, TALLOC_CTX *mem_ctx, struct smb2_ioctl *io)
{
	struct smb2_request *req = smb2_ioctl_send(tree, io);
	return smb2_ioctl_recv(req, mem_ctx, io);
}
