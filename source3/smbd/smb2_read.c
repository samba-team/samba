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

static NTSTATUS smbd_smb2_read(struct smbd_smb2_request *req,
			       uint32_t in_smbpid,
			       uint64_t in_file_id_volatile,
			       uint32_t in_length,
			       uint64_t in_offset,
			       uint32_t in_minimum,
			       uint32_t in_remaining,
			       DATA_BLOB *out_data_buffer,
			       uint32_t *out_remaining);

NTSTATUS smbd_smb2_request_process_read(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	int i = req->current_idx;
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	size_t expected_body_size = 0x31;
	size_t body_size;
	uint32_t in_smbpid;
	uint32_t in_length;
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_minimum_count;
	uint32_t in_remaining_bytes;
	uint8_t out_data_offset;
	DATA_BLOB out_data_buffer;
	uint32_t out_data_remaining;
	NTSTATUS status;

	inhdr = (const uint8_t *)req->in.vector[i+0].iov_base;
	if (req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_smbpid = IVAL(inhdr, SMB2_HDR_PID);

	in_length		= IVAL(inbody, 0x04);
	in_offset		= BVAL(inbody, 0x08);
	in_file_id_persistent	= BVAL(inbody, 0x10);
	in_file_id_volatile	= BVAL(inbody, 0x18);
	in_minimum_count	= IVAL(inbody, 0x20);
	in_remaining_bytes	= IVAL(inbody, 0x28);

	/* check the max read size */
	if (in_length > 0x00010000) {
		DEBUG(0,("here:%s: 0x%08X: 0x%08X\n",
			__location__, in_length, 0x00010000));
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_file_id_persistent != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	status = smbd_smb2_read(req,
				in_smbpid,
				in_file_id_volatile,
				in_length,
				in_offset,
				in_minimum_count,
				in_remaining_bytes,
				&out_data_buffer,
				&out_data_remaining);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	out_data_offset = SMB2_HDR_BODY + 0x10;

	outhdr = (uint8_t *)req->out.vector[i].iov_base;

	outbody = data_blob_talloc(req->out.vector, NULL, 0x10);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x10 + 1);	/* struct size */
	SCVAL(outbody.data, 0x02,
	      out_data_offset);			/* data offset */
	SCVAL(outbody.data, 0x03, 0);		/* reserved */
	SIVAL(outbody.data, 0x04,
	      out_data_buffer.length);		/* data length */
	SIVAL(outbody.data, 0x08,
	      out_data_remaining);		/* data remaining */
	SIVAL(outbody.data, 0x0C, 0);		/* reserved */

	outdyn = out_data_buffer;

	return smbd_smb2_request_done(req, outbody, &outdyn);
}

static NTSTATUS smbd_smb2_read(struct smbd_smb2_request *req,
			       uint32_t in_smbpid,
			       uint64_t in_file_id_volatile,
			       uint32_t in_length,
			       uint64_t in_offset,
			       uint32_t in_minimum,
			       uint32_t in_remaining,
			       DATA_BLOB *out_data_buffer,
			       uint32_t *out_remaining)
{
	struct smb_request *smbreq;
	connection_struct *conn = req->tcon->compat_conn;
	files_struct *fsp;
	ssize_t nread = -1;
	struct lock_struct lock;

	DEBUG(10,("smbd_smb2_read: file_id[0x%016llX]\n",
		  (unsigned long long)in_file_id_volatile));

	smbreq = smbd_smb2_fake_smb_request(req);
	if (smbreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	fsp = file_fsp(smbreq, (uint16_t)in_file_id_volatile);
	if (fsp == NULL) {
		return NT_STATUS_FILE_CLOSED;
	}
	if (conn != fsp->conn) {
		return NT_STATUS_FILE_CLOSED;
	}
	if (req->session->vuid != fsp->vuid) {
		return NT_STATUS_FILE_CLOSED;
	}

	if (!CHECK_READ(fsp, smbreq)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	*out_data_buffer = data_blob_talloc(req, NULL, in_length);
	if (in_length > 0 && out_data_buffer->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	init_strict_lock_struct(fsp,
				in_smbpid,
				in_offset,
				in_length,
				READ_LOCK,
				&lock);

	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	nread = read_file(fsp,
			  (char *)out_data_buffer->data,
			  in_offset,
			  in_length);

	SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);

	if (nread < 0) {
		DEBUG(5,("smbd_smb2_read: read_file[%s] nread[%lld]\n",
			fsp->fsp_name, (long long)nread));
		return NT_STATUS_ACCESS_DENIED;
	}
	if (nread == 0 && in_length != 0) {
		DEBUG(5,("smbd_smb2_read: read_file[%s] end of file\n",
			fsp->fsp_name));
		return NT_STATUS_END_OF_FILE;
	}

	out_data_buffer->length = nread;
	*out_remaining = 0;
	return NT_STATUS_OK;
}
