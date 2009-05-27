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

static NTSTATUS smbd_smb2_write(struct smbd_smb2_request *req,
				uint32_t in_smbpid,
				uint64_t in_file_id_volatile,
				DATA_BLOB in_data,
				uint64_t in_offset,
				uint32_t in_flags,
				uint32_t *out_count);

NTSTATUS smbd_smb2_request_process_write(struct smbd_smb2_request *req)
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
	uint16_t in_data_offset;
	uint32_t in_data_length;
	DATA_BLOB in_data_buffer;
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_flags;
	uint32_t out_count;
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

	in_data_offset		= SVAL(inbody, 0x02);
	in_data_length		= IVAL(inbody, 0x04);
	in_offset		= BVAL(inbody, 0x08);
	in_file_id_persistent	= BVAL(inbody, 0x10);
	in_file_id_volatile	= BVAL(inbody, 0x18);
	in_flags		= IVAL(inbody, 0x2C);

	if (in_data_offset != (SMB2_HDR_BODY + (body_size & 0xFFFFFFFE))) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_data_length > req->in.vector[i+2].iov_len) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	/* check the max write size */
	if (in_data_length > 0x00010000) {
		DEBUG(0,("here:%s: 0x%08X: 0x%08X\n",
			__location__, in_data_length, 0x00010000));
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_data_buffer.data = (uint8_t *)req->in.vector[i+2].iov_base;
	in_data_buffer.length = in_data_length;

	if (in_file_id_persistent != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	status = smbd_smb2_write(req,
				 in_smbpid,
				 in_file_id_volatile,
				 in_data_buffer,
				 in_offset,
				 in_flags,
				 &out_count);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	outhdr = (uint8_t *)req->out.vector[i].iov_base;

	outbody = data_blob_talloc(req->out.vector, NULL, 0x10);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x10 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */
	SIVAL(outbody.data, 0x04, out_count);	/* count */
	SIVAL(outbody.data, 0x08, 0);		/* remaining */
	SSVAL(outbody.data, 0x0C, 0);		/* write channel info offset */
	SSVAL(outbody.data, 0x0E, 0);		/* write channel info length */

	outdyn = data_blob_const(NULL, 0);

	return smbd_smb2_request_done(req, outbody, &outdyn);
}

static NTSTATUS smbd_smb2_write(struct smbd_smb2_request *req,
				uint32_t in_smbpid,
				uint64_t in_file_id_volatile,
				DATA_BLOB in_data,
				uint64_t in_offset,
				uint32_t in_flags,
				uint32_t *out_count)
{
	NTSTATUS status;
	struct smb_request *smbreq;
	connection_struct *conn = req->tcon->compat_conn;
	files_struct *fsp;
	ssize_t nwritten;
	bool write_through = false;
	struct lock_struct lock;

	DEBUG(10,("smbd_smb2_write: file_id[0x%016llX]\n",
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

	if (!CHECK_WRITE(fsp)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	init_strict_lock_struct(fsp,
				in_smbpid,
				in_offset,
				in_data.length,
				WRITE_LOCK,
				&lock);

	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	nwritten = write_file(smbreq, fsp,
			      (const char *)in_data.data,
			      in_offset,
			      in_data.length);

	if (((nwritten == 0) && (in_data.length != 0)) || (nwritten < 0)) {
		DEBUG(5,("smbd_smb2_write: write_file[%s] disk full\n",
			fsp->fsp_name));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
		return NT_STATUS_DISK_FULL;
	}

	DEBUG(3,("smbd_smb2_write: fnum=[%d/%s] length=%d offset=%d wrote=%d\n",
		fsp->fnum, fsp->fsp_name, (int)in_data.length,
		(int)in_offset, (int)nwritten));

	if (in_flags & 0x00000001) {
		write_through = true;
	}

	status = sync_file(conn, fsp, write_through);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("smbd_smb2_write: sync_file for %s returned %s\n",
			fsp->fsp_name, nt_errstr(status)));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);
		return status;
	}

	SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);

	return NT_STATUS_OK;
}
